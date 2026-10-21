"""Semgrep, Trivy and ZAP adapters: argument safety and normalization. No binaries and no network."""
import json
import re
from pathlib import Path

import pytest

from reposhield.adapters import semgrep, trivy, zap
from reposhield.adapters.base import Result, ToolError


def _fake(monkeypatch, module, writer, returncode=0):
    calls = []

    def fake_execute(args, **kwargs):
        calls.append((list(args), kwargs))
        writer(args, kwargs)
        return Result(returncode, '', '')

    monkeypatch.setattr(module, 'execute', fake_execute)
    return calls


def _write_after(flag, payload):
    """Simulate the tool writing its report to the path that follows `flag` (relative to cwd if given)."""
    def writer(args, kwargs):
        base = Path(kwargs.get('cwd') or '.')
        target = base/args[list(args).index(flag) + 1]
        target.write_text(json.dumps(payload), encoding='utf-8')
    return writer


def _semgrep_report(root):
    return {
        'version': '1.100.0',
        'results': [
            {'check_id': 'reposhield.python.subprocess-shell-true', 'path': str(root/'app'/'run.py'),
             'start': {'line': 7}, 'extra': {'message': 'subprocess com shell=True', 'severity': 'ERROR',
                                             'lines': 'subprocess.run(cmd, shell=True)',
                                             'metadata': {'cwe': 'CWE-78: OS Command Injection',
                                                          'category': 'security'}}},
            {'check_id': 'reposhield.js.eval-variavel', 'path': str(root/'web'/'a.js'),
             'start': {'line': 3}, 'extra': {'message': 'eval com variavel', 'severity': 'WARNING',
                                             'lines': 'requires login',
                                             'metadata': {'cwe': ['CWE-95: Eval Injection']}}},
        ],
        'errors': [{'level': 'error', 'type': 'PartialParsing', 'message': 'x'},
                   {'level': 'info', 'type': 'info', 'message': 'y'}],
    }


# ---- Semgrep ----

def test_semgrep_args_seguros(monkeypatch, tmp_path):
    root, workdir = tmp_path/'proj', tmp_path/'wd'
    workdir.mkdir()
    calls = _fake(monkeypatch, semgrep, _write_after('--output', _semgrep_report(root)))
    semgrep.Semgrep().run(root, workdir, dict(path='/bin/semgrep', version='1.100.0'), {})
    args = calls[0][0]
    assert '--metrics=off' in args
    assert '--config' in args
    assert Path(args[args.index('--config') + 1]) == semgrep.RULES_DIR
    assert semgrep.RULES_DIR.is_dir()
    assert not any(a == 'auto' or a.startswith(('p/', 'r/')) or 'registry' in a for a in args)
    assert '--no-git-ignore' not in args


def test_semgrep_returncode_invalido_falha(monkeypatch, tmp_path):
    _fake(monkeypatch, semgrep, lambda a, k: None, returncode=2)
    with pytest.raises(ToolError):
        semgrep.Semgrep().run(tmp_path, tmp_path, dict(path='/bin/semgrep', version='1'), {})


def test_semgrep_normaliza_resultados(tmp_path):
    raw = dict(text=json.dumps(_semgrep_report(tmp_path)))
    out = semgrep.Semgrep().normalize(raw, tmp_path, dict(path='/bin/semgrep', version='1.100.0'))
    first, second = out['findings']
    assert first['rule'] == 'semgrep/reposhield.python.subprocess-shell-true'
    assert first['severity'] == 'high'
    assert first['file'] == 'app/run.py'
    assert first['line'] == 7
    assert first['cwe'] == 'CWE-78'
    assert first['category'] == 'sast'
    assert first['source'] == 'semgrep@1.100.0'
    assert first['evidence'] == 'subprocess.run(cmd, shell=True)'
    assert second['severity'] == 'medium'
    assert second['cwe'] == 'CWE-95'
    assert second['evidence'] == 'eval com variavel'  # 'requires login' cai para a mensagem
    assert '1 erro(s)' in out['detail']
    assert re.search(r'\(\d+ regras\)', out['detail'])


# ---- Trivy ----

def test_trivy_applies_detecta_iac_e_ignora_node_modules(tmp_path):
    adapter = trivy.Trivy()
    assert adapter.applies(tmp_path) is False
    (tmp_path/'node_modules'/'pkg').mkdir(parents=True)
    (tmp_path/'node_modules'/'pkg'/'Dockerfile').write_text('FROM x\n', encoding='utf-8')
    assert adapter.applies(tmp_path) is False
    (tmp_path/'deploy').mkdir()
    (tmp_path/'deploy'/'k8s.yaml').write_text('apiVersion: v1\nkind: Pod\n', encoding='utf-8')
    assert adapter.applies(tmp_path) is True


def test_trivy_yaml_comum_nao_aplica(tmp_path):
    (tmp_path/'config.yml').write_text('name: app\nversion: 1\n', encoding='utf-8')
    assert trivy.Trivy().applies(tmp_path) is False


def test_trivy_args_seguros(monkeypatch, tmp_path):
    root, workdir = tmp_path/'proj', tmp_path/'wd'
    workdir.mkdir()
    payload = {'Results': []}
    calls = _fake(monkeypatch, trivy, _write_after('--output', payload))
    trivy.Trivy().run(root, workdir, dict(path='/bin/trivy', version='0.50.0'), {})
    args = calls[0][0]
    assert args[1] == 'config'
    assert '--exit-code' in args and args[args.index('--exit-code') + 1] == '0'
    assert not any('offline' in a for a in args)


def test_trivy_normaliza_somente_falhas(tmp_path):
    payload = {'Results': [{
        'Target': 'Dockerfile', 'Class': 'config', 'Type': 'dockerfile',
        'Misconfigurations': [
            {'ID': 'DS002', 'AVDID': 'AVD-DS-0002', 'Title': "Image user should not be 'root'",
             'Message': 'Specify at least 1 USER command in Dockerfile',
             'Resolution': "Add 'USER <non root user name>' line to the Dockerfile",
             'Severity': 'HIGH', 'Status': 'FAIL', 'CauseMetadata': {'StartLine': 1}},
            {'ID': 'DS026', 'Title': 'ok', 'Severity': 'LOW', 'Status': 'PASS'},
            {'ID': 'DS099', 'Title': 'desconhecida', 'Message': 'm', 'Severity': 'UNKNOWN', 'Status': 'FAIL'},
        ]}]}
    raw = dict(text=json.dumps(payload))
    out = trivy.Trivy().normalize(raw, tmp_path, dict(path='/bin/trivy', version='0.50.0'))
    assert len(out['findings']) == 2
    high, unknown = out['findings']
    assert high['rule'] == 'trivy/DS002'
    assert high['severity'] == 'high'
    assert high['file'] == 'Dockerfile'
    assert high['line'] == 1
    assert high['category'] == 'iac'
    assert high['recommendation'].startswith('Add')
    assert unknown['severity'] == 'medium'
    assert unknown['line'] == 1


# ---- ZAP ----

@pytest.mark.parametrize('url', ['http://127.0.0.1:8080', 'https://[::1]:8443', 'http://127.0.0.1/'])
def test_zap_loopback_aceito(url):
    assert zap._loopback(url)


@pytest.mark.parametrize('url', [
    'http://example.com', 'http://10.0.0.5:8080', 'http://localhost:8080', 'ftp://127.0.0.1',
    'http://127.0.0.1:8080/path', 'http://user:pw@127.0.0.1', 'http://127.0.0.1/?q=1',
    'http://127.0.0.1/#x', '', None,
])
def test_zap_loopback_recusado(url):
    assert not zap._loopback(url)


def test_zap_run_rejeita_origem_nao_loopback(monkeypatch, tmp_path):
    calls = _fake(monkeypatch, zap, lambda a, k: None)
    with pytest.raises(ToolError, match='loopback'):
        zap.ZapBaseline().run(tmp_path, tmp_path, dict(path='/bin/zap', version='unknown'),
                              dict(base_url='http://example.com'))
    assert calls == []


def test_zap_run_args_seguros(monkeypatch, tmp_path):
    workdir = tmp_path/'wd'
    workdir.mkdir()
    payload = {'site': []}
    calls = _fake(monkeypatch, zap, _write_after('-J', payload))
    raw = zap.ZapBaseline().run(tmp_path, workdir, dict(path='/bin/zap', version='unknown'),
                                dict(base_url='http://127.0.0.1:8080'))
    args, kwargs = calls[0]
    assert args[args.index('-t') + 1] == 'http://127.0.0.1:8080'
    assert '-a' not in args
    assert kwargs['cwd'] == workdir
    assert raw['base_url'] == 'http://127.0.0.1:8080'


def test_zap_normaliza_alertas(tmp_path):
    payload = {'site': [{'@name': 'http://127.0.0.1:8080', 'alerts': [
        {'pluginid': '10038', 'alert': 'Content Security Policy (CSP) Header Not Set', 'riskcode': '2',
         'cweid': '693', 'solution': '<p>Ensure that your web server sets CSP.</p>',
         'instances': [{'uri': 'http://127.0.0.1:8080/', 'method': 'GET'}]},
        {'pluginid': '10021', 'alert': 'X-Content-Type-Options Header Missing', 'riskcode': '1',
         'cweid': '-1', 'solution': '', 'instances': []},
    ]}]}
    raw = dict(text=json.dumps(payload), base_url='http://127.0.0.1:8080')
    out = zap.ZapBaseline().normalize(raw, tmp_path, dict(path='/bin/zap', version='unknown'))
    first, second = out['findings']
    assert first['rule'] == 'zap/10038'
    assert first['severity'] == 'medium'
    assert first['cwe'] == 'CWE-693'
    assert first['file'] == 'runtime:http://127.0.0.1:8080'
    assert first['category'] == 'runtime'
    assert first['evidence'] == 'http://127.0.0.1:8080/ GET'
    assert first['recommendation'] == 'Ensure that your web server sets CSP.'
    assert second['severity'] == 'low'
    assert second['cwe'] is None
    assert second['evidence'] == ''


def _fake_docker(monkeypatch, docker_present=True):
    """Só o docker aparece no PATH seguro; zap-baseline.py não existe."""
    def fake_resolve(name, root=None):
        return '/usr/bin/docker' if docker_present and name == 'docker' else None
    monkeypatch.setattr('reposhield.adapters.base.resolve_binary', fake_resolve)
    monkeypatch.setattr(zap, 'resolve_binary', fake_resolve)


def test_zap_available_docker_sem_binario_local(monkeypatch, tmp_path):
    _fake_docker(monkeypatch)
    calls = []

    def fake_execute(args, **kwargs):
        calls.append(list(args))
        if 'inspect' in args:
            return Result(0, 'sha256:abc\n', '')
        return Result(0, 'zap-2.17.0.jar\nzap-2.17.0.jar.sha256\n', '')

    monkeypatch.setattr(zap, 'execute', fake_execute)
    tool = zap.ZapBaseline().available(tmp_path)
    assert tool == dict(path='/usr/bin/docker', version='2.17.0', mode='docker')
    assert calls[0][:3] == ['/usr/bin/docker', 'image', 'inspect']
    assert '--pull' in calls[1] and calls[1][calls[1].index('--pull') + 1] == 'never'


def test_zap_available_docker_imagem_ausente(monkeypatch, tmp_path):
    _fake_docker(monkeypatch)
    calls = []

    def fake_execute(args, **kwargs):
        calls.append(list(args))
        return Result(1, '', 'No such image')

    monkeypatch.setattr(zap, 'execute', fake_execute)
    assert zap.ZapBaseline().available(tmp_path) is None
    assert len(calls) == 1  # não tenta rodar nem baixar


def test_zap_run_docker_windows_usa_host_docker_internal(monkeypatch, tmp_path):
    monkeypatch.setattr(zap.sys, 'platform', 'win32')
    workdir = tmp_path/'wd'
    workdir.mkdir()
    calls = _fake(monkeypatch, zap, _write_after('-J', {'site': []}))
    raw = zap.ZapBaseline().run(tmp_path, workdir, dict(path='/usr/bin/docker', version='2.17.0', mode='docker'),
                                dict(base_url='http://127.0.0.1:8767'))
    args, kwargs = calls[0]
    assert args[:4] == ['/usr/bin/docker', 'run', '--rm', '--pull']
    assert args[args.index('--pull') + 1] == 'never'
    assert '--network' not in args
    assert args[args.index('-t') + 1] == 'http://host.docker.internal:8767'
    assert args[args.index('-v') + 1] == f'{workdir}:/zap/wrk:rw'
    assert args[args.index(zap.IMAGE) + 1] == 'zap-baseline.py'
    assert kwargs['cwd'] == workdir
    assert raw['base_url'] == 'http://127.0.0.1:8767'
    assert raw['target_url'] == 'http://host.docker.internal:8767'


def test_zap_run_docker_linux_usa_network_host(monkeypatch, tmp_path):
    monkeypatch.setattr(zap.sys, 'platform', 'linux')
    workdir = tmp_path/'wd'
    workdir.mkdir()
    calls = _fake(monkeypatch, zap, _write_after('-J', {'site': []}))
    raw = zap.ZapBaseline().run(tmp_path, workdir, dict(path='/usr/bin/docker', version='2.17.0', mode='docker'),
                                dict(base_url='http://127.0.0.1:8767'))
    args = calls[0][0]
    assert args[args.index('--network') + 1] == 'host'
    assert args[args.index('-t') + 1] == 'http://127.0.0.1:8767'
    assert raw['target_url'] == 'http://127.0.0.1:8767'


def test_zap_normaliza_troca_host_docker_pela_base_url(tmp_path):
    payload = {'site': [{'alerts': [
        {'pluginid': '10038', 'alert': 'CSP', 'riskcode': '2', 'cweid': '693', 'solution': '',
         'instances': [{'uri': 'http://host.docker.internal:8767/', 'method': 'GET'}]}]}]}
    raw = dict(text=json.dumps(payload), base_url='http://127.0.0.1:8767',
               target_url='http://host.docker.internal:8767')
    out = zap.ZapBaseline().normalize(raw, tmp_path, dict(path='/usr/bin/docker', version='2.17.0'))
    assert out['findings'][0]['evidence'] == 'http://127.0.0.1:8767/ GET'


# ---- Regras Semgrep ----

def test_regras_semgrep_yaml_valido():
    yaml = pytest.importorskip('yaml')
    data = yaml.safe_load((semgrep.RULES_DIR/'reposhield.yml').read_text(encoding='utf-8'))
    rules = data['rules']
    assert 10 <= len(rules) <= 15
    langs = {'python', 'js', 'csharp', 'java'}
    for rule in rules:
        match = re.fullmatch(r'reposhield\.(python|js|csharp|java)\.[a-z0-9-]+', rule['id'])
        assert match, rule['id']
        assert rule['severity'] in {'ERROR', 'WARNING', 'INFO'}
        assert rule['message']
        assert rule['metadata']['category'] == 'security'
        assert re.fullmatch(r'CWE-\d+: .+', rule['metadata']['cwe'])
        assert match.group(1) in langs


def test_semgrep_rule_id_strips_config_path_prefix():
    from reposhield.adapters.semgrep import _rule_id
    assert _rule_id('C.dev.x.RepoShield.backend.reposhield.rules.semgrep.reposhield.java.sql') == 'reposhield.java.sql'
