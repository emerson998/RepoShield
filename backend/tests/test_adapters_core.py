import json
from pathlib import Path

import pytest

from reposhield.adapters import base, gitleaks as gitleaks_mod, osv_scanner as osv_mod, sarif
from reposhield.adapters.base import Result, ToolError, run_adapters
from reposhield.adapters.gitleaks import Gitleaks
from reposhield.adapters.osv_scanner import OsvScanner
from reposhield.scanner import finding


def fake_exec(monkeypatch, handler):
    """Substitui execute em todos os módulos que o chamam. Nunca roda binário real."""
    calls = []

    def execute(args, **kwargs):
        calls.append(list(args))
        return handler(list(args), kwargs)

    monkeypatch.setattr(base, 'execute', execute)
    monkeypatch.setattr(gitleaks_mod, 'execute', execute)
    monkeypatch.setattr(osv_mod, 'execute', execute)
    return calls


def sarif_doc(results, rules=None, driver_name='Demo', version='1.2.3'):
    return json.dumps({'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': driver_name, 'version': version, 'rules': rules or []}},
        'results': results}]})


def sarif_result(rule_id='R1', uri='src/a.cs', line=3, level='warning', **extra):
    item = {'ruleId': rule_id, 'level': level, 'message': {'text': 'msg'},
            'locations': [{'physicalLocation': {'artifactLocation': {'uri': uri}, 'region': {'startLine': line}}}]}
    item.update(extra)
    return item


# ---------- SARIF ----------

def test_sarif_decodes_relative_and_absolute_paths(tmp_path):
    root = tmp_path / 'proj'
    doc = sarif_doc([
        sarif_result(uri='src/My%20File.cs'),
        sarif_result(uri=(root / 'sub' / 'a b.cs').as_uri()),
        sarif_result(uri=(tmp_path / 'outside' / 'x y.cs').as_uri()),
    ])
    files = [item['file'] for item in sarif.import_sarif(doc, root=root)]
    assert files == ['src/My File.cs', 'sub/a b.cs', '(externo)/x y.cs']


def test_sarif_cwe_from_rule_tags_and_critical_severity():
    rules = [{'id': 'R9', 'shortDescription': {'text': 'XSS'}, 'help': {'text': 'Encode output.'},
              'properties': {'tags': ['security', 'external/cwe/cwe-79'], 'security-severity': '9.1'}}]
    [item] = sarif.import_sarif(sarif_doc([sarif_result(rule_id='R9', level='note')], rules=rules))
    assert item['cwe'] == 'CWE-79'
    assert item['severity'] == 'critical'
    assert item['title'] == 'XSS'
    assert item['recommendation'] == 'Encode output.'
    assert item['category'] == 'sast'


def test_sarif_cwe_from_result_tags_and_level_fallback():
    doc = sarif_doc([sarif_result(rule_id='R2', level='error', properties={'tags': ['CWE-89']})])
    [item] = sarif.import_sarif(doc)
    assert item['cwe'] == 'CWE-89'
    assert item['severity'] == 'high'


def test_sarif_ignores_pass_and_not_applicable_keeps_suppressed_marked():
    doc = sarif_doc([
        sarif_result(uri='accepted.cs', suppressions=[{'status': 'accepted'}]),
        sarif_result(uri='kept.cs', suppressions=[{'status': 'rejected'}]),
        sarif_result(uri='pass.cs', kind='pass'),
        sarif_result(uri='na.cs', kind='notApplicable'),
    ])
    items = sarif.import_sarif(doc)
    assert [item['file'] for item in items] == ['accepted.cs', 'kept.cs']
    assert items[0]['disposition'] == 'suppressed' and items[0]['source_suppressed'] is True
    assert 'disposition' not in items[1]


def test_sarif_rule_by_index_and_sanitized_tool_name():
    rules = [{'id': 'IDX1', 'shortDescription': {'text': 'by index'}}]
    doc = sarif_doc([{'message': {'text': 'm'}, 'level': 'note',
                      'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'a.cs'}, 'region': {'startLine': 2}}}],
                      'ruleIndex': 0}], rules=rules, driver_name='My Tool!')
    [item] = sarif.import_sarif(doc)
    assert item['rule'] == 'mytool/IDX1'
    assert item['title'] == 'by index'


def test_sarif_extra_is_appended_to_evidence():
    [item] = sarif.import_sarif(sarif_doc([sarif_result()]), extra=lambda result: 'commit abc')
    assert item['evidence'].endswith('commit abc')


@pytest.mark.parametrize('text', ['[]', '{"runs": "x"}', '{not json'])
def test_sarif_rejects_invalid_documents(text):
    with pytest.raises(ValueError, match='SARIF inválido'):
        sarif.import_sarif(text)


def test_sarif_result_limit():
    with pytest.raises(ValueError, match='limite'):
        sarif.import_sarif(sarif_doc([{}] * 20_001))


# ---------- Gitleaks ----------

def gitleaks_report(uri='config/app.env', line=3):
    return json.dumps({'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'gitleaks', 'version': '8.18.0',
                            'rules': [{'id': 'generic-api-key', 'shortDescription': {'text': 'Generic API Key'}}]}},
        'results': [{'ruleId': 'generic-api-key', 'level': 'error',
                     'message': {'text': 'Detected a Generic API Key, redacted'},
                     'locations': [{'physicalLocation': {'artifactLocation': {'uri': uri},
                                                         'region': {'startLine': line}}}],
                     'partialFingerprints': {'commitSha': 'a1b2c3d4e5f6a7b8c9d0'}}]}]})


def run_gitleaks(monkeypatch, root, tmp_path, report=None):
    workdir = tmp_path / 'work'
    workdir.mkdir()

    def handler(args, kwargs):
        if '--report-path' not in args:  # chamada de 'git config' feita por git_history_safe
            return Result(0, '', '')
        report_path = Path(args[args.index('--report-path') + 1])
        report_path.write_text(report or gitleaks_report(), encoding='utf-8')
        return Result(0, '', '')

    calls = fake_exec(monkeypatch, handler)
    # Determinístico mesmo sem git instalado: a checagem de config usa o git resolvido aqui (falso).
    monkeypatch.setattr(base, 'resolve_binary', lambda name, root=None: '/fake/git' if name == 'git' else None)
    tool = dict(path='/fake/gitleaks', version='8.18.0')
    adapter = Gitleaks()
    raw = adapter.run(root, workdir, tool, {})
    out = adapter.normalize(raw, root, tool)
    return calls, out, workdir


def test_gitleaks_without_git_adds_no_git(monkeypatch, tmp_path):
    root = tmp_path / 'proj'
    root.mkdir()
    calls, out, _ = run_gitleaks(monkeypatch, root, tmp_path)
    assert '--no-git' in calls[-1]
    assert out['detail'].startswith('Histórico git não varrido')


def test_gitleaks_with_safe_git_scans_history(monkeypatch, tmp_path):
    root = tmp_path / 'proj'
    (root / '.git').mkdir(parents=True)
    (root / '.git' / 'config').write_text('[core]\n\trepositoryformatversion = 0\n', encoding='utf-8')
    calls, out, _ = run_gitleaks(monkeypatch, root, tmp_path)
    assert '--no-git' not in calls[-1]
    assert out['detail'] == 'Arquivos e histórico git varridos.'


def test_gitleaks_git_config_with_textconv_adds_no_git(monkeypatch, tmp_path):
    root = tmp_path / 'proj'
    (root / '.git').mkdir(parents=True)
    (root / '.git' / 'config').write_text('[diff "x"]\n\ttextconv = evil-program\n', encoding='utf-8')
    calls, _, _ = run_gitleaks(monkeypatch, root, tmp_path)
    assert '--no-git' in calls[-1]


def test_gitleaks_uses_default_rules_not_project_config(monkeypatch, tmp_path):
    root = tmp_path / 'proj'
    root.mkdir()
    (root / '.gitleaks.toml').write_text('[allowlist]\npaths = [".*"]\n', encoding='utf-8')
    calls, _, workdir = run_gitleaks(monkeypatch, root, tmp_path)
    config = Path(calls[-1][calls[-1].index('--config') + 1])
    assert config.parent == workdir
    assert 'useDefault = true' in config.read_text(encoding='utf-8')


def test_gitleaks_fingerprint_matches_rs403_and_rs001_on_same_line(monkeypatch, tmp_path):
    root = tmp_path / 'proj'
    root.mkdir()
    _, out, _ = run_gitleaks(monkeypatch, root, tmp_path)
    [item] = out['findings']
    assert item['fingerprint'] == finding('RS403', 'config/app.env', 3, 'x')['fingerprint']
    assert item['fingerprint'] == finding('RS001', 'config/app.env', 3, 'x')['fingerprint']
    assert item['category'] == 'secrets'
    assert item['cwe'] == 'CWE-798'
    assert item['evidence'].endswith('commit a1b2c3d4e5f6')


def test_gitleaks_nonzero_exit_is_tool_error(monkeypatch, tmp_path):
    fake_exec(monkeypatch, lambda args, kwargs: Result(2, '', 'fatal: boom'))
    with pytest.raises(ToolError, match='boom'):
        Gitleaks().run(tmp_path, tmp_path, dict(path='/fake/gitleaks', version='8'), {})


# ---------- OSV-Scanner ----------

GHSA_LODASH = {'id': 'GHSA-35jh-r3h4-6jhm', 'aliases': ['CVE-2021-23337'], 'summary': 'Command Injection in lodash',
               'database_specific': {'severity': 'HIGH'},
               'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N'}],
               'affected': [{'package': {'ecosystem': 'npm', 'name': 'lodash'},
                             'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': '4.17.21'}]}]}]}
GHSA_JEST = {'id': 'GHSA-jest-test', 'summary': 'dev tool issue', 'database_specific': {'severity': 'LOW'},
             'affected': [{'package': {'ecosystem': 'npm', 'name': 'jest-x'},
                           'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': '1.0.1'}]}]}]}
GHSA_NUGET = {'id': 'GHSA-nuget-test', 'summary': 'json issue', 'database_specific': {'severity': 'MODERATE'},
              'affected': [{'package': {'ecosystem': 'NuGet', 'name': 'Newtonsoft.Json'},
                            'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '13.0.1'}]}]}]}


def write_lock(root):
    (root / 'package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {
        '': {},
        'node_modules/lodash': {'version': '4.17.20'},
        'node_modules/jest-x': {'version': '1.0.0', 'dev': True},
    }}), encoding='utf-8')


def osv_json(root):
    return {'results': [
        {'source': {'path': str(root / 'package-lock.json'), 'type': 'lockfile'}, 'packages': [
            {'package': {'name': 'lodash', 'version': '4.17.20', 'ecosystem': 'npm'}, 'vulnerabilities': [GHSA_LODASH]},
            {'package': {'name': 'jest-x', 'version': '1.0.0', 'ecosystem': 'npm'}, 'vulnerabilities': [GHSA_JEST]},
        ]},
        {'source': {'path': str(root / 'App' / 'App.csproj'), 'type': 'lockfile'}, 'packages': [
            {'package': {'name': 'Newtonsoft.Json', 'version': '12.0.1', 'ecosystem': 'NuGet'},
             'vulnerabilities': [GHSA_NUGET]}]},
    ]}


def test_osv_normalizes_npm_and_nuget_to_dependencies_format(tmp_path):
    (tmp_path / 'App').mkdir()
    write_lock(tmp_path)
    out = OsvScanner().normalize(osv_json(tmp_path), tmp_path, dict(path='/x', version='2.0.0'))
    dep = out['dependencies']
    assert set(dep) == {'status', 'packages', 'vulnerabilities', 'errors', 'warnings', 'skipped_local', 'scope'}
    assert dep['status'] == 'failed'
    assert dep['packages'] == 3
    assert dep['errors'] == [] and dep['skipped_local'] == 0
    assert dep['scope'] == 'Lockfiles de todos os ecossistemas suportados pelo OSV-Scanner 2.0.0.'
    assert out['findings'] == []
    by_id = {v['advisory']: v for v in dep['vulnerabilities']}
    lodash = by_id['GHSA-35jh-r3h4-6jhm']
    assert lodash['severity'] == 'high'
    assert lodash['fixed_in'] == ['4.17.21']
    assert lodash['reachability'] == 'production'
    assert lodash['ecosystem'] == 'npm'
    assert lodash['cvss'] == 'CVSS:3.1/AV:N'
    assert by_id['GHSA-jest-test']['reachability'] == 'dev_only'
    assert by_id['GHSA-jest-test']['severity'] == 'low'
    nuget = by_id['GHSA-nuget-test']
    assert nuget['severity'] == 'medium'
    assert nuget['fixed_in'] == ['13.0.1']
    assert nuget['ecosystem'] == 'NuGet'
    assert nuget['reachability'] == 'production'


def test_osv_clean_scan_passes_and_empty_is_incomplete(tmp_path):
    adapter = OsvScanner()
    clean = adapter.normalize({'results': [{'packages': [
        {'package': {'name': 'left-pad', 'version': '1.0.0', 'ecosystem': 'npm'}, 'vulnerabilities': []}]}]},
        tmp_path, dict(version='2'))
    assert clean['dependencies']['status'] == 'passed'
    empty = adapter.normalize({'results': []}, tmp_path, dict(version='2'))
    assert empty['dependencies']['status'] == 'incomplete'


def test_osv_applies_only_to_lockfiles_in_allowed_depth(tmp_path):
    adapter = OsvScanner()
    assert not adapter.applies(tmp_path)
    (tmp_path / 'node_modules' / 'x').mkdir(parents=True)
    (tmp_path / 'node_modules' / 'x' / 'package-lock.json').write_text('{}')
    assert not adapter.applies(tmp_path)
    (tmp_path / 'a' / 'b' / 'c' / 'd').mkdir(parents=True)
    (tmp_path / 'a' / 'b' / 'c' / 'd' / 'Cargo.lock').write_text('')
    assert not adapter.applies(tmp_path)
    (tmp_path / 'a' / 'b' / 'c' / 'Cargo.lock').write_text('')
    assert adapter.applies(tmp_path)


def test_osv_falls_back_to_v1_arguments(monkeypatch, tmp_path):
    def handler(args, kwargs):
        if args[1] == 'scan':
            return Result(127, '', 'Error: unknown command "scan" for "osv-scanner"')
        return Result(0, json.dumps({'results': []}), '')

    calls = fake_exec(monkeypatch, handler)
    raw = OsvScanner().run(tmp_path, tmp_path, dict(path='/fake/osv', version='1'), {})
    assert raw == {'results': []}
    assert calls[0][1:3] == ['scan', 'source']
    assert calls[1][1:3] == ['--format', 'json']
    assert all('--experimental-call-analysis' not in call for call in calls)


def test_osv_other_exit_code_is_tool_error(monkeypatch, tmp_path):
    fake_exec(monkeypatch, lambda args, kwargs: Result(3, '', 'boom'))
    with pytest.raises(ToolError, match='boom'):
        OsvScanner().run(tmp_path, tmp_path, dict(path='/fake/osv', version='2'), {})


def test_osv_reads_dev_flags_from_package_lock_inside_root(tmp_path):
    (tmp_path / 'App').mkdir()
    write_lock(tmp_path)
    out = OsvScanner().normalize(osv_json(tmp_path), tmp_path, dict(version='2'))
    reach = {v['advisory']: v['reachability'] for v in out['dependencies']['vulnerabilities']}
    assert reach == {'GHSA-35jh-r3h4-6jhm': 'production', 'GHSA-jest-test': 'dev_only', 'GHSA-nuget-test': 'production'}


# ---------- run_adapters ----------

def test_run_adapters_missing_tool_is_not_installed(monkeypatch, tmp_path):
    monkeypatch.setattr(base.shutil, 'which', lambda name, **kw: None)
    out = run_adapters(tmp_path, [Gitleaks(), OsvScanner()], requested={'auto'})
    assert [t['status'] for t in out['tools']] == ['not_installed', 'not_installed']
    assert out['findings'] == [] and out['dependencies'] is None


def test_run_adapters_per_query_without_consent_is_skipped(monkeypatch, tmp_path):
    (tmp_path / 'package-lock.json').write_text('{}', encoding='utf-8')
    monkeypatch.setattr(base.shutil, 'which', lambda name, **kw: '/fake/osv-scanner')
    calls = fake_exec(monkeypatch, lambda args, kwargs: Result(0, 'osv-scanner version 2.0.1', ''))
    out = run_adapters(tmp_path, [OsvScanner()], requested={'osv-scanner'}, dependencies_consent=False)
    assert out['tools'][0]['status'] == 'skipped_network'
    assert out['tools'][0]['version'] == '2.0.1'
    assert len(calls) == 1  # só a checagem de versão; nenhuma consulta de pacotes


def test_run_adapters_with_consent_executes_osv(monkeypatch, tmp_path):
    (tmp_path / 'App').mkdir()
    write_lock(tmp_path)
    payload = json.dumps(osv_json(tmp_path))
    monkeypatch.setattr(base.shutil, 'which', lambda name, **kw: '/fake/osv-scanner')

    def handler(args, kwargs):
        if args[1:] == ['--version']:
            return Result(0, 'osv-scanner version 2.0.1', '')
        return Result(1, payload, '')

    fake_exec(monkeypatch, handler)
    out = run_adapters(tmp_path, [OsvScanner()], requested={'auto'}, dependencies_consent=True)
    assert out['tools'][0]['status'] == 'executed'
    assert out['dependencies']['status'] == 'failed'
    assert out['dependencies']['packages'] == 3


@pytest.mark.parametrize('status', ['underReview', 'rejected', 'unknown', None])
def test_unapproved_sarif_suppression_still_counts(status):
    suppression = {'kind': 'external'}
    if status is not None:
        suppression['status'] = status
    [item] = sarif.import_sarif(sarif_doc([sarif_result(suppressions=[suppression])]))
    assert not item.get('source_suppressed')
    assert item.get('disposition') != 'suppressed'


def test_sarif_resolves_artifact_index_and_nested_uri_bases(tmp_path):
    data = json.loads(sarif_doc([sarif_result()]))
    run = data['runs'][0]
    run['originalUriBaseIds'] = {
        'ROOT': {'uri': tmp_path.as_uri() + '/'},
        'SRC': {'uri': 'src/', 'uriBaseId': 'ROOT'},
    }
    run['artifacts'] = [{'location': {'uri': 'a%20b.cs', 'uriBaseId': 'SRC'}}]
    run['results'][0]['locations'][0]['physicalLocation']['artifactLocation'] = {'index': 0}
    [item] = sarif.import_sarif(json.dumps(data), root=tmp_path)
    assert item['file'] == 'src/a b.cs'


def test_sarif_cyclic_uri_base_is_bounded():
    data = json.loads(sarif_doc([sarif_result()]))
    run = data['runs'][0]
    run['originalUriBaseIds'] = {'A': {'uri': 'src/', 'uriBaseId': 'A'}}
    run['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uriBaseId'] = 'A'
    assert sarif.import_sarif(json.dumps(data))[0]['file'] == 'src/src/a.cs'


def test_sarif_failed_invocation_cannot_be_imported_as_complete():
    data = json.loads(sarif_doc([]))
    data['runs'][0]['invocations'] = [{'executionSuccessful': False}]
    with pytest.raises(ValueError, match='execução incompleta'):
        sarif.import_sarif(json.dumps(data))


@pytest.mark.parametrize('severity', ['critical', 'high', 'medium', 'low'])
def test_reposhield_sarif_roundtrip_preserves_severity_cwe_and_suppression(severity):
    from reposhield.scanner import sarif as export_sarif
    original = finding('RS001', 'src/config.py', 3, 'synthetic evidence')
    original.update(severity=severity, disposition='suppressed',
                    suppressed_by={'justification': 'Revisado pela equipe.'})
    exported = export_sarif({'findings': [original]})
    [item] = sarif.import_sarif(json.dumps(exported))
    assert item['severity'] == severity
    assert item['cwe'] == original['cwe']
    assert item['disposition'] == 'suppressed'
    assert item['category'] == 'secrets'
