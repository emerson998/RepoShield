import sys
import pytest
from reposhield import cli
from reposhield.assurance import classify, evaluate


DIFF = {'base': 'main', 'note': 'somente linhas alteradas', 'files': []}


def base_report(**extra):
    report = dict(project='demo', created_at='2026-01-01', coverage={'files': 1, 'skipped': 0, 'partial': False},
                  findings=[], errors=[], limitations=['Amostra sintética.'],
                  dependencies={'status': 'passed', 'vulnerabilities': [], 'packages': 1, 'errors': [],
                                'scope': 'fixture'},
                  runtime={'results': [{'case': 'c', 'path': '/', 'identity': 'anon', 'expected': [401],
                                        'actual': 401, 'matched': True}]})
    report.update(extra)
    return report


def test_conditional_advisory_is_gap_not_block():
    report = base_report(dependencies={'status': 'failed', 'vulnerabilities': [
        dict(package='x', version='1.0.0', advisory='GHSA-ssr', reachability='conditional', severity='high')]})
    verdict = evaluate(report)
    assert verdict['status'] == 'inconclusive'
    assert not verdict['release_allowed']
    assert ('1 advisory(ies) grave(s) condicionados a recurso aparentemente ausente (ex.: SSR); '
            'confirme manualmente que não se aplicam.') in verdict['reasons']


def test_diff_clean_is_passed_diff_and_not_release():
    report = base_report(triage={'suppressed': 0, 'baseline': None, 'diff': DIFF, 'warnings': []})
    verdict = evaluate(report)
    assert verdict['status'] == 'passed_diff'
    assert verdict['label'] == 'APROVADO NO DIFF — linhas alteradas sem pendências; não vale como liberação do projeto'
    assert verdict['release_allowed'] is False


def test_diff_gate_returns_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, 'scan', lambda path, **kw: base_report(
        triage={'suppressed': 0, 'baseline': None, 'diff': DIFF, 'warnings': []}))
    monkeypatch.setattr(sys, 'argv', ['reposhield', 'scan', str(tmp_path), '--stdout', '--gate', '--diff-base', 'main'])
    try:
        cli.main()
    except SystemExit as exc:
        code = exc.code
    else:
        code = 0
    assert code == 0


def test_auto_failed_tool_is_gap():
    tool = dict(name='semgrep', axis='sast', network='none', version=None, status='failed',
                findings=0, detail='', requested='auto')
    verdict = evaluate(base_report(tools=[tool]))
    assert verdict['status'] == 'inconclusive'
    assert 'Ferramenta semgrep não executada (falhou); eixo sast não verificado.' in verdict['reasons']


def test_source_suppressed_is_preserved_and_not_review():
    finding = {'id': 'sar', 'rule': 'RS001', 'category': 'secrets', 'file': 'app.py', 'line': 4,
               'source_suppressed': True}
    classify([finding])
    assert finding['disposition'] == 'suppressed'
    verdict = evaluate(base_report(findings=[finding]))
    assert 'sar' not in verdict['review_findings']
    assert any('1 achado(s) suprimido(s) na ferramenta de origem; confira a justificativa.' == w
               for w in verdict['warnings'])
    assert not any('com justificativa' in w for w in verdict['warnings'])


@pytest.mark.parametrize('rule,expected', [
    ('RS403', 'dev_config'),
    ('RS001', 'dev_config'),
    ('gitleaks/generic-api-key', 'review_required'),
])
def test_dev_config_only_for_repo_config_rules(rule, expected):
    finding = {'id': 'f', 'rule': rule, 'category': 'secrets', 'file': 'appsettings.Development.json', 'line': 2}
    classify([finding])
    assert finding['disposition'] == expected


def test_external_tool_secret_in_dev_config_still_blocks():
    finding = {'id': 'gl', 'rule': 'gitleaks/generic-api-key', 'category': 'secrets',
               'file': 'appsettings.Development.json', 'line': 2}
    classify([finding])
    assert 'gl' in evaluate(base_report(findings=[finding]))['review_findings']
    assert evaluate(base_report(findings=[finding]))['status'] == 'inconclusive'
