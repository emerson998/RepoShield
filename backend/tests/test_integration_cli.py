import sys
from pathlib import Path
import pytest
from reposhield import cli
from reposhield.assurance import evaluate
from reposhield.report import markdown


def minimal_report(**extra):
    report = dict(project='demo', created_at='2026-01-01', coverage={'files': 1, 'skipped': 0, 'partial': False},
                  findings=[], errors=[], limitations=['Amostra sintética.'],
                  dependencies=None, runtime=None)
    report.update(extra)
    return report


def tool(**extra):
    base = dict(name='gitleaks', axis='secrets', network='none', version=None, status='executed',
                findings=0, detail='', requested='explicit')
    base.update(extra)
    return base


def test_cli_forwards_integration_options(tmp_path, monkeypatch, capsys):
    captured = {}

    def fake_scan(path, **kwargs):
        captured.update(kwargs)
        return minimal_report()

    monkeypatch.setattr(cli, 'scan', fake_scan)
    monkeypatch.setattr(sys, 'argv', ['reposhield', 'scan', str(tmp_path), '--stdout',
                                      '--tools', 'gitleaks,semgrep', '--import', 'a.sarif',
                                      '--allow-downloads', '--baseline', 'b.json', '--diff-base', 'main'])
    cli.main()
    assert captured['tools'] == {'gitleaks', 'semgrep'}
    assert captured['imports'] == [Path('a.sarif')]
    assert captured['allow_downloads'] is True
    assert captured['baseline'] == Path('b.json')
    assert captured['diff_base'] == 'main'


def test_cli_defaults_keep_previous_behavior(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, 'scan', lambda path, **kw: captured.update(kw) or minimal_report())
    monkeypatch.setattr(sys, 'argv', ['reposhield', 'scan', str(tmp_path), '--stdout'])
    cli.main()
    assert captured['tools'] is None
    assert tuple(captured['imports']) == ()
    assert captured['allow_downloads'] is False
    assert captured['baseline'] is None
    assert captured['diff_base'] is None


def test_cli_rejects_unknown_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['reposhield', 'scan', str(tmp_path), '--tools', 'foo'])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 2


def test_cli_rejects_auto_mixed_with_names(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['reposhield', 'scan', str(tmp_path), '--tools', 'auto,semgrep'])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 2


def test_explicit_missing_tool_is_a_gap():
    report = minimal_report(findings=[], tools=[tool(status='not_installed')])
    report['dependencies'] = {'status': 'passed', 'vulnerabilities': []}
    report['runtime'] = {'results': [{'case': 'c', 'matched': True}]}
    verdict = evaluate(report)
    assert verdict['status'] == 'inconclusive'
    assert any('Ferramenta gitleaks não executada (não instalada); eixo secrets não verificado.' in r
               for r in verdict['reasons'])


def test_auto_missing_tool_is_only_a_warning():
    report = minimal_report(tools=[tool(requested='auto', status='not_installed')])
    report['dependencies'] = {'status': 'passed', 'vulnerabilities': []}
    report['runtime'] = {'results': [{'case': 'c', 'matched': True}]}
    verdict = evaluate(report)
    assert verdict['status'] == 'passed_scoped'
    assert any('Ferramentas automáticas não executadas: gitleaks (não instalada).' in w for w in verdict['warnings'])


def test_suppressed_and_baseline_findings_do_not_block():
    report = minimal_report(findings=[
        {'id': 'a', 'disposition': 'suppressed', 'rule': 'RS004', 'file': 'x.py', 'line': 1},
        {'id': 'b', 'disposition': 'baseline', 'rule': 'RS004', 'file': 'y.py', 'line': 2},
    ])
    report['dependencies'] = {'status': 'passed', 'vulnerabilities': []}
    report['runtime'] = {'results': [{'case': 'c', 'matched': True}]}
    verdict = evaluate(report)
    assert verdict['review_findings'] == []
    assert verdict['status'] == 'passed_scoped'
    assert any('suprimido(s)' in w for w in verdict['warnings'])
    assert any('linha de base' in w for w in verdict['warnings'])


def test_diff_mode_adds_exclusion_and_triage_warning():
    report = minimal_report(triage={'suppressed': 0, 'baseline': None,
                                    'diff': {'base': 'origin/main', 'note': 'linhas alteradas', 'files': []},
                                    'warnings': ['Aviso de teste.']})
    report['dependencies'] = {'status': 'passed', 'vulnerabilities': []}
    report['runtime'] = {'results': [{'case': 'c', 'matched': True}]}
    verdict = evaluate(report)
    assert any('origin/main' in e and '(modo diff)' in e for e in verdict['exclusions'])
    assert 'Aviso de teste.' in verdict['warnings']


def test_markdown_shows_tools_and_triage_sections():
    finding_open = {'id': 'p', 'rule': 'RS004', 'severity': 'high', 'title': 'Debug ativo', 'file': 'app.py', 'line': 3,
                    'confidence': 'high', 'evidence': 'debug=True', 'recommendation': 'Desative o debug.'}
    finding_suppressed = dict(finding_open, id='s', title='Segredo antigo', disposition='suppressed',
                              source='gitleaks@8.18.0',
                              suppressed_by={'author': 'dev', 'expires': '2027-01-01', 'justification': 'Valor de exemplo fictício'})
    report = minimal_report(findings=[finding_open, finding_suppressed],
                            tools=[tool(name='gitleaks', version='8.18.0', status='executed', findings=1),
                                   tool(name='trivy', axis='iac', network='db_download', status='skipped_network',
                                        requested='explicit', detail='exige --allow-downloads')],
                            triage={'suppressed': 1, 'baseline': {'file': 'b.json', 'new': 1, 'existing': 2},
                                    'diff': {'base': 'main', 'note': 'somente linhas alteradas', 'files': []},
                                    'warnings': []})
    report['verdict'] = evaluate(report)
    md = markdown(report)
    assert '## Ferramentas executadas' in md
    assert '| gitleaks | 8.18.0 | secrets | nenhuma | executada | 1 |' in md
    assert 'bloqueada: exige consentimento de rede' in md
    assert '## Triagem' in md
    assert 'Linha de base b.json: 1 novo(s), 2 existente(s).' in md
    assert '### Não bloqueantes' in md
    assert 'Origem: gitleaks@8.18.0' in md
    assert 'Suprimido por dev até 2027-01-01: Valor de exemplo fictício' in md
    assert md.index('Debug ativo') < md.index('### Não bloqueantes') < md.index('Segredo antigo')


def test_markdown_old_report_without_new_fields_still_renders():
    old_finding = {'id': 'o', 'rule': 'RS004', 'severity': 'low', 'title': 'Antigo', 'file': 'a.py', 'line': 1,
                   'confidence': 'medium', 'evidence': 'x', 'recommendation': 'Ajuste.'}
    report = minimal_report(findings=[old_finding])
    report['verdict'] = evaluate(report)
    md = markdown(report)
    assert '## Ferramentas executadas' not in md
    assert '## Triagem' not in md
    assert 'Antigo' in md
    assert 'Origem:' not in md
