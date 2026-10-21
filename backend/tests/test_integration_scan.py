"""Integração do scan(): Java, adaptadores externos, SARIF importado, supressões, linha de base e diff."""
import json
from datetime import date

import pytest

from reposhield import dotnet
from reposhield.adapters import base
from reposhield.scanner import scan, sarif

TODAY = date(2026, 10, 21)
FUTURE = '2026-11-20'
JUST = 'Revisado com o time de segurança.'

CONTROLLER = '''package com.x.api;

@RestController
@RequestMapping("/api/orders")
public class OrderController {
    @GetMapping("/list")
    public String list() { return ""; }
}
'''

SECURITY = '''package com.x.config;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a.anyRequest().authenticated());
        return http.build();
    }
}
'''

APPSETTINGS = '{\n  "Logging": {},\n  "Password": "super-secret-value-123",\n  "ApiKey": "another-secret-value-456"\n}\n'


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    return path


def gitleaks_sarif(uri='appsettings.json', line=3):
    rule = {'id': 'generic-api-key', 'shortDescription': {'text': 'Generic API Key'},
            'properties': {'tags': ['secret', 'external/cwe/cwe-798']}}
    result = {'ruleId': 'generic-api-key', 'level': 'error', 'message': {'text': 'Generic API Key'},
              'locations': [{'physicalLocation': {'artifactLocation': {'uri': uri}, 'region': {'startLine': line}}}]}
    return json.dumps({'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'gitleaks', 'version': '8.18.0',
                                                                       'rules': [rule]}}, 'results': [result]}]})


def rules_of(report):
    return {f['rule'] for f in report['findings']}


def test_java_controller_is_protected_by_security_config(tmp_path):
    write(tmp_path, 'app/src/main/java/com/x/api/OrderController.java', CONTROLLER)
    write(tmp_path, 'app/src/main/java/com/x/config/SecurityConfig.java', SECURITY)
    report = scan(tmp_path)
    controller = [f for f in report['findings'] if f['file'].endswith('OrderController.java')]
    assert 'RS100' not in {f['rule'] for f in controller}


def test_java_controller_without_security_config_gets_rs100(tmp_path):
    write(tmp_path, 'app/src/main/java/com/x/api/OrderController.java', CONTROLLER)
    report = scan(tmp_path)
    assert 'RS100' in rules_of(report)


def test_imported_sarif_merges_with_rs403_on_same_line(tmp_path):
    write(tmp_path, 'appsettings.json', APPSETTINGS)
    imported = write(tmp_path.parent / 'imports', 'g.sarif', gitleaks_sarif())
    report = scan(tmp_path, imports=[imported])
    same_line = [f for f in report['findings'] if f['file'] == 'appsettings.json' and f['line'] == 3]
    assert len(same_line) == 1
    assert any(rule.startswith('gitleaks/') for rule in same_line[0].get('also_matched', []))
    record = next(t for t in report['tools'] if t['name'] == 'import:g.sarif')
    assert record['status'] == 'imported' and record['requested'] == 'import'


def test_invalid_sarif_import_is_reported_as_failed(tmp_path):
    write(tmp_path, 'app.py', 'x = 1\n')
    bad = write(tmp_path.parent / 'imports', 'bad.sarif', '{"nao": "sarif"}')
    report = scan(tmp_path, imports=[bad])
    assert 'SARIF importado inválido: bad.sarif' in report['errors']
    assert report['coverage']['partial']
    tool = next(t for t in report['tools'] if t['name'] == 'import:bad.sarif')
    assert tool['status'] == 'failed'


def test_requested_adapter_not_installed_is_recorded(tmp_path, monkeypatch):
    write(tmp_path, 'app.py', 'x = 1\n')
    monkeypatch.setattr(base.shutil, 'which', lambda name, **kw: None)
    report = scan(tmp_path, tools={'gitleaks'})
    record = next(t for t in report['tools'] if t['name'] == 'gitleaks')
    assert record['status'] == 'not_installed'
    assert record['requested'] == 'explicit'


def test_unknown_tool_is_rejected(tmp_path):
    with pytest.raises(ValueError, match='Ferramenta desconhecida: nada'):
        scan(tmp_path, tools={'nada'})


def test_valid_suppression_marks_finding_and_counts_it(tmp_path):
    write(tmp_path, 'appsettings.json', APPSETTINGS)
    write(tmp_path, '.reposhield.json', json.dumps({'suppressions': [
        {'rule': 'RS403', 'file': 'appsettings.json', 'line': 3, 'justification': JUST, 'author': 'Emerson', 'expires': FUTURE}]}))
    report = scan(tmp_path, today=TODAY)
    suppressed = [f for f in report['findings'] if f.get('disposition') == 'suppressed']
    assert suppressed and all(f['rule'] == 'RS403' for f in suppressed)
    assert report['triage']['suppressed'] == 1
    assert report['triage']['warnings'] == []


def test_invalid_suppression_goes_to_errors_and_makes_scan_partial(tmp_path):
    write(tmp_path, 'appsettings.json', APPSETTINGS)
    write(tmp_path, '.reposhield.json', json.dumps({'suppressions': [{'rule': 'RS403', 'file': 'appsettings.json'}]}))
    report = scan(tmp_path, today=TODAY)
    assert report['errors']
    assert report['coverage']['partial']
    assert report['triage']['suppressed'] == 0
    assert not any(f.get('disposition') == 'suppressed' for f in report['findings'])


def test_baseline_from_same_scan_marks_everything_existing(tmp_path):
    write(tmp_path, 'appsettings.json', APPSETTINGS)
    first = scan(tmp_path, today=TODAY)
    assert first['findings']
    baseline = write(tmp_path.parent / 'prev', 'baseline.json', json.dumps(first, default=str))
    report = scan(tmp_path, baseline=baseline, today=TODAY)
    assert report['triage']['baseline'] == dict(file='baseline.json', new=0, existing=len(report['findings']))
    assert all(f['baseline'] == 'existing' for f in report['findings'])
    assert all(f['stable_key'] for f in report['findings'])


def test_sarif_output_reflects_suppression_and_baseline(tmp_path):
    write(tmp_path, 'appsettings.json', APPSETTINGS)
    first = scan(tmp_path, today=TODAY)
    baseline = write(tmp_path.parent / 'prev2', 'baseline.json', json.dumps(first, default=str))
    report = scan(tmp_path, baseline=baseline, today=TODAY)
    results = sarif(report)['runs'][0]['results']
    assert all(r['baselineState'] == 'unchanged' for r in results)
    assert 'tools' in sarif(report)['runs'][0]['properties']


def test_diff_keeps_only_findings_on_changed_lines(tmp_path, monkeypatch):
    write(tmp_path, 'appsettings.json', APPSETTINGS)
    (tmp_path / '.git').mkdir()
    (tmp_path / '.git' / 'config').write_text('[core]\n\tbare = false\n', encoding='utf-8')
    diff = ('diff --git a/appsettings.json b/appsettings.json\n'
            '--- a/appsettings.json\n+++ b/appsettings.json\n@@ -4 +4 @@\n'
            '-  "ApiKey": "old-secret-value-000"\n+  "ApiKey": "another-secret-value-456"\n')
    monkeypatch.setattr(base, 'resolve_binary', lambda name, root=None: '/fake/git' if name == 'git' else None)

    def fake_git(args, **kw):
        if 'merge-base' in args:
            return base.Result(0, 'a' * 40 + '\n', '')
        if 'ls-files' in args:
            return base.Result(0, '', '')
        if 'diff' in args:
            return base.Result(0, diff, '')
        return base.Result(0, '', '')  # git config --list: sem chaves perigosas

    monkeypatch.setattr(base, 'execute', fake_git)
    report = scan(tmp_path, diff_base='main', today=TODAY)
    assert report['findings']
    assert {f['line'] for f in report['findings']} == {4}
    assert report['triage']['diff']['files'] == 1
    assert report['triage']['diff']['base'] == 'main'


def test_diff_base_with_unsafe_characters_is_rejected(tmp_path):
    write(tmp_path, 'app.py', 'x = 1\n')
    (tmp_path / '.git').mkdir()
    (tmp_path / '.git' / 'config').write_text('[core]\n', encoding='utf-8')
    with pytest.raises(ValueError):
        scan(tmp_path, diff_base='x;y')


def test_diff_without_safe_git_is_rejected(tmp_path):
    write(tmp_path, 'app.py', 'x = 1\n')
    with pytest.raises(ValueError, match='Diff exige repositório git'):
        scan(tmp_path, diff_base='main')


def test_object_route_with_camel_case_placeholder_gets_rs102(tmp_path):
    write(tmp_path, 'app.py', 'from fastapi import FastAPI\n\napp = FastAPI()\n\n\n'
                             '@app.get("/orders/{orderId}")\ndef read_order(orderId: int):\n    return {"id": orderId}\n')
    report = scan(tmp_path)
    assert 'RS102' in rules_of(report)


def test_guard_hashes_ignores_literal_near_throw_without_comparison():
    lit = 'dev-only-signing-key-123456'
    no_compare = f'if (env.IsDevelopment()) {{ }}\nvar label = "{lit}";\nthrow new Exception();\n'
    assert dotnet.guard_hashes(no_compare) == set()
    compared = f'if (!env.IsDevelopment() && key == "{lit}") throw new Exception();\n'
    assert dotnet.value_digest(lit) in {digest for digest, _ in dotnet.guard_hashes(compared, 'Program.cs')}
