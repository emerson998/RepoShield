import json

import pytest

from reposhield import dependencies, java
from reposhield.adapters import sarif
from reposhield.dependencies import check
from reposhield.scanner import scan
from reposhield.syntax import placeholder


# ---------- placeholder ----------

@pytest.mark.parametrize('value', ['changeme', 'change-me', 'example1', '<senha>', '${X}', 'your-api-key',
                                   'your_secret_here', '"changeme"', '{{TOKEN}}', '%SECRET%', '__KEY__',
                                   '***', 'xxxx', '...', 'redacted', '[redacted]', 'minhasenha', 'sua-senha', ''])
def test_placeholder_true_for_documentation_values(value):
    assert placeholder(value)


@pytest.mark.parametrize('value', ['changeme-Pr0dSecret!9', 'example.RealKey9921', 'yourSecretValue123',
                                   'your-key-2024x9'])
def test_placeholder_false_for_real_looking_values(value):
    assert not placeholder(value)


# ---------- .NET runtime guard ----------

KEY_JSON = '{\n  "JwtKey": "REAL-PROD-KEY-123"\n}\n'
DEV_KEY = 'dev-only-signing-key-123456'


def secrets_of(report, file):
    return [f for f in report['findings'] if f['file'] == file and f['category'] == 'secrets']


def test_fixed_key_check_with_bare_throw_is_not_runtime_guard(tmp_path):
    (tmp_path/'appsettings.json').write_text(KEY_JSON)
    (tmp_path/'Program.cs').write_text('if (key != "REAL-PROD-KEY-123") throw new Exception();\n')
    hits = secrets_of(scan(tmp_path), 'appsettings.json')
    assert hits
    assert not any(f.get('runtime_guard') or f.get('disposition') == 'runtime_guarded' for f in hits)


def test_environment_guard_in_same_project_applies(tmp_path):
    # Positive control: the same literal guarded by IsDevelopment in the same directory is marked.
    (tmp_path/'appsettings.json').write_text(f'{{\n  "JwtKey": "{DEV_KEY}"\n}}\n')
    (tmp_path/'Program.cs').write_text(f'if (!env.IsDevelopment() && key == "{DEV_KEY}") throw new Exception();\n')
    hits = secrets_of(scan(tmp_path), 'appsettings.json')
    assert hits and all(f.get('runtime_guard') for f in hits)


def test_environment_guard_in_sibling_project_does_not_apply(tmp_path):
    (tmp_path/'a').mkdir()
    (tmp_path/'b').mkdir()
    (tmp_path/'a'/'appsettings.json').write_text(f'{{\n  "JwtKey": "{DEV_KEY}"\n}}\n')
    (tmp_path/'b'/'Program.cs').write_text(f'if (!env.IsDevelopment() && key == "{DEV_KEY}") throw new Exception();\n')
    hits = secrets_of(scan(tmp_path), 'a/appsettings.json')
    assert hits and not any(f.get('runtime_guard') for f in hits)


# ---------- SSR condition ----------

DETAIL_SSR = {'summary': 'Open redirect in SSR rendering of router', 'details': ''}


class _Response:
    def __init__(self, data): self.data = data
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, limit): return json.dumps(self.data).encode()


def osv(monkeypatch, detail, vulnerable=('@angular/router',)):
    class Opener:
        def open(self, request, timeout):
            if '/v1/vulns/' in request.full_url:
                return _Response(detail)
            queries = json.loads(request.data)['queries']
            return _Response({'results': [{'vulns': [{'id': 'GHSA-ssr'}]} if q['package']['name'] in vulnerable else {}
                                          for q in queries]})
    monkeypatch.setattr('urllib.request.build_opener', lambda *args: Opener())


def write_lock(tmp_path, packages):
    (tmp_path/'package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {'': {'name': 'app'}, **packages}}))


ROUTER = {'node_modules/@angular/router': {'version': '17.0.0'}}


@pytest.fixture(autouse=True)
def clear_osv_details():
    dependencies._DETAILS.clear()
    yield
    dependencies._DETAILS.clear()


def ssr_vuln(tmp_path, monkeypatch, detail, packages=ROUTER):
    write_lock(tmp_path, packages)
    osv(monkeypatch, detail)
    return check(tmp_path)


def test_ssr_high_is_conditional(tmp_path, monkeypatch):
    result = ssr_vuln(tmp_path, monkeypatch, dict(DETAIL_SSR, database_specific={'severity': 'HIGH'}))
    vuln = result['vulnerabilities'][0]
    assert vuln['severity'] == 'high'
    assert vuln['reachability'] == 'conditional' and vuln['condition']


def test_ssr_unknown_severity_is_conditional(tmp_path, monkeypatch):
    result = ssr_vuln(tmp_path, monkeypatch, dict(DETAIL_SSR))
    vuln = result['vulnerabilities'][0]
    assert vuln['severity'] == 'unknown'
    assert vuln['reachability'] == 'conditional' and vuln['condition']


def test_ssr_medium_is_not_applicable(tmp_path, monkeypatch):
    result = ssr_vuln(tmp_path, monkeypatch, dict(DETAIL_SSR, database_specific={'severity': 'MEDIUM'}))
    vuln = result['vulnerabilities'][0]
    assert vuln['severity'] == 'medium'
    assert vuln['reachability'] == 'not_applicable' and vuln['condition']


def test_ssr_condition_ignored_when_local_packages_skipped(tmp_path, monkeypatch):
    # A linked workspace may hold the SSR code, so the advisory stays in production.
    packages = dict(ROUTER, **{'node_modules/ui': {'link': True, 'resolved': 'packages/ui'}})
    result = ssr_vuln(tmp_path, monkeypatch, dict(DETAIL_SSR, database_specific={'severity': 'HIGH'}), packages)
    assert result['skipped_local'] == 1
    vuln = result['vulnerabilities'][0]
    assert vuln['reachability'] == 'production' and 'condition' not in vuln


# ---------- Spring Security ----------

def make(rule, rel, line, evidence, confidence='medium'):
    return dict(rule=rule, file=rel, line=line, evidence=evidence, confidence=confidence)


CTRL = '''
@RestController
@RequestMapping("/x")
public class XController {
    @GetMapping
    public String get() { return ""; }
    @PostMapping
    public String post() { return ""; }
}
'''
CTRL_REL = 'app/src/main/java/com/x/api/XController.java'
CFG_REL = 'app/src/main/java/com/x/config/SecurityConfig.java'


def resolve(text, cfg_rel, cfg_text, ctrl_rel=CTRL_REL):
    endpoints, findings = java.analyze(text, ctrl_rel, [], make)
    java.resolve_project(endpoints, findings, [(cfg_rel, java.security_config(cfg_text, cfg_rel))])
    return endpoints


def test_get_permit_all_does_not_make_post_public():
    cfg = 'http.authorizeHttpRequests(a -> a.requestMatchers(HttpMethod.GET, "/x").permitAll());'
    by_method = {e['methods'][0]: e for e in resolve(CTRL, CFG_REL, cfg)}
    assert by_method['GET']['authentication'] == 'public_declared'
    assert by_method['POST']['authentication'] == 'unknown'


def test_config_under_src_test_is_ignored_but_main_config_applies():
    cfg_text = 'http.authorizeHttpRequests(a -> a.anyRequest().authenticated());'
    for test_rel in ('app/src/test/java/com/x/TestSecurity.java', 'src/test/java/TestSecurity.java'):
        endpoints = resolve(CTRL, test_rel, cfg_text, ctrl_rel=CTRL_REL)
        assert all(e['authentication'] == 'unknown' for e in endpoints), test_rel
    # Positive control: the same config outside src/test protects both endpoints.
    endpoints = resolve(CTRL, CFG_REL, cfg_text)
    assert all(e['authentication'] == 'hint_found' for e in endpoints)


def test_security_matcher_chain_does_not_protect_controllers_outside():
    cfg_rel = 'app/src/main/java/com/x/config/ApiSecurity.java'
    cfg_text = 'http.securityMatcher("/api/**").authorizeHttpRequests(a -> a.anyRequest().authenticated());'
    assert java.security_config(cfg_text, cfg_rel)['authenticated_default'] is None
    assert all(e['authentication'] == 'unknown' for e in resolve(CTRL, cfg_rel, cfg_text))


def test_deny_all_and_access_count_as_protected():
    cfg_text = 'http.authorizeHttpRequests(a -> a.requestMatchers("/secret/**").denyAll().requestMatchers("/acl/**").access("hasRole(\'X\')"));'
    cfg = java.security_config(cfg_text, CFG_REL)
    assert cfg['public'] == []
    assert cfg['protected'] == [('/secret/**', 'denyAll'), ('/acl/**', 'access')]
    secret_ctrl = '''
@RestController
public class SecretController {
    @GetMapping("/secret/x")
    public String get() { return ""; }
}
'''
    [ep] = resolve(secret_ctrl, CFG_REL, cfg_text)
    assert ep['authentication'] == 'hint_found'


# ---------- SARIF ----------

def sarif_doc(results):
    return json.dumps({'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'Scanner', 'version': '1.0', 'rules': []}}, 'results': results}]})


def sarif_result(message='msg', **extra):
    item = {'ruleId': 'R1', 'level': 'error', 'message': {'text': message},
            'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'src/a.cs'}, 'region': {'startLine': 3}}}]}
    item.update(extra)
    return item


def test_sarif_suppressed_in_source_is_kept_and_marked():
    doc = sarif_doc([sarif_result(suppressions=[{'kind': 'external', 'status': 'accepted',
                                                  'justification': 'Falso positivo confirmado'}])])
    [item] = sarif.import_sarif(doc)
    assert item['disposition'] == 'suppressed' and item['source_suppressed'] is True
    assert item['suppressed_by'] == dict(justification='Falso positivo confirmado', author='ferramenta de origem',
                                         expires=None, match='sarif')


def test_sarif_redacts_before_truncating_evidence():
    # The key starts at char 296: truncating first would leave 'AKIA' unredacted.
    key = 'AKIAIOSFODNN7EXAMPLE'
    [item] = sarif.import_sarif(sarif_doc([sarif_result(message='a' * 295 + ' ' + key)]))
    assert key not in item['evidence'] and 'AKIA' not in item['evidence']
    assert '[REDACTED]' in item['evidence']
