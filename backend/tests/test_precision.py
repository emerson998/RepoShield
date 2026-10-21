import json
import pytest
from reposhield import dependencies
from reposhield.assurance import evaluate
from reposhield.dependencies import check
from reposhield.scanner import scan


@pytest.fixture(autouse=True)
def clear_osv_details():
    dependencies._DETAILS.clear()
    yield
    dependencies._DETAILS.clear()


def osv(monkeypatch, detail=None, vulnerable=('@angular/router',)):
    class Response:
        def __init__(self, data): self.data = data
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return json.dumps(self.data).encode()
    class Opener:
        def open(self, request, timeout):
            if '/v1/vulns/' in request.full_url:
                return Response(detail)
            queries = json.loads(request.data)['queries']
            return Response({'results': [{'vulns': [{'id': 'GHSA-ssr'}]} if q['package']['name'] in vulnerable else {}
                                         for q in queries]})
    monkeypatch.setattr('urllib.request.build_opener', lambda *args: Opener())


def write_lock(tmp_path, packages):
    (tmp_path/'package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {'': {'name': 'app'}, **packages}}))


def test_authorize_inherited_from_base_class_in_another_file(tmp_path):
    (tmp_path/'ApiControllerBase.cs').write_text(
        'using Microsoft.AspNetCore.Authorization;\n[Authorize]\npublic class ApiControllerBase : ControllerBase { }\n')
    (tmp_path/'ItemsController.cs').write_text(
        '[Route("api/[controller]")]\npublic class ItemsController : ApiControllerBase {\n'
        '    [HttpGet("{id}")]\n    public IActionResult Get(int id) => Ok();\n}\n')
    report = scan(tmp_path)
    ep = next(e for e in report['endpoints'] if e['file'] == 'ItemsController.cs')
    assert ep['authentication'] == 'hint_found'
    assert ep['auth_sources'] == ['inherited_authorize:ApiControllerBase']
    assert ep['class_name'] == 'ItemsController' and ep['base_class'] == 'ApiControllerBase'
    assert ep['object_authorization'] == 'manual_review'
    assert not any(f['rule'] in {'RS100', 'RS102'} and f['file'] == 'ItemsController.cs' for f in report['findings'])


def test_anonymous_class_in_chain_keeps_rs100(tmp_path):
    (tmp_path/'ApiControllerBase.cs').write_text('[Authorize]\npublic class ApiControllerBase : ControllerBase { }\n')
    (tmp_path/'Mid.cs').write_text('[AllowAnonymous]\npublic class Mid : ApiControllerBase { }\n')
    (tmp_path/'ItemsController.cs').write_text(
        'public class ItemsController : Mid {\n    [HttpGet("items")]\n    public IActionResult Get() => Ok();\n}\n')
    report = scan(tmp_path)
    ep = next(e for e in report['endpoints'] if e['file'] == 'ItemsController.cs')
    assert ep['authentication'] == 'unknown' and ep['auth_sources'] == []
    assert any(f['rule'] == 'RS100' and f['file'] == 'ItemsController.cs' for f in report['findings'])


def test_development_config_secret_is_not_review_blocker(tmp_path):
    (tmp_path/'appsettings.Development.json').write_text('{\n  "JwtKey": "Qm9yZy1yZWFsLXNpZ25pbmcta2V5LTk4NzY1NA"\n}\n')
    report = scan(tmp_path)
    hits = [f for f in report['findings'] if f['file'] == 'appsettings.Development.json' and f['category'] == 'secrets']
    assert hits and all(f['disposition'] == 'dev_config' for f in hits)
    assert not {f['id'] for f in hits} & set(report['verdict']['review_findings'])
    assert any('desenvolvimento' in w for w in report['verdict']['warnings'])


def test_runtime_guard_marks_secret_without_leaking_digest_or_value(tmp_path):
    (tmp_path/'appsettings.json').write_text('{\n  "JwtKey": "dev-only-signing-key-123456"\n}\n')
    (tmp_path/'Program.cs').write_text(
        'if (!env.IsDevelopment() && key == "dev-only-signing-key-123456") throw new Exception();\n')
    report = scan(tmp_path)
    hits = [f for f in report['findings'] if f['file'] == 'appsettings.json' and f['category'] == 'secrets']
    assert hits and all(f['disposition'] == 'runtime_guarded' for f in hits)
    assert all(f['runtime_guard'] for f in hits)
    dumped = json.dumps(report)
    assert '_value_sha' not in dumped
    assert 'dev-only-signing-key-123456' not in dumped


def test_ssr_advisory_not_applicable_without_ssr_in_lock(tmp_path, monkeypatch):
    detail = {'database_specific': {'severity': 'HIGH'}, 'summary': 'Open redirect in SSR rendering of router', 'details': ''}
    write_lock(tmp_path, {'node_modules/@angular/router': {'version': '17.0.0'}})
    osv(monkeypatch, detail)
    report = scan(tmp_path, dependencies_enabled=True)
    vuln = report['dependencies']['vulnerabilities'][0]
    assert vuln['severity'] == 'high'
    assert vuln['reachability'] == 'conditional' and vuln['condition']
    assert report['verdict']['status'] != 'rejected'
    assert any('condicionados a recurso aparentemente ausente' in r for r in report['verdict']['reasons'])


def test_ssr_advisory_is_production_when_ssr_is_in_lock(tmp_path, monkeypatch):
    detail = {'database_specific': {'severity': 'HIGH'}, 'summary': 'Open redirect in SSR rendering of router', 'details': ''}
    write_lock(tmp_path, {'node_modules/@angular/router': {'version': '17.0.0'},
                          'node_modules/@angular/ssr': {'version': '17.0.0'}})
    osv(monkeypatch, detail)
    report = scan(tmp_path, dependencies_enabled=True)
    vuln = next(v for v in report['dependencies']['vulnerabilities'] if v['package'] == '@angular/router')
    assert vuln['reachability'] == 'production' and 'condition' not in vuln
    assert report['verdict']['status'] == 'rejected'


def test_workspace_only_lock_passes_without_querying_osv(tmp_path, monkeypatch):
    (tmp_path/'package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {
        '': {'name': 'app'}, 'node_modules/ui': {'link': True, 'resolved': 'packages/ui'},
        'packages/ui': {'name': 'ui', 'version': '1.0.0'}}}))
    def no_network(*args): raise AssertionError('OSV não deve ser consultado')
    monkeypatch.setattr('urllib.request.build_opener', no_network)
    result = check(tmp_path)
    assert result['status'] == 'passed'
    assert result['packages'] == 0
    assert 'Nenhuma dependência de registro npm no lock; apenas pacotes locais/workspace.' in result['warnings']
