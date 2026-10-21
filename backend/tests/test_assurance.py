import json
import sys
import pytest
from reposhield.assurance import evaluate
from reposhield.scanner import scan, markdown
from reposhield.cli import main
from reposhield.dependencies import check
from reposhield import dependencies


@pytest.fixture(autouse=True)
def clear_osv_details():
    dependencies._DETAILS.clear()
    yield
    dependencies._DETAILS.clear()


def complete():
    return dict(findings=[], errors=[], coverage={'files': 1, 'partial': False},
                dependencies={'status': 'passed', 'vulnerabilities': []},
                runtime={'results': [{'case': 'case-1', 'matched': True}]})


def test_no_findings_does_not_mean_safe(tmp_path):
    (tmp_path/'app.ts').write_text('export const answer = 42;')
    report = scan(tmp_path)
    assert report['verdict']['status'] == 'inconclusive'
    assert not report['verdict']['release_allowed']
    assert 'INCONCLUSIVO' in markdown(report)


@pytest.mark.parametrize('change', ['error', 'partial', 'empty', 'finding', 'runtime', 'dependencies'])
def test_fail_closed(change):
    report = complete()
    if change == 'error': report['errors'] = ['timeout']
    if change == 'partial': report['coverage']['partial'] = True
    if change == 'empty': report['coverage']['files'] = 0
    if change == 'finding': report['findings'] = [{'id': 'x'}]
    if change == 'runtime': report['runtime'] = None
    if change == 'dependencies': report['dependencies']['status'] = 'incomplete'
    assert evaluate(report)['status'] == 'inconclusive'


def test_scoped_success_and_failed_checks():
    report = complete()
    assert evaluate(report)['status'] == 'passed_scoped'
    report['runtime']['results'][0]['matched'] = False
    assert evaluate(report)['status'] == 'rejected'
    report = complete()
    report['dependencies'] = {'status': 'failed', 'vulnerabilities': [{'advisory': 'GHSA-test'}]}
    assert evaluate(report)['status'] == 'inconclusive'
    report['dependencies'] = {'status': 'failed', 'vulnerabilities': [
        {'advisory': 'GHSA-test', 'reachability': 'production', 'severity': 'critical'}]}
    assert evaluate(report)['status'] == 'rejected'


def test_test_token_is_preserved_with_context(tmp_path):
    (tmp_path/'auth.spec.ts').write_text("localStorage.setItem('token', 'fake');")
    (tmp_path/'auth.ts').write_text("localStorage.setItem('token', realToken);")
    report = scan(tmp_path)
    hits = {f['file']: f for f in report['findings'] if f['rule'] == 'RS209'}
    assert hits['auth.spec.ts']['disposition'] == 'test_context'
    assert hits['auth.ts']['disposition'] == 'review_required'
    assert 'JavaScript' in markdown(report)


def test_gate_preserves_report(tmp_path, monkeypatch):
    (tmp_path/'app.ts').write_text('export const answer = 42;')
    monkeypatch.setattr(sys, 'argv', ['reposhield', 'scan', str(tmp_path), '--gate'])
    with pytest.raises(SystemExit) as exc: main()
    assert exc.value.code == 3
    assert 'INCONCLUSIVO' in (tmp_path/'.reposhield/security-review.md').read_text()


@pytest.mark.parametrize('response,status', [
    ({'results': [{}]}, 'passed'),
    ({'results': [{'vulns': [{'id': 'GHSA-test'}]}]}, 'failed'),
    ({'results': []}, 'incomplete'),
    ({'results': [{'error': 'unavailable'}]}, 'incomplete'),
    ({'results': [{'next_page_token': 'more'}]}, 'incomplete'),
    ({'results': [{'vulns': 'invalid'}]}, 'incomplete'),
])
def test_osv_contract(tmp_path, monkeypatch, response, status):
    (tmp_path/'package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {
        '': {'name': 'app'}, 'node_modules/example': {'version': '1.2.3'}}}))
    class Response:
        def __init__(self, data): self.data = data
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return json.dumps(self.data).encode()
    class Opener:
        def open(self, request, timeout):
            if '/v1/vulns/' in request.full_url:
                return Response({'id': 'GHSA-test'})
            assert request.full_url == 'https://api.osv.dev/v1/querybatch'
            assert json.loads(request.data)['queries'][0]['version'] == '1.2.3'
            return Response(response)
    monkeypatch.setattr('urllib.request.build_opener', lambda *args: Opener())
    assert check(tmp_path)['status'] == status


def test_missing_lock_and_network_error_never_pass(tmp_path, monkeypatch):
    assert check(tmp_path)['status'] == 'incomplete'
    (tmp_path/'package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {
        'node_modules/example': {'version': '1.2.3'}}}))
    def fail(*args): raise OSError('offline')
    monkeypatch.setattr('urllib.request.build_opener', fail)
    assert check(tmp_path)['status'] == 'incomplete'


def write_lock(tmp_path, extra=None):
    packages = {'': {'name': 'app'}, 'node_modules/example': {'version': '1.2.3', **(extra or {})}}
    (tmp_path/'package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': packages}))


def fake_osv(monkeypatch, batch, detail=None, detail_error=None):
    class Response:
        def __init__(self, data): self.data = data
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return json.dumps(self.data).encode()
    class Opener:
        def open(self, request, timeout):
            if '/v1/vulns/' in request.full_url:
                if detail_error: raise detail_error
                return Response(detail if detail is not None else {'id': 'GHSA-test'})
            assert request.full_url == 'https://api.osv.dev/v1/querybatch'
            return Response(batch)
    monkeypatch.setattr('urllib.request.build_opener', lambda *args: Opener())


def test_workspace_link_is_skipped_with_warning(tmp_path, monkeypatch):
    (tmp_path/'package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {
        '': {'name': 'app'}, 'node_modules/ui': {'link': True, 'resolved': 'packages/ui'},
        'node_modules/example': {'version': '1.2.3'}}}))
    fake_osv(monkeypatch, {'results': [{}]})
    result = check(tmp_path)
    assert result['status'] == 'passed'
    assert result['skipped_local'] == 1
    assert result['warnings']


def test_dev_flag_sets_reachability(tmp_path, monkeypatch):
    write_lock(tmp_path, {'dev': True})
    fake_osv(monkeypatch, {'results': [{'vulns': [{'id': 'GHSA-test'}]}]})
    assert check(tmp_path)['vulnerabilities'][0]['reachability'] == 'dev_only'


def test_dev_only_high_advisory_does_not_reject():
    report = complete()
    report['dependencies'] = {'status': 'failed', 'vulnerabilities': [
        dict(package='x', version='1.0.0', advisory='GHSA-dev', reachability='dev_only', severity='high')]}
    verdict = evaluate(report)
    assert verdict['status'] == 'passed_scoped'
    assert verdict['warnings']


def test_production_high_advisory_rejects():
    report = complete()
    report['dependencies'] = {'status': 'failed', 'vulnerabilities': [
        dict(package='x', version='1.0.0', advisory='GHSA-prod', reachability='production', severity='high')]}
    assert evaluate(report)['status'] == 'rejected'


def test_detail_failure_is_unknown_and_inconclusive(tmp_path, monkeypatch):
    write_lock(tmp_path)
    fake_osv(monkeypatch, {'results': [{'vulns': [{'id': 'GHSA-test'}]}]}, detail_error=OSError('offline'))
    deps = check(tmp_path)
    assert deps['status'] == 'failed'
    assert deps['vulnerabilities'][0]['severity'] == 'unknown'
    assert deps['warnings']
    report = complete()
    report['dependencies'] = deps
    assert evaluate(report)['status'] == 'inconclusive'


def test_advisory_details_are_extracted(tmp_path, monkeypatch):
    write_lock(tmp_path)
    detail = {'id': 'GHSA-abc', 'summary': 'x' * 250, 'aliases': ['CVE-2026-0001'],
              'database_specific': {'severity': 'MODERATE'},
              'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N'}],
              'affected': [
                  {'package': {'ecosystem': 'npm', 'name': 'example'},
                   'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': '1.2.4'}]}]},
                  {'package': {'ecosystem': 'PyPI', 'name': 'example'},
                   'ranges': [{'type': 'ECOSYSTEM', 'events': [{'fixed': '9.9.9'}]}]}]}
    fake_osv(monkeypatch, {'results': [{'vulns': [{'id': 'GHSA-abc'}]}]}, detail=detail)
    vuln = check(tmp_path)['vulnerabilities'][0]
    assert vuln['severity'] == 'medium'
    assert vuln['fixed_in'] == ['1.2.4']
    assert vuln['aliases'] == ['CVE-2026-0001']
    assert vuln['cvss'] == 'CVSS:3.1/AV:N'
    assert len(vuln['summary']) == 200
    assert vuln['reachability'] == 'production'



def test_gate_http_integration(tmp_path, monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(401)
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
        def log_message(self, *args): pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = {'runtime': {'base_url': f'http://127.0.0.1:{server.server_port}',
                          'cases': [{'path': '/private', 'expected_status': [401]}]}}
    (tmp_path/'app.ts').write_text('export const x = 1;')
    monkeypatch.setattr('reposhield.dependencies.check', lambda root: {
        'status': 'passed', 'packages': 1, 'vulnerabilities': [], 'errors': [], 'scope': 'fixture'})
    monkeypatch.setattr(sys, 'argv', ['reposhield', 'scan', str(tmp_path), '--runtime', '--dependencies', '--gate'])
    try:
        (tmp_path/'.reposhield.json').write_text(json.dumps(config))
        main()
        assert 'APROVADO NO ESCOPO' in (tmp_path/'.reposhield/security-review.md').read_text()
        config['runtime']['cases'][0]['expected_status'] = [200]
        (tmp_path/'.reposhield.json').write_text(json.dumps(config))
        with pytest.raises(SystemExit) as exc: main()
        assert exc.value.code == 1
        assert 'REPROVADO' in (tmp_path/'.reposhield/security-review.md').read_text()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
