import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import pytest
from reposhield.scanner import scan

@pytest.fixture
def server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path=='/redirect':
                self.send_response(302);self.send_header('Location','http://example.com');self.end_headers();return
            if self.path=='/auth' and self.headers.get('Authorization')!='Bearer synthetic-test-token':
                self.send_response(401);self.end_headers();return
            self.send_response(200)
            self.send_header('Content-Type','text/html')
            self.send_header('Set-Cookie','session=secret-never-save')
            self.end_headers()
            self.wfile.write(b'sensitive body never save')
        def log_message(self,*args):pass
    s=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    t=Thread(target=s.serve_forever,daemon=True);t.start()
    yield f'http://127.0.0.1:{s.server_port}'
    s.shutdown();s.server_close()

def test_runtime_requires_opt_in_and_checks_expectations(tmp_path,server):
    config={'runtime':{'base_url':server,'cases':[{'path':'/private','expected_status':[401,403]}]}}
    (tmp_path/'.reposhield.json').write_text(json.dumps(config))
    assert scan(tmp_path)['runtime'] is None
    r=scan(tmp_path,runtime_enabled=True)
    assert r['runtime']['results'][0]['actual']==200
    assert not r['runtime']['results'][0]['matched']
    assert {'RS300','RS301','RS302','RS303','RS304','RS305'}<={f['rule'] for f in r['findings']}
    assert 'secret-never-save' not in json.dumps(r)
    assert 'sensitive body never save' not in json.dumps(r)

def test_runtime_does_not_follow_redirect(tmp_path,server):
    (tmp_path/'.reposhield.json').write_text(json.dumps({'runtime':{'base_url':server,'cases':[{'path':'/redirect','expected_status':[302]}]}}))
    assert scan(tmp_path,runtime_enabled=True)['runtime']['results'][0]['actual']==302

@pytest.mark.parametrize('url',['http://example.com','http://169.254.169.254','http://127.0.0.1@evil.test','file:///etc/passwd'])
def test_runtime_rejects_nonloopback_before_network(tmp_path,url):
    (tmp_path/'.reposhield.json').write_text(json.dumps({'runtime':{'base_url':url,'cases':[{'path':'/','expected_status':[200]}]}}))
    with pytest.raises(ValueError):scan(tmp_path,runtime_enabled=True)

def test_runtime_validates_whole_plan_and_requires_token_env(tmp_path,server):
    (tmp_path/'.reposhield.json').write_text(json.dumps({'runtime':{'base_url':server,'cases':[
      {'path':'/','expected_status':[200]}, {'path':'/private','expected_status':[200],'token_env':'HOME'}]}}))
    with pytest.raises(ValueError):scan(tmp_path,runtime_enabled=True)


def test_authenticated_matrix_and_no_token_persistence(tmp_path,server,monkeypatch):
    monkeypatch.setenv('REPOSHIELD_TEST_USER','synthetic-test-token')
    (tmp_path/'.reposhield.json').write_text(json.dumps({'runtime':{'base_url':server,'cases':[
        {'path':'/auth','expected_status':[401]},
        {'path':'/auth','expected_status':[200],'token_env':'REPOSHIELD_TEST_USER'}]}}))
    r=scan(tmp_path,runtime_enabled=True)
    assert all(x['matched'] for x in r['runtime']['results'])
    assert 'synthetic-test-token' not in json.dumps(r)
    assert not any(f['rule']=='RS300' for f in r['findings'])
