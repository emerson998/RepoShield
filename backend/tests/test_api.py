import importlib
from fastapi.testclient import TestClient

def test_api_access_and_scan(tmp_path,monkeypatch):
    monkeypatch.setenv('REPOSHIELD_ROOT',str(tmp_path))
    monkeypatch.setenv('REPOSHIELD_TOKEN','testing-token')
    monkeypatch.setenv('REPOSHIELD_DB',str(tmp_path/'history.db'))
    from reposhield import api
    importlib.reload(api)
    headers={'X-RepoShield-Token':'testing-token'}
    with TestClient(api.app) as c:
        assert c.get('/api/settings').status_code==401
        assert c.get('/api/settings',headers={**headers,'Origin':'https://evil.example'}).status_code==403
        assert c.post('/api/scans',headers=headers,json={'path':'/tmp'}).status_code==400
        assert c.post('/api/scans',headers=headers,json={'path':'.','provider':'codex'}).status_code==422
        (tmp_path/'a.py').write_text('debug=True')
        response=c.post('/api/scans',headers=headers,json={'path':'.'})
        assert response.status_code==202
        import time
        for _ in range(100):
            r=c.get('/api/scans/'+response.json()['id'],headers=headers).json()
            if r['status']!='running': break
            time.sleep(.01)
        assert r['status']=='completed'
        assert r['report']['findings'][0]['rule']=='RS004'
        assert c.get('/api/scans/'+response.json()['id']+'/export?format=sarif',headers=headers).status_code==200
        assert len(c.get('/api/scans',headers=headers).json())==1


def test_api_performance_option_and_persisted_exports(tmp_path, monkeypatch):
    import time
    monkeypatch.setenv('REPOSHIELD_ROOT', str(tmp_path))
    monkeypatch.setenv('REPOSHIELD_TOKEN', 'performance-token')
    monkeypatch.setenv('REPOSHIELD_DB', str(tmp_path / 'history.db'))
    from reposhield import api
    importlib.reload(api)
    headers = {'X-RepoShield-Token': 'performance-token'}
    (tmp_path / 'q.sql').write_text('SELECT * FROM orders;')
    with TestClient(api.app) as client:
        for enabled in (True, False):
            response = client.post('/api/scans', headers=headers, json={'path': '.', 'performance': enabled})
            assert response.status_code == 202
            identifier = response.json()['id']
            for _ in range(100):
                result = client.get('/api/scans/' + identifier, headers=headers).json()
                if result['status'] != 'running': break
                time.sleep(.01)
            assert result['status'] == 'completed'
            perf = result['report']['performance']
            assert perf['enabled'] is enabled
            assert bool(perf['findings']) is enabled
            exported = client.get('/api/scans/' + identifier + '/export?format=json', headers=headers).json()
            assert exported['performance'] == perf
            md = client.get('/api/scans/' + identifier + '/export?format=markdown', headers=headers).text
            assert 'Performance — queries e acesso a dados' in md
