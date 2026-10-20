import json
from reposhield.scanner import scan, sarif

def test_routes_secrets_and_redaction(tmp_path):
    (tmp_path/'app.py').write_text("""
from fastapi import FastAPI, Depends
app=FastAPI()
api_key = "supersecret12345"
@app.get('/health')
def health(): return {}
@app.delete('/admin/users/{user_id}')
def remove(user_id: int): return {}
@app.get('/me')
def me(user=Depends(current_user)): return user
""")
    r=scan(tmp_path)
    assert len(r['endpoints'])==3
    assert not any(f['rule']=='RS100' and '/health' in f['evidence'] for f in r['findings'])
    assert {'RS001','RS100','RS101','RS102'} <= {f['rule'] for f in r['findings']}
    assert 'supersecret12345' not in json.dumps(r)
    assert r['endpoints'][2]['authentication']=='hint_found'
    assert sarif(r)['version']=='2.1.0'

def test_exclusion_and_symlink(tmp_path):
    (tmp_path/'.gitignore').write_text('ignored/\n')
    (tmp_path/'ignored').mkdir()
    (tmp_path/'ignored'/'bad.py').write_text('debug=True')
    (tmp_path/'link.py').symlink_to(tmp_path/'ignored'/'bad.py')
    (tmp_path/'good.py').write_text('debug=False')
    r=scan(tmp_path)
    assert r['coverage']['files']==1
    assert r['findings']==[]

def test_partial_and_invalid_python(tmp_path):
    (tmp_path/'big.py').write_text('x'*300001)
    (tmp_path/'invalid.py').write_text('def !!!')
    r=scan(tmp_path)
    assert r['coverage']['partial']
    assert len(r['errors'])==2

def test_public_configuration(tmp_path):
    (tmp_path/'.reposhield.json').write_text(json.dumps({'public_routes':['/welcome']}))
    (tmp_path/'a.py').write_text('@app.get("/welcome")\ndef home(): return {}')
    assert not scan(tmp_path)['findings']
