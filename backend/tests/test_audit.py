import json
from reposhield.scanner import scan, markdown, sarif

def project(tmp_path,code,name='app.py',config=None):
    (tmp_path/name).write_text(code)
    if config is not None: (tmp_path/'.reposhield.json').write_text(json.dumps(config))
    return scan(tmp_path)

def ids(report):return {f['rule'] for f in report['findings']}

def test_local_router_inheritance_and_prefix(tmp_path):
    r=project(tmp_path,'''from fastapi import FastAPI, APIRouter, Depends
app=FastAPI(dependencies=[Depends(get_current_user)])
router=APIRouter(prefix='/orders')
app.include_router(router,prefix='/v1')
@router.get('/{order_id}')
def get_order(order_id): return {}
''')
    ep=r['endpoints'][0]
    assert ep['path']=='/v1/orders/{order_id}'
    assert ep['authentication']=='hint_found'
    assert 'local_router_or_app' in ep['auth_sources']
    assert 'RS100' not in ids(r)
    assert 'RS102' in ids(r)

def test_generic_dependency_and_auth_comments_do_not_prove_auth(tmp_path):
    r=project(tmp_path,'''@app.get('/private')
def private(db=Depends(get_db)):
    """current_user login_required"""
    # current_user is handled somewhere
    return {}
''')
    assert r['endpoints'][0]['authentication']=='unknown'
    assert 'RS100' in ids(r)

def test_public_login_still_has_abuse_checks(tmp_path):
    r=project(tmp_path,'''@app.post('/login')
def login(): return {}
''',config={'public_routes':['/login']})
    assert 'RS100' not in ids(r)
    assert 'RS222' in ids(r)

def test_cookie_multiline_and_safe_flags(tmp_path):
    r=project(tmp_path,'''response.set_cookie(
  'session', token,
  httponly=False,
  secure=False,
  samesite=None
)
response.set_cookie('safe', token, httponly=True, secure=True, samesite='strict')
''')
    assert {'RS204','RS205','RS206'}<=ids(r)
    assert len([f for f in r['findings'] if f['rule']=='RS204'])==1

def test_security_patterns_and_safe_password(tmp_path):
    r=project(tmp_path,'''import hashlib
hashed = hashlib.md5(password.encode())
new_hash = bcrypt.hashpw(password, salt)
user.password = request.password
jwt.decode(token, key, options={'verify_exp': False})
logger.info(password)
requests.get(request.args.get('url'))
open(request.args.get('path'))
cursor.execute(f'SELECT * FROM users WHERE id={user_id}')
cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))
''')
    assert {'RS200','RS201','RS203','RS210','RS214','RS217','RS218'}<=ids(r)
    assert len([f for f in r['findings'] if f['rule']=='RS200'])==1
    assert len([f for f in r['findings'] if f['rule']=='RS210'])==1

def test_express_route_guards_and_cross_object_review(tmp_path):
    r=project(tmp_path,"router.get('/admin/users/:userId', requireAuth, requireAdmin, handler);",'app.ts')
    assert r['endpoints'][0]['authentication']=='hint_found'
    assert r['endpoints'][0]['authorization']=='hint_found'
    assert 'RS101' not in ids(r)
    assert 'RS102' in ids(r)

def test_openapi_security_inheritance_overrides_and_anonymous_alternative(tmp_path):
    spec={'openapi':'3.0.3','components':{'securitySchemes':{'bearer':{'type':'http','scheme':'bearer'}}},'security':[{'bearer':[]}],
      'paths':{'/private':{'get':{}},'/accident':{'get':{'security':[]}},'/optional':{'get':{'security':[{}, {'bearer':[]}]}},
               '/invalid':{'get':{'security':[{'missing':[]}]}},'/health':{'get':{'security':[]}}}}
    r=project(tmp_path,json.dumps(spec),'openapi.json')
    assert len(r['endpoints'])==5
    assert r['endpoints'][0]['authentication']=='contract_required'
    assert len([f for f in r['findings'] if f['rule']=='RS225'])==2
    assert 'RS226' in ids(r)
    assert len({f['id'] for f in r['findings']})==len(r['findings'])

def test_checklist_does_not_claim_safe_without_findings(tmp_path):
    r=project(tmp_path,'x = 1')
    assert len(r['controls'])==24
    assert all(c['status']=='manual_required' for c in r['controls'])
    assert not r['findings']
    assert 'Checklist' in markdown(r)
    assert len(sarif(r)['runs'][0]['tool']['driver']['rules'])==46

def test_invalid_config_and_malformed_openapi(tmp_path):
    import pytest
    with pytest.raises(ValueError): project(tmp_path,'x=1',config={'exclude':'all'})
    (tmp_path/'.reposhield.json').unlink()
    r=project(tmp_path,json.dumps({'openapi':'3.0.0','paths':None}),'spec.json')
    assert r['coverage']['partial']


def test_config_symlink_rejected(tmp_path):
    import pytest
    (tmp_path/'actual.json').write_text('{}')
    (tmp_path/'.reposhield.json').symlink_to(tmp_path/'actual.json')
    with pytest.raises(ValueError): scan(tmp_path)

