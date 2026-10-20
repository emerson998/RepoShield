"""Opt-in local GET probes with explicit expected access. No redirects or response bodies."""
import http.client
import ipaddress
import os
from urllib.parse import urlsplit

RULES={
 'RS300':('high','Matriz de acesso divergente do esperado','Revise guards, políticas e propriedade do recurso; confirme a expectativa e crie um teste de regressão.'),
 'RS301':('medium','Resposta HTML sem Content-Security-Policy','Defina CSP compatível com os recursos da página.'),
 'RS302':('medium','Resposta sem X-Content-Type-Options nosniff','Envie X-Content-Type-Options: nosniff.'),
 'RS303':('medium','Cookie de resposta sem HttpOnly','Use HttpOnly para cookies de autenticação.'),
 'RS304':('medium','Cookie de resposta sem Secure','Use Secure para cookies de autenticação em produção HTTPS.'),
 'RS305':('medium','Cookie de resposta sem SameSite','Defina SameSite e valide o fluxo CSRF.'),
 'RS306':('medium','CORS aceita origem de teste com credenciais','Use allowlist explícita de origens confiáveis.'),
}
META={key:dict(category='authorization' if key=='RS300' else 'cors' if key=='RS306' else 'headers' if key in {'RS301','RS302'} else 'sessions',
    cwe={'RS300':'CWE-862','RS301':'CWE-693','RS302':'CWE-693','RS303':'CWE-1004','RS304':'CWE-614','RS305':'CWE-1275','RS306':'CWE-942'}[key],validation='Repita com dados sintéticos e confirme a política documentada.') for key in RULES}

def run(config,make):
    settings=config.get('runtime')
    if not isinstance(settings,dict): raise ValueError('Defina runtime.base_url e runtime.cases em .reposhield.json.')
    url=urlsplit(settings.get('base_url',''))
    try: loopback=ipaddress.ip_address(url.hostname or '').is_loopback
    except ValueError: loopback=False
    if url.scheme not in {'http','https'} or not loopback or url.username or url.password or url.path not in {'','/'} or url.query or url.fragment:
        raise ValueError('Runtime aceita apenas origem HTTP(S) com IP literal de loopback e sem credenciais/path.')
    cases=settings.get('cases',[])
    if not isinstance(cases,list) or not 1<=len(cases)<=20: raise ValueError('Runtime exige entre 1 e 20 casos GET explícitos.')
    # Validate the whole plan before any network activity.
    for case in cases:
        if not isinstance(case,dict): raise ValueError('Caso runtime inválido.')
        path=case.get('path',''); expected=case.get('expected_status'); env=case.get('token_env')
        if not isinstance(path,str) or not path.startswith('/') or path.startswith('//') or '\r' in path or '\n' in path or len(path)>2048 or '#' in path:
            raise ValueError('Cada caso deve ter path local absoluto, sem fragmentos.')
        if not isinstance(expected,list) or not expected or not all(type(x) is int and 100<=x<=599 for x in expected): raise ValueError('Defina expected_status para todos os casos.')
        if case.get('method','GET')!='GET': raise ValueError('Runtime suporta somente GET. Não aponte para GETs com efeitos colaterais.')
        if env is not None and (not isinstance(env,str) or not env.startswith('REPOSHIELD_TEST_') or not os.environ.get(env)):
            raise ValueError('Tokens devem vir de variável REPOSHIELD_TEST_* definida no ambiente.')
        if env and any(c in os.environ[env] for c in '\r\n'): raise ValueError('Token contém caracteres inválidos.')
    findings=[];results=[];errors=[]
    for i,case in enumerate(cases):
        headers={'Origin':'https://reposhield-probe.invalid','User-Agent':'RepoShield/0.2 local-authorized-probe','Accept':'application/json,text/html'}
        if case.get('token_env'): headers['Authorization']='Bearer '+os.environ[case['token_env']]
        conn=None
        try:
            cls=http.client.HTTPSConnection if url.scheme=='https' else http.client.HTTPConnection
            conn=cls(url.hostname,url.port,timeout=5)
            conn.request('GET',case['path'],headers=headers)
            response=conn.getresponse()
            # Never follow redirects, parse HTML, save bodies or expose supplied tokens.
            status=response.status
            label='case-'+str(i+1)
            results.append(dict(case=label,path=case['path'],identity='authenticated' if case.get('token_env') else 'anonymous',
                expected=case['expected_status'],actual=status,matched=status in case['expected_status']))
            if status not in case['expected_status']:
                f=make('RS300','.reposhield.json',1,f'{label}: GET {case["path"]} esperado {case["expected_status"]}, recebido {status}','high')
                f['source']='reposhield-runtime';f['status']='expectation_mismatch';findings.append(f)
            checks=[]
            if 'text/html' in response.getheader('Content-Type','').lower() and not response.getheader('Content-Security-Policy'): checks.append(('RS301','Content-Security-Policy ausente'))
            if response.getheader('X-Content-Type-Options','').lower()!='nosniff': checks.append(('RS302','X-Content-Type-Options diferente de nosniff'))
            if response.getheader('Access-Control-Allow-Origin') in {'https://reposhield-probe.invalid','*'} and response.getheader('Access-Control-Allow-Credentials','').lower()=='true': checks.append(('RS306','Origem de teste permitida com credenciais'))
            for cookie in response.headers.get_all('Set-Cookie',[]):
                # Inspect attributes only. Cookie names and values never enter findings.
                attrs={part.strip().split('=',1)[0].lower() for part in cookie.split(';')[1:]}
                for attr,rule in [('httponly','RS303'),('secure','RS304'),('samesite','RS305')]:
                    if attr not in attrs: checks.append((rule,'Set-Cookie: atributo '+attr+' ausente; confirme se autentica a sessão'))
            for rule,evidence in checks:
                f=make(rule,'.reposhield.json',1,f'{label}: {evidence}','medium');f['source']='reposhield-runtime';findings.append(f)
        except (OSError,http.client.HTTPException,ValueError):
            errors.append('runtime case-'+str(i+1)+': conexão indisponível ou resposta inválida')
        finally:
            if conn: conn.close()
    return dict(results=results,findings=findings,errors=errors,scope='Somente GETs explícitos em loopback; sem redirects ou armazenamento de corpo.')
