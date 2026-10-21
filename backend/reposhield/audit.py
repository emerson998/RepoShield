"""Versioned security controls. Indicators are never treated as proof of safety."""
import ast
import json
import re

# id, severity, category, CWE, title, remediation, test recommendation
DEFINITIONS = [
 ('RS200','high','passwords','CWE-916','Hash inadequado para senha','Use Argon2id, scrypt ou bcrypt com custo apropriado; planeje migração dos hashes.','Verifique formato e custo do hash persistido e migração após login.'),
 ('RS201','high','passwords','CWE-256','Possível senha armazenada sem hash','Faça hash no servidor antes de persistir; nunca use criptografia reversível como hash.','Cadastre uma senha sintética e inspecione o armazenamento em ambiente de teste.'),
 ('RS202','high','tokens','CWE-347','JWT com algoritmo none permitido','Defina uma allowlist de algoritmos e exija assinatura.','Token sem assinatura e token com algoritmo inesperado devem ser rejeitados.'),
 ('RS203','medium','tokens','CWE-613','JWT sem expiração ou audience verificadas','Ative validação de expiração e destinatário, conforme o contrato de tokens.','Teste tokens expirados e destinados a outro serviço.'),
 ('RS204','medium','sessions','CWE-1004','Cookie sem HttpOnly explícito','Configure HttpOnly para cookies de sessão e valide o comportamento real.','Inspecione Set-Cookie de login e refresh; JavaScript não deve ler a sessão.'),
 ('RS205','medium','sessions','CWE-614','Cookie sem Secure explícito','Use Secure em produção e HTTPS em toda a sessão.','Verifique Set-Cookie e que o cookie não é enviado por HTTP.'),
 ('RS206','medium','csrf','CWE-352','Cookie sem política SameSite explícita','Configure SameSite e proteção CSRF de acordo com o fluxo.','Tente uma mutação cross-site em staging sem token CSRF.'),
 ('RS207','high','csrf','CWE-352','Proteção CSRF desabilitada explicitamente','Ative CSRF nas operações autenticadas por cookies; documente exceções.','Mutações sem token CSRF válido devem falhar quando cookies autenticam.'),
 ('RS208','medium','cors','CWE-942','CORS com origem irrestrita','Restrinja origens e credenciais conforme os clientes reais.','Teste preflight e requisição com Origin não confiável.'),
 ('RS209','medium','tokens','CWE-922','Token persistido em Web Storage','Avalie cookies HttpOnly ou armazenamento em memória e reduza exposição a XSS.','Inspecione armazenamento do navegador e impacto de execução de script.'),
 ('RS210','high','injection','CWE-89','SQL construído com interpolação','Use parâmetros vinculados, sem concatenar entrada no SQL.','Teste entradas com aspas e confirme uso de bind parameters.'),
 ('RS211','high','injection','CWE-95','Execução dinâmica de código','Substitua eval/exec por parsing estrito e operações permitidas.','Verifique se conteúdo controlado por usuário chega ao interpretador.'),
 ('RS212','high','serialization','CWE-502','Desserialização potencialmente insegura','Use formatos de dados sem execução e validação de schema.','Verifique origem e integridade dos dados desserializados.'),
 ('RS213','medium','xss','CWE-79','Renderização HTML sem escape automático','Evite sinks HTML; sanitize conteúdo com biblioteca apropriada.','Teste conteúdo HTML sintético sem escape no fluxo afetado.'),
 ('RS214','medium','logging','CWE-532','Possível credencial enviada ao log','Remova credenciais e aplique redação estruturada antes do log.','Autentique com credenciais sintéticas e confira todos os destinos de logs.'),
 ('RS215','medium','recovery','CWE-330','Token de segurança gerado com PRNG comum','Use secrets ou crypto.randomBytes para tokens de recuperação e sessão.','Revise gerador, entropia, expiração e uso único dos tokens.'),
 ('RS216','medium','login','CWE-204','Resposta pode enumerar usuários','Retorne mensagens equivalentes em login e recuperação; avalie tempo de resposta.','Compare status, corpo e latência entre contas existentes e inexistentes.'),
 ('RS217','high','ssrf','CWE-918','URL de requisição obtida diretamente da entrada','Valide destino e resoluções DNS; bloqueie redes internas e redirects não aprovados.','Em ambiente isolado, teste destinos não autorizados e redirects.'),
 ('RS218','high','files','CWE-22','Caminho de arquivo obtido diretamente da entrada','Resolva o caminho sob uma raiz permitida e valide extensão, tamanho e autorização.','Teste traversal e acesso cruzado a arquivos com dados sintéticos.'),
 ('RS219','high','authorization','CWE-915','Atualização de entidade com payload inteiro','Use DTOs com allowlist de campos e proteja campos de papel, owner e tenant.','Envie campos extras como role e owner_id; eles devem ser rejeitados.'),
 ('RS220','medium','transport','CWE-319','Redirecionamento HTTPS desativado','Exija HTTPS em produção e configure proxies confiáveis.','Valide HTTP→HTTPS e cabeçalhos de proxy no ambiente final.'),
 ('RS221','medium','headers','CWE-693','Política de segurança de conteúdo desativada','Defina CSP apropriada e valide compatibilidade antes de impor.','Inspecione Content-Security-Policy nas respostas HTML.'),
 ('RS222','medium','rate_limit','CWE-307','Login sem limitação aparente','Aplique limitação por conta e origem sem facilitar negação de serviço.','Teste poucas tentativas sintéticas conforme política aprovada em staging.'),
 ('RS223','medium','recovery','CWE-640','Recuperação de senha exige revisão','Exija expiração, uso único, resposta uniforme e invalidação apropriada.','Reutilização e uso após expiração do token devem falhar.'),
 ('RS224','medium','tokens','CWE-613','Refresh/logout exige revisão de revogação','Implemente rotação, detecção de reutilização e invalidação conforme o modelo de sessão.','Reutilize refresh token antigo após rotação e após logout.'),
 ('RS225','medium','openapi','CWE-306','OpenAPI permite acesso sem credenciais','Revise security herdada e overrides; documente somente operações públicas intencionais.','Faça chamada anônima e confirme a política implementada no servidor.'),
 ('RS226','high','openapi','CWE-287','OpenAPI referencia esquema de segurança inexistente','Defina securitySchemes válidos e revise o contrato de autenticação.','Valide o contrato e gere testes de autenticação do endpoint.'),
]
RULES={x[0]:(x[1],x[4],x[5]) for x in DEFINITIONS}
META={x[0]:dict(category=x[2],cwe=x[3],validation=x[6]) for x in DEFINITIONS}
CATEGORIES = [
 ('login','Login e enumeração','Validar respostas equivalentes, política de tentativas e reautenticação.'),
 ('passwords','Armazenamento de senhas','Verificar hash, custo, política e migração de credenciais.'),
 ('rate_limit','Força bruta e abuso','Testar limites distribuídos por conta, origem e operação.'),
 ('mfa','MFA e recuperação de segundo fator','Verificar desafio, expiração, replay e recuperação sem bypass.'),
 ('recovery','Recuperação de senha','Testar expiração, uso único e ausência de enumeração.'),
 ('tokens','JWT, refresh e logout','Testar assinatura, algoritmo, issuer, audience, expiração e revogação.'),
 ('sessions','Sessões e cookies','Validar flags, rotação, fixação e duração absoluta/ociosa.'),
 ('authentication','Autenticação dos endpoints','Testar acesso anônimo e credenciais inválidas em todas as rotas restritas.'),
 ('authorization','Papéis, objetos e tenants','Testar matriz de papéis e acesso cruzado por objeto/tenant.'),
 ('csrf','CSRF','Testar mutações cross-site nos fluxos autenticados por cookies.'),
 ('cors','CORS','Testar origens permitidas, negadas e requisições com credenciais.'),
 ('injection','SQL e execução de código','Rastrear entradas até sinks e validar parametrização.'),
 ('serialization','Desserialização','Revisar formato, origem e autenticidade das entradas.'),
 ('xss','XSS e saída HTML','Validar escape contextual, sanitização e política CSP.'),
 ('ssrf','Requisições de saída / SSRF','Validar destinos, redirects e resolução DNS.'),
 ('files','Upload e acesso a arquivos','Testar tamanho, tipo real, traversal, armazenamento e propriedade.'),
 ('logging','Logs e dados sensíveis','Verificar redação, auditoria de eventos e acesso aos logs.'),
 ('transport','TLS e transporte','Validar certificados, HTTPS e configuração do proxy.'),
 ('headers','Cabeçalhos de segurança','Inspecionar CSP, HSTS e políticas de conteúdo.'),
 ('secrets','Segredos e configuração','Revisar segredos, rotação e diferenças entre ambientes.'),
 ('openapi','Contrato OpenAPI','Comparar contrato com implementação, autenticação e escopos.'),
 ('dependencies','Dependências e CVEs','Executar auditoria com base de CVEs atualizada e revisar alcance.'),
 ('business','Lógica de negócio','Testar transições, limites, concorrência e operações sensíveis.'),
 ('oauth','OAuth e OIDC','Validar state, nonce, PKCE, redirect URI e vínculo com a conta.'),
]

PATTERNS = [
 ('RS200',r'(?i)(?:md5|sha1|sha256)\s*\([^\n]*(?:password|passwd|senha)'),
 ('RS201',r'(?i)\b(?:user|account|usuario)\.password\s*=\s*(?:request|body|data|payload|form)\.'),
 ('RS202',r"""(?i)algorithms?\s*[:=]\s*\[?\s*["']none["']"""),
 ('RS203',r"""(?i)["'](?:verify_exp|verify_aud)["']\s*:\s*(?:false|False)"""),
 ('RS207',r'(?i)(?:csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False)'),
 ('RS208',r"""(?i)(?:allow_origins|origin|origins|CORS_ALLOW_ALL_ORIGINS)\s*[:=]\s*(?:\[?\s*["']\*["']|True|true)"""),
 ('RS209',r"""(?i)(?:localStorage|sessionStorage)\.setItem\s*\(\s*["'][^"']*(?:token|jwt|session)[^"']*["']"""),
 ('RS210',r"""(?i)\.(?:execute|executemany|raw|query)\s*\(\s*(?:f["']|["'][^\n]*["']\s*(?:%|\+)|`[^`]*\$\{)"""),
 ('RS211',r'\b(?:eval|exec)\s*\('),
 ('RS212',r'\b(?:pickle\.(?:load|loads)|yaml\.unsafe_load)\s*\('),
 ('RS213',r'dangerouslySetInnerHTML|\.innerHTML\s*='),
 ('RS214',r'(?i)(?:logger?\.(?:info|debug|warning|error)|console\.log|print)\s*\([^\n]*(?:password|authorization|access_token|refresh_token)'),
 ('RS215',r'(?i)(?:reset_token|session_token|otp|recovery_token)\s*=\s*(?:random\.|Math\.random)'),
 ('RS216',r"""(?i)["'][^"'\n]*(?:user not found|email not found|usuário não encontrado|email não cadastrado|account does not exist)[^"'\n]*["']"""),
 ('RS217',r'(?i)(?:requests|httpx|axios)\.(?:get|post|request)\s*\(\s*(?:request\.(?:args|query_params)\.get|req\.(?:query|body)\.)'),
 ('RS218',r'\b(?:open|send_file|readFile)\s*\(\s*(?:request\.(?:args|query_params)\.get|req\.(?:query|body)\.)'),
 ('RS219',r'\.update\s*\(\s*(?:\*\*(?:payload|data|body)|req\.body)'),
 ('RS220',r'\bSECURE_SSL_REDIRECT\s*=\s*False'),
 ('RS221',r'\bcontentSecurityPolicy\s*:\s*false'),
]

INDICATORS = {
 'login':r'(?i)\b(?:login|signin|sign_in|authenticate)\b',
 'passwords':r'(?i)\b(?:argon2|bcrypt|scrypt|pbkdf2|password_hash|hash_password)\b',
 'rate_limit':r'(?i)\b(?:ratelimit|rate_limit|rateLimit|throttle|limiter)\b',
 'mfa':r'(?i)\b(?:totp|webauthn|pyotp|two_factor|mfa)\b',
 'recovery':r'(?i)(?:reset.password|forgot.password|recovery.token)',
 'tokens':r'(?i)\b(?:jwt|refresh_token|verify_token)\b',
 'sessions':r'(?i)(?:set_cookie|httpOnly|SESSION_COOKIE|express.session)',
 'csrf':r'(?i)\b(?:csrf|CSRFProtect|csurf|csrf_token)\b',
 'cors':r'(?i)(?:CORSMiddleware|\bcors\b|allow_origins)',
 'headers':r'(?i)(?:helmet|Content-Security-Policy|Strict-Transport-Security)',
 'oauth':r'(?i)\b(?:oauth|oidc|pkce|openid)\b',
 'dependencies':r'(?i)(?:pip-audit|npm audit|osv-scanner)',
}

def analyze_file(text, rel, make):
    findings=[]
    is_code=rel.endswith(('.py','.js','.jsx','.ts','.tsx'))
    if rel.endswith(('.js','.jsx','.ts','.tsx')):
        from .storage import analyze
        findings.extend(analyze(text, rel, make))
    if is_code:
        for n,line in enumerate(text.splitlines(),1):
            if line.lstrip().startswith(('#','//','*')): continue
            for rule,pattern in PATTERNS:
                if rule == 'RS209': continue
                if re.search(pattern,line): findings.append(make(rule,rel,n,line.strip()))
        if rel.endswith('.py'):
            try: tree=ast.parse(text)
            except SyntaxError: tree=None
            if tree:
                for node in ast.walk(tree):
                    if not isinstance(node,ast.Call) or not isinstance(node.func,ast.Attribute) or node.func.attr!='set_cookie': continue
                    flags={k.arg:k.value for k in node.keywords}
                    # Star kwargs can supply flags; do not infer absence in that case.
                    if None in flags: continue
                    for flag,rule in [('httponly','RS204'),('secure','RS205'),('samesite','RS206')]:
                        value=flags.get(flag)
                        unsafe = flag not in flags or (isinstance(value,ast.Constant) and (value.value is False or value.value is None))
                        if unsafe:
                            findings.append(make(rule,rel,node.lineno,'set_cookie(...): '+flag+' ausente/desabilitado','low'))
    evidence={}
    for category,pattern in INDICATORS.items():
        hits=[]
        for n,line in enumerate(text.splitlines(),1):
            if line.lstrip().startswith(('#','//','*')): continue
            if re.search(pattern,line): hits.append({'file':rel,'line':n})
            if len(hits)>=3: break
        if hits: evidence[category]=hits
    return findings,evidence

def endpoint_findings(endpoint, source, make):
    """Route-specific follow-ups, including intentional public login endpoints."""
    route=endpoint['path']; rel=endpoint['file']; line=endpoint['line']
    out=[]
    if re.search(r'(?i)(?:login|sign[-_]?in|token)(?:/|$)',route) and any(m in {'POST','PUT'} for m in endpoint['methods']):
        if not re.search(INDICATORS['rate_limit'],source): out.append(make('RS222',rel,line,route,'low'))
    if re.search(r'(?i)(?:forgot|reset[-_/]?password|password[-_/]?reset|recover)',route):
        out.append(make('RS223',rel,line,route,'low'))
    if re.search(r'(?i)(?:refresh|logout|sign[-_]?out)(?:/|$)',route):
        out.append(make('RS224',rel,line,route,'low'))
    return out

def openapi_routes(text,rel,public,make):
    """Local OpenAPI 3 JSON only; never fetch or resolve remote $refs."""
    if not rel.endswith('.json'): return [],[],[]
    try: doc=json.loads(text)
    except ValueError: return [],[],[]
    if not isinstance(doc,dict) or not str(doc.get('openapi','')).startswith('3.'): return [],[],[]
    routes=[];findings=[];errors=[]
    schemes=doc.get('components',{}).get('securitySchemes',{})
    for path,item in doc.get('paths',{}).items():
        if not isinstance(item,dict): continue
        if '$ref' in item: errors.append(f'{rel}: referência de path não resolvida: {path}'); continue
        for method,operation in item.items():
            if method not in {'get','post','put','patch','delete','head','options','trace'} or not isinstance(operation,dict): continue
            security=operation.get('security',doc.get('security',[]))
            anonymous=not security or any(isinstance(req,dict) and not req for req in security)
            invalid=any(k not in schemes for req in security if isinstance(req,dict) for k in req)
            ep=dict(file=rel,line=1,path=path,methods=[method.upper()],framework='openapi3',
                authentication='public_declared' if path in public else 'anonymous_allowed' if anonymous else 'invalid_scheme' if invalid else 'contract_required',
                authorization='unknown',caveat='Contrato declarativo; implementação e escopos precisam de teste.')
            routes.append(ep)
            if anonymous and path not in public: findings.append(make('RS225',rel,1,method.upper()+' '+path,'high'))
            if invalid: findings.append(make('RS226',rel,1,method.upper()+' '+path,'high'))
            findings+=endpoint_findings(ep,'',make)
    return routes,findings,errors

def controls(findings, indicators, endpoints):
    counts={}
    for f in findings: counts[f['category']]=counts.get(f['category'],0)+1
    rows=[]
    for category,title,validation in CATEGORIES:
        refs=indicators.get(category,[])[:12]
        if category=='authentication': refs += [{'file':e['file'],'line':e['line']} for e in endpoints[:12]]
        rows.append(dict(id=category,title=title,status='findings' if counts.get(category) else 'indicator_only' if refs else 'manual_required',
            findings=counts.get(category,0),evidence=refs,validation=validation,
            assurance='Não validado em runtime. Nenhum estado significa aprovado.'))
    return rows

