"""Conservative C#/.NET patterns. No compilation, Roslyn or external tools."""
import hashlib
import re
from .syntax import clean, closing, placeholder

DEFINITIONS = [
    ('RS400', 'medium', 'cors', 'CWE-942', 'CORS .NET permite qualquer origem', 'Restrinja origens conforme os clientes reais e teste a política efetivamente aplicada.'),
    ('RS401', 'high', 'tokens', 'CWE-347', 'Validação de token .NET desabilitada', 'Revise TokenValidationParameters e habilite validação de assinatura, issuer, audience e lifetime.'),
    ('RS402', 'high', 'transport', 'CWE-295', 'Bypass de certificado TLS em .NET', 'Remova callbacks que aceitam qualquer certificado e configure uma CA confiável.'),
    ('RS403', 'high', 'secrets', 'CWE-798', 'Possível segredo em configuração .NET', 'Retire o segredo do repositório, avalie revogação e use configuração segura por ambiente.'),
]
RULES = {r[0]: (r[1], r[4], r[5]) for r in DEFINITIONS}
META = {r[0]: dict(category=r[2], cwe=r[3], validation='Confirme ambiente, política e fluxo efetivo; padrões estáticos não comprovam explorabilidade.') for r in DEFINITIONS}


def analyze(text, rel, public, make):
    from .routes import check
    source, mask = clean(text), clean(text, strings=True)
    findings, endpoints = [], []
    patterns = [
        ('RS400', r'\bAllowAnyOrigin\s*\('),
        ('RS400', r'\bSetIsOriginAllowed\s*\(\s*\w+\s*=>\s*true\s*\)'),
        ('RS401', r'\b(?:ValidateIssuerSigningKey|ValidateIssuer|ValidateAudience|ValidateLifetime|RequireSignedTokens|RequireExpirationTime)\s*=\s*false\b'),
        ('RS402', r'\bDangerousAcceptAnyServerCertificateValidator\b'),
        ('RS402', r'\b(?:ServerCertificateCustomValidationCallback|ServerCertificateValidationCallback)\s*=\s*\([^)]*\)\s*=>\s*true\b'),
    ]
    for rule, pattern in patterns:
        for match in re.finditer(pattern, mask):
            findings.append(make(rule, rel, text[:match.start()].count('\n')+1, source[match.start():match.end()]))

    # Scope class attributes and methods with balanced braces. Do not borrow a
    # sibling action's attributes or global middleware as proof of protection.
    for scope in _scopes(source, mask):
        body_start = scope['cls'].end()
        body = source[body_start:scope['end']]
        attrs = scope['attrs']
        method_pattern = r'((?:\s*\[[^\n]*?\]\s*)+)public\s+(?:[\w<>?,.\[\]]+\s+)+(\w+)\s*\('
        for method in re.finditer(method_pattern, body):
            absolute = body_start+method.start()+len(method[0])-len(method[0].lstrip())
            # String contents can contain fake declarations.
            public_at = source.find('public', absolute, body_start+method.end())
            if public_at < 0 or mask[public_at:public_at+6] != 'public': continue
            mattrs = method[1]
            verbs = list(re.finditer(r'\[Http(Get|Post|Put|Patch|Delete|Head|Options)(?:\s*\(\s*"([^"]*)"[^)]*\))?\s*\]', mattrs))
            for verb in verbs:
                route = re.search(r'\[Route\s*\(\s*"([^"]*)"\s*\)\]', attrs)
                base = route[1] if route else ''
                action_route = re.search(r'\[Route\s*\(\s*"([^"]*)"\s*\)\]', mattrs)
                suffix = verb[2] if verb[2] is not None else action_route[1] if action_route else ''
                path = suffix[1:] if suffix.startswith('~/') else suffix if suffix.startswith('/') else '/'.join([base.rstrip('/'), suffix.lstrip('/')])
                path = '/'+path.lstrip('/')
                path = path.replace('[controller]', re.sub(r'Controller$', '', scope['name'])).replace('[action]', method[2])
                combined = attrs+' '+mattrs
                anonymous = bool(re.search(r'\[AllowAnonymous(?:Attribute)?\b', combined))
                authorized = bool(re.search(r'\[Authorize(?:Attribute)?\b', combined))
                policy = authorized and bool(re.search(r'\b(?:Roles|Policy)\s*=', combined))
                ep = endpoint(rel, text[:absolute].count('\n')+1, path, verb[1].upper(), anonymous, authorized, policy, public)
                ep.update(class_name=scope['name'], base_class=scope['base'])
                endpoints.append(ep); findings.extend(check(ep, combined, make))
    # Minimal APIs: a local fluent call only; MapGroup inheritance is unresolved.
    for match in re.finditer(r'\b(\w+)\.Map(Get|Post|Put|Patch|Delete|Head|Options)\s*\(', mask):
        end = closing(mask, match.end()-1)
        if end is None: continue
        route = re.match(r'\s*"([^"]*)"', source[match.end():end])
        if not route: continue
        stop = mask.find(';', end)
        tail = mask[end:stop if stop >= 0 else end]
        anonymous = bool(re.search(r'\.AllowAnonymous\s*\(', tail))
        authorized = bool(re.search(r'\.RequireAuthorization\s*\(', tail))
        ep = endpoint(rel, text[:match.start()].count('\n')+1, route[1], match[2].upper(), anonymous, authorized, False, public)
        ep['route_resolution'] = 'local_literal_only'
        endpoints.append(ep); findings.extend(check(ep, tail, make))
    return endpoints, findings


def endpoint(rel, line, path, method, anonymous, authorized, policy, public):
    return dict(file=rel, line=line, path=path, methods=[method], framework='aspnet-pattern',
                authentication='public_declared' if anonymous or path in public else 'hint_found' if authorized else 'unknown',
                authorization='hint_found' if policy and not anonymous else 'unknown',
                auth_sources=['local_attribute_or_fluent'] if authorized and not anonymous else [],
                caveat='Heurística C#: FallbackPolicy com RequireAuthenticatedUser e [Authorize] herdado de classe base (por nome, no projeto) são resolvidos; não resolve filtros globais, MapGroup, extensões, preprocessor ou semântica de policies. Rotas convencionais podem não ser inventariadas.')


FALLBACK = re.compile(r'FallbackPolicy\s*=|\.SetFallbackPolicy\s*\(')
REQUIRE_AUTH = re.compile(r'RequireAuthenticatedUser\s*\(')


def fallback_policy(text):
    # Returns the 1-based line of a FallbackPolicy that requires an authenticated user, else None.
    masked = clean(text, strings=True)
    for start in FALLBACK.finditer(masked):
        if REQUIRE_AUTH.search(masked, start.end(), start.end()+400):
            return text[:start.start()].count('\n')+1
    return None


def config_secrets(text, rel, make):
    # Never put raw values or connection strings in evidence.
    source = clean(text)
    patterns = [r'(?i)"(?:Password|ClientSecret|SecretKey|SigningKey|JwtKey|ApiKey)"\s*:\s*"([^"\n]+)"',
                r'(?i)\b(?:Password|Pwd)\s*=\s*([^;"\n]+)']
    findings = []
    for pattern in patterns:
        for match in re.finditer(pattern, source):
            value = match[1].strip()
            if placeholder(value): continue
            finding = make('RS403', rel, text[:match.start()].count('\n')+1,
                           'Configuração de credencial literal: [REDACTED]')
            finding['_value_sha'] = value_digest(value)  # temporary; removed by scanner
            findings.append(finding)
    return findings


def value_digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


# Only environment checks count as a guard. A bare throw is fixed-key authentication, not an environment gate.
GUARD_TRIGGER = re.compile(r'IsDevelopment\s*\(|IsProduction\s*\(|IsEnvironment\s*\(|IsStaging\s*\(|EnvironmentName')


def _compared(source, start, end):
    # The literal is an operand of ==/!= or an argument of Equals(...) in the same call.
    before, after = source[max(0, start-10):start], source[end:end+10]
    return bool(re.search(r'(?:==|!=)\s*$', before) or re.match(r'\s*(?:==|!=)', after)
                or re.search(r'Equals\s*\([^)]*$', source[max(0, start-300):start]))


def guard_hashes(text, rel=''):
    # Digests only, paired with the .cs path: comparison literals within 400 characters of an environment check.
    source = clean(text)
    triggers = [m.start() for m in GUARD_TRIGGER.finditer(source)]
    if not triggers: return set()
    return {(value_digest(m[1].strip()), rel) for m in re.finditer(r'"([^"\\\n]{8,200})"', source)
            if any(abs(m.start()-t) <= 400 for t in triggers) and _compared(source, m.start(), m.end())}


def _scopes(source, mask):
    # Class declarations with balanced bodies. attrs are the text between the previous
    # statement/brace and the class keyword, so a sibling's attributes are never borrowed.
    scopes = []
    for cls in re.finditer(r'\bclass\s+(\w+)[^{;]*\{', mask):
        end = closing(mask, cls.end()-1, '{', '}')
        if end is None: continue
        prefix_start = max(mask.rfind('}', 0, cls.start()), mask.rfind(';', 0, cls.start()), mask.rfind('{', 0, cls.start()))+1
        header = mask[cls.end(1):cls.end()-1]
        base = re.match(r'\s*(?:<[^>]*>)?\s*:\s*([A-Za-z_][\w.]*)', header)
        attrs = source[prefix_start:cls.start()]
        scopes.append(dict(cls=cls, name=cls[1], end=end, attrs=attrs,
                           base=base[1].rpartition('.')[2] if base else None,
                           authorized=bool(re.search(r'\[Authorize(?:Attribute)?\b', attrs)),
                           anonymous=bool(re.search(r'\[AllowAnonymous(?:Attribute)?\b', attrs))))
    return scopes


def classes(text):
    source, mask = clean(text), clean(text, strings=True)
    return [dict(name=s['name'], base=s['base'], authorized=s['authorized'], anonymous=s['anonymous'])
            for s in _scopes(source, mask)]


def resolve_project(endpoints, findings, fallbacks, classes):
    """Project-wide .NET auth resolution, applied after all files are read.

    Inherited [Authorize] (by class name, up to 10 base levels) takes precedence over
    FallbackPolicy. Neither applies if any class in the chain is [AllowAnonymous].
    """
    from .routes import OBJECT_ID
    declared = {}
    for decl in classes:
        declared.setdefault(decl['name'], []).append(decl)

    def authorizer(start):
        # Nearest protected class in the chain; None when the chain is unknown or anonymous.
        seen, current, found = set(), start, None
        for _ in range(10):
            if current is None or current in seen or current not in declared: break
            seen.add(current)
            decls = declared[current]
            if any(d['anonymous'] for d in decls): return None
            if found is None and all(d['authorized'] for d in decls): found = current
            bases = {d['base'] for d in decls}
            current = bases.pop() if len(bases) == 1 else None
        return found

    resolved = set()
    for ep in endpoints:
        if ep['framework'] != 'aspnet-pattern' or ep['authentication'] != 'unknown': continue
        owner = authorizer(ep.get('class_name'))
        if owner is not None:
            ep['authentication'] = 'hint_found'
            ep['auth_sources'].append(f'inherited_authorize:{owner}')
            if re.search(OBJECT_ID, ep['path']): ep['object_authorization'] = 'manual_review'
            resolved.add((ep['file'], ep['line']))
            continue
        # A FallbackPolicy with RequireAuthenticatedUser covers .NET endpoints without a local
        # attribute, scoped to the declaring file's directory so one app in a monorepo cannot vouch for another.
        cover = next(((r, n) for r, n in fallbacks if ep['file'].startswith(r.rpartition('/')[0]+'/' if '/' in r else '')), None)
        if cover is None: continue
        ep['authentication'] = 'hint_found'
        ep['auth_sources'].append(f'fallback_policy:{cover[0]}:{cover[1]}')
        if re.search(OBJECT_ID, ep['path']): ep['object_authorization'] = 'manual_review'
        resolved.add((ep['file'], ep['line']))
    return [f for f in findings if not (f['rule'] in {'RS100', 'RS102'} and (f['file'], f['line']) in resolved)]
