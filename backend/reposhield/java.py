"""Heurísticas Java/Spring: anotações locais, DSL do Spring Security e XML legado. Sem compilação nem execução."""
import re
from .syntax import clean, closing, blank, placeholder
from .routes import check, OBJECT_ID

DEFINITIONS = [
    ('RS500', 'medium', 'csrf', 'CWE-352', 'CSRF desabilitado no Spring Security', 'Mantenha CSRF para sessões com cookie; desabilite só em APIs stateless com token no header, documentando o motivo.'),
    ('RS501', 'medium', 'cors', 'CWE-942', 'CORS Spring permite qualquer origem', 'Restrinja origens aos clientes reais.'),
    ('RS502', 'high', 'secrets', 'CWE-798', 'Possível segredo em configuração Spring', 'Retire o segredo do repositório, avalie revogação e use variáveis de ambiente/cofre.'),
    ('RS503', 'high', 'authorization', 'CWE-284', 'Regra de segurança libera todas as requisições', 'Troque anyRequest().permitAll() por authenticated() e libere só rotas públicas explícitas.'),
]
RULES = {r[0]: (r[1], r[4], r[5]) for r in DEFINITIONS}
META = {r[0]: dict(category=r[2], cwe=r[3], validation='Confirme ambiente, política e fluxo efetivo; padrões estáticos não comprovam explorabilidade.') for r in DEFINITIONS}

PATTERNS = [
    ('RS500', r'\.csrf\s*\(\s*\)\s*\.disable\s*\('),
    ('RS500', r'\.csrf\s*\(\s*(?:AbstractHttpConfigurer::disable|\w+\s*->\s*\w+\.disable\s*\(\s*\))'),
    # Bare @CrossOrigin also allows every origin (default is "*").
    ('RS501', r'@CrossOrigin\b(?:\s*\(\s*\)|\s*\([^)]*origins\s*=\s*\{?\s*"\*"|(?!\s*\())'),
    ('RS501', r'\ballowedOrigins\s*\(\s*"\*"'),
    ('RS501', r'\baddAllowedOrigin\s*\(\s*"\*"'),
    ('RS501', r'\ballowedOriginPatterns\s*\(\s*"\*"'),
    ('RS503', r'\banyRequest\s*\(\s*\)\s*\.permitAll\s*\('),
]
ANN = re.compile(r'@(\w+)(?:\s*\(((?:[^()]|\([^()]*\))*)\))?')
MAPPINGS = {'GetMapping': 'GET', 'PostMapping': 'POST', 'PutMapping': 'PUT', 'PatchMapping': 'PATCH', 'DeleteMapping': 'DELETE'}
AUTHZ = {'PreAuthorize', 'Secured', 'RolesAllowed'}
CONFIG_KEY = re.compile(r'(?i)^(?:password|secret|client-secret|clientsecret|api-key|apikey|signing-key|private-key)$')
MATCHER = re.compile(r'\b(?:requestMatchers|antMatchers|mvcMatchers)\s*\(')
MATCHER_TAIL = re.compile(r'\s*\.\s*(permitAll|authenticated|fullyAuthenticated|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|denyAll|access)\s*\(')
ANY_AUTH = re.compile(r'\banyRequest\s*\(\s*\)\s*\.\s*(?:authenticated|fullyAuthenticated|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority)\s*\(')


def analyze(text, rel, public, make):
    source, mask = clean(text), clean(text, strings=True)
    findings, endpoints = [], []
    for rule, pattern in PATTERNS:
        for match in re.finditer(pattern, source):
            # Matches that start inside a string or comment are not code.
            if mask[match.start()].isspace(): continue
            findings.append(make(rule, rel, text[:match.start()].count('\n')+1, source[match.start():match.end()]))

    # Only classes annotated as controllers are inventoried; each member is scoped by balanced braces.
    for cls in re.finditer(r'\bclass\s+(\w+)[^{;]*\{', mask):
        end = closing(mask, cls.end()-1, '{', '}')
        if end is None: continue
        prefix_start = max(mask.rfind('}', 0, cls.start()), mask.rfind(';', 0, cls.start()), mask.rfind('{', 0, cls.start()))+1
        class_anns = annotations(source, mask, prefix_start, cls.start())
        if not any(name in {'RestController', 'Controller'} for name, _, _ in class_anns): continue
        base = next((mapping_path(args) for name, args, _ in class_anns if name == 'RequestMapping'), '')
        class_header = source[prefix_start:cls.end()]
        for start, brace in members(mask, cls.end(), end):
            header_mask = ANN.sub(lambda m: ' '*len(m[0]), mask[start:brace])
            method = re.search(r'(\w+)\s*\(', header_mask)
            if not method: continue
            method_anns = annotations(source, mask, start, brace)
            verbs = []
            for name, args, pos in method_anns:
                if name in MAPPINGS: verbs.append((MAPPINGS[name], args, pos))
                elif name == 'RequestMapping':
                    found = re.findall(r'RequestMethod\.(\w+)', args) or ['ANY']
                    verbs.extend((verb.upper(), args, pos) for verb in found)
            security = class_anns+method_anns
            anonymous = any(name == 'PermitAll' or (name == 'PreAuthorize' and 'permitAll()' in args) for name, args, _ in security)
            authorized = any(name in AUTHZ for name, _, _ in security)
            combined = class_header+' '+source[start:brace]
            for verb, args, pos in verbs:
                path = join_path(base, mapping_path(args))
                ep = endpoint(rel, source[:pos].count('\n')+1, path, verb, anonymous, authorized, authorized, public)
                endpoints.append(ep); findings.extend(check(ep, combined, make))
    return endpoints, findings


def annotations(source, mask, start, end):
    # Annotations found in code only: a '@' inside a string or comment is blanked in the mask.
    return [(m[1], m[2] or '', m.start()) for m in ANN.finditer(source, start, end) if mask[m.start()] == '@']


def members(mask, start, end):
    # Yields (header_start, body_open) for direct members of a class body; skips over nested bodies.
    i = start
    while i < end:
        found = re.compile(r'[{;]').search(mask, i, end)
        if not found: break
        if mask[found.start()] == ';':
            i = found.end(); continue
        close = closing(mask, found.start(), '{', '}')
        if close is None: break
        yield i, found.start()
        i = close+1


def mapping_path(args):
    # Accepts value=, path= or the positional literal; other attributes such as produces= are ignored.
    named = re.search(r'\b(?:value|path)\s*=\s*\{?\s*"([^"]*)"', args)
    if named: return named[1]
    positional = re.match(r'\s*\{?\s*"([^"]*)"', args)
    return positional[1] if positional else ''


def join_path(base, suffix):
    parts = [part.strip('/') for part in (base, suffix)]
    return '/'+'/'.join(part for part in parts if part)


def endpoint(rel, line, path, method, anonymous, authorized, policy, public):
    return dict(file=rel, line=line, path=path, methods=[method], framework='spring-pattern',
                authentication='public_declared' if anonymous or path in public else 'hint_found' if authorized else 'unknown',
                authorization='hint_found' if policy and not anonymous else 'unknown',
                auth_sources=['local_annotation'] if authorized and not anonymous else [],
                caveat='Heurística Java/Spring: anotações locais e DSL simples; não resolve SecurityFilterChain complexo, herança, meta-anotações nem expressões SpEL. Rotas convencionais podem não ser inventariadas.')


def security_config(text, rel):
    # Returns the DSL or XML rules of one file, in declaration order (Spring uses the first match).
    result = dict(authenticated_default=None, public=[], protected=[], rules=[])
    if rel.lower().endswith('.xml'): return xml_security(text, result)
    source, mask = clean(text), clean(text, strings=True)
    events = []
    # securityMatcher limits a chain to some paths, so its anyRequest() is not a global default.
    chained = re.search(r'securityMatcher\s*\(', text) is not None
    for match in ANY_AUTH.finditer(source):
        if chained or mask[match.start()].isspace(): continue
        if result['authenticated_default'] is None: result['authenticated_default'] = text[:match.start()].count('\n')+1
    for match in MATCHER.finditer(mask):
        open_at = match.end()-1
        close = closing(mask, open_at)
        if close is None: continue
        tail = MATCHER_TAIL.match(source, close+1)
        if not tail: continue
        access = tail[1]
        kind = 'public' if access == 'permitAll' else 'protected'
        # requestMatchers(HttpMethod.GET, "/x"): the rule only covers that verb.
        verb = re.match(r'\s*HttpMethod\.(\w+)\s*,', source[open_at+1:close])
        method = verb[1].upper() if verb else None
        for pattern in re.findall(r'"([^"]*)"', source[open_at:close+1]):
            events.append((match.start(), pattern, kind, access, method))
    # Events are appended in source order, so literals of one matcher keep their declared order.
    for _, pattern, kind, access, method in events:
        result['rules'].append((pattern, kind, method))
        if kind == 'public': result['public'].append(pattern)
        else: result['protected'].append((pattern, access))
    return result


def xml_security(text, result):
    text = re.sub(r'<!--.*?-->', lambda m: blank(m[0]), text, flags=re.S)
    for match in re.finditer(r'<intercept-url\b([^>]*)>', text):
        attrs = match[1]
        pattern, access = xml_attr(attrs, 'pattern'), xml_attr(attrs, 'access')
        if pattern is None or access is None: continue
        public = 'permitAll' in access or 'IS_AUTHENTICATED_ANONYMOUSLY' in access
        if pattern == '/**' and not public and result['authenticated_default'] is None:
            result['authenticated_default'] = text[:match.start()].count('\n')+1
        if public:
            result['public'].append(pattern); result['rules'].append((pattern, 'public', None))
        else:
            result['protected'].append((pattern, access)); result['rules'].append((pattern, 'protected', None))
    return result


def xml_attr(attrs, name):
    # Each attribute is read separately, so their order in the tag does not matter.
    found = re.search(r'(?<![\w-])%s\s*=\s*(?:"([^"]*)"|\'([^\']*)\')' % name, attrs)
    return (found[1] if found[1] is not None else found[2]) if found else None


def config_secrets(text, rel, make):
    # Never put raw values in evidence. Placeholders such as ${VAR:default} are not literals.
    name = rel.replace('\\', '/').split('/')[-1].lower()
    if not name.startswith('application') or not name.endswith(('.properties', '.yml', '.yaml')): return []
    properties = name.endswith('.properties')
    findings = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if properties:
            if not line or line[0] in '#!': continue
            found = re.match(r'([^=:\s]+)\s*[=:\s]\s*(.*)$', line)
        else:
            line = re.sub(r'^-\s+', '', line)
            if not line or line[0] == '#': continue
            found = re.match(r'([\w.\-]+)\s*:\s*(.*)$', line)
        if not found or not CONFIG_KEY.match(found[1].split('.')[-1]): continue
        value = found[2].strip()
        if not value or value[0] in '|>': continue
        if value[0] in '\'"':
            end = value.find(value[0], 1)
            value = value[1:end] if end > 0 else value[1:]
        elif not properties:
            value = re.split(r'\s+#', value)[0].strip()
        if '${' in value or placeholder(value): continue
        findings.append(make('RS502', rel, number, 'Configuração de credencial literal: [REDACTED]'))
    return findings


def scope(rel):
    # Module root: the prefix before /src/, so a config in java/config covers controllers in java/api.
    norm = '/'+rel.replace('\\', '/').lstrip('/')
    if '/src/' in norm: return norm.split('/src/')[0].strip('/')
    return norm.rsplit('/', 1)[0].strip('/')


def within(path_scope, config_scope):
    return config_scope == '' or path_scope == config_scope or path_scope.startswith(config_scope+'/')


def ant_regex(pattern):
    # Ant style: ** crosses '/', * does not; {x} stays literal, as written in the pattern.
    body_pattern = pattern[:-3] if pattern.endswith('/**') else pattern
    body = []
    i = 0
    while i < len(body_pattern):
        if body_pattern.startswith('**', i):
            body.append('.*'); i += 2
        elif body_pattern[i] == '*':
            body.append('[^/]*'); i += 1
        else:
            body.append(re.escape(body_pattern[i])); i += 1
    tail = '(?:/.*)?' if pattern.endswith('/**') else ''
    return re.compile('^'+''.join(body)+tail+'$')


def resolve_project(endpoints, findings, configs):
    # configs: [(rel, security_config dict)]. The first matching rule wins, as in Spring.
    dropped = set()
    # Test sources are not the application's security configuration.
    configs = [(rel, cfg) for rel, cfg in configs if '/src/test/' not in '/'+rel.replace('\\', '/').lstrip('/')]
    for ep in endpoints:
        if ep['framework'] != 'spring-pattern' or ep['authentication'] != 'unknown': continue
        applicable = [(rel, cfg) for rel, cfg in configs if within(scope(ep['file']), scope(rel))]
        verdict, source = None, None
        for rel, cfg in applicable:
            for pattern, kind, method in cfg.get('rules', []):
                if (method is None or method in ep['methods']) and ant_regex(pattern).match(ep['path']):
                    verdict, source = kind, rel; break
            if verdict: break
        if verdict is None:
            for rel, cfg in applicable:
                if cfg.get('authenticated_default'):
                    verdict, source = 'protected', rel; break
        if verdict == 'public':
            ep['authentication'] = 'public_declared'
            dropped |= {(ep['file'], ep['line'], rule) for rule in ('RS100', 'RS101', 'RS102')}
        elif verdict:
            ep['authentication'] = 'hint_found'
            ep['auth_sources'] = ep.get('auth_sources', [])+[f'spring_security:{source}']
            if re.search(OBJECT_ID, ep['path']): ep['object_authorization'] = 'manual_review'
            dropped |= {(ep['file'], ep['line'], rule) for rule in ('RS100', 'RS102')}
    return [f for f in findings if (f['file'], f['line'], f['rule']) not in dropped]
