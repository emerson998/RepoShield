"""Endpoint extraction with explicit, local provenance. No imports or execution."""
import ast
import re
from .audit import endpoint_findings

AUTH=r'(?i)\b(?:current_user|get_current_user|require_auth|authenticate|authenticated|login_required|jwt_required|auth_required|verify_token|auth_guard|requireAuth|isAuthenticated)\b'
AUTHZ=r'(?i)\b(?:require_role|has_permission|is_admin|authorize|check_permission|requireAdmin|requireRole|checkOwnership|require_owner|check_owner|verify_tenant)\b'
VERBS={'get','post','put','patch','delete','head','options','route','api_route'}

def node_source(text,node): return ast.get_source_segment(text,node) or ''

def python_routes(text,rel,public,make):
    try: tree=ast.parse(text)
    except SyntaxError: return [],[]
    objects={}; mounts={}
    for node in ast.walk(tree):
        if isinstance(node,ast.Assign) and isinstance(node.value,ast.Call):
            call=node.value
            constructor=ast.unparse(call.func).split('.')[-1]
            if constructor in {'FastAPI','APIRouter','Flask','Blueprint'}:
                kw={k.arg:k.value for k in call.keywords}
                prefix=kw.get('prefix',kw.get('url_prefix'))
                for target in node.targets:
                    if isinstance(target,ast.Name): objects[target.id]=dict(prefix=prefix.value if isinstance(prefix,ast.Constant) and isinstance(prefix.value,str) else '',dependencies=node_source(text,kw['dependencies']) if 'dependencies' in kw else '',constructor=constructor)
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='include_router' and node.args and isinstance(node.args[0],ast.Name):
            kw={k.arg:k.value for k in node.keywords}
            prefix=kw.get('prefix'); parent=ast.unparse(node.func.value)
            mounts.setdefault(node.args[0].id,[]).append(dict(parent=parent,prefix=prefix.value if isinstance(prefix,ast.Constant) and isinstance(prefix.value,str) else '',dependencies=node_source(text,kw['dependencies']) if 'dependencies' in kw else ''))
    endpoints=[];findings=[]
    for node in ast.walk(tree):
        if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)): continue
        for dec in node.decorator_list:
            if not isinstance(dec,ast.Call) or not isinstance(dec.func,ast.Attribute) or dec.func.attr not in VERBS: continue
            if not dec.args or not isinstance(dec.args[0],ast.Constant) or not isinstance(dec.args[0].value,str): continue
            raw=dec.args[0].value; obj=ast.unparse(dec.func.value)
            info=objects.get(obj,dict(prefix='',dependencies='',constructor='unresolved'))
            method=dec.func.attr
            methods=[method.upper()] if method not in {'route','api_route'} else ['GET']
            for kw in dec.keywords:
                if kw.arg=='methods':
                    try: methods=[str(x).upper() for x in ast.literal_eval(kw.value)]
                    except (ValueError,TypeError): methods=['UNKNOWN']
            # Use executable syntax, excluding comments/docstrings, to avoid treating comments as controls.
            body=' '.join(n.id if isinstance(n,ast.Name) else n.attr for n in ast.walk(node) if isinstance(n,(ast.Name,ast.Attribute)))
            contexts=mounts.get(obj,[dict(parent='',prefix='',dependencies='')])
            for mount in contexts:
                parent=objects.get(mount['parent'],{})
                path=parent.get('prefix','')+mount['prefix']+info['prefix']+raw
                inherited=' '.join([info['dependencies'],mount['dependencies'],parent.get('dependencies','')])
                auth=[]
                if re.search(AUTH,body): auth.append('route')
                if re.search(AUTH,inherited): auth.append('local_router_or_app')
                authorization=bool(re.search(AUTHZ,body+' '+inherited))
                is_public=path in public
                ep=dict(file=rel,line=dec.lineno,path=path,raw_path=raw,methods=methods,framework=info['constructor'],
                    authentication='public_declared' if is_public else 'hint_found' if auth else 'unknown',
                    authorization='hint_found' if authorization else 'unknown',auth_sources=auth,
                    caveat='Indícios locais; imports, middleware e semântica das funções não são resolvidos.')
                endpoints.append(ep)
                findings+=check(ep,body+' '+inherited,make)
    return endpoints,findings

def check(ep,source,make):
    out=[];path=ep['path'];rel=ep['file'];line=ep['line'];public=ep['authentication']=='public_declared'
    evidence=f'{"/".join(ep["methods"])} {path}'
    if not public and ep['authentication']=='unknown': out.append(make('RS100',rel,line,evidence,'low'))
    if not public and re.search(r'(^|/)(?:admin|management)(/|$)',path) and ep['authorization']=='unknown': out.append(make('RS101',rel,line,evidence,'low'))
    if not public and re.search(r'\{[^}]*(?:id|uuid)[^}]*\}|<[^>]*(?:id|uuid)[^>]*>|:\w*(?:id|Id|uuid)\w*',path):
        # Even a role guard does not prove object authorization; keep this as a low-confidence review.
        out.append(make('RS102',rel,line,evidence,'low'))
    return out+endpoint_findings(ep,source,make)

def js_routes(text,rel,public,make):
    endpoints=[];findings=[]
    # Bounded route-local snippets; global middleware is intentionally unresolved.
    pattern=r"""\b(app|router)\.(get|post|put|patch|delete|head|options)\s*\(\s*["']([^"']+)["']"""
    matches=list(re.finditer(pattern,text))
    for i,m in enumerate(matches):
        end=matches[i+1].start() if i+1<len(matches) else len(text)
        source=text[m.end():min(end,m.end()+3000)]
        source=re.sub(r'/\*.*?\*/|//[^\n]*','',source,flags=re.S)
        ep=dict(file=rel,line=text[:m.start()].count('\n')+1,path=m[3],methods=[m[2].upper()],framework='express-pattern',
            authentication='public_declared' if m[3] in public else 'hint_found' if re.search(AUTH,source) else 'unknown',
            authorization='hint_found' if re.search(AUTHZ,source) else 'unknown',auth_sources=['route_snippet'] if re.search(AUTH,source) else [],
            caveat='Snippet limitado; middleware global, mounts e semântica não resolvidos.')
        endpoints.append(ep);findings+=check(ep,source,make)
    return endpoints,findings
