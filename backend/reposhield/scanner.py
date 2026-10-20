"""Bounded, non-executing static analysis. Findings are hypotheses, not proof."""
import ast
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
import pathspec

EXCLUDED = {'.git', '.venv', 'venv', 'node_modules', 'dist', 'build', '__pycache__', '.next', '.reposhield'}
EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.env'}
RULES = {
 'RS001': ('high', 'Possível segredo no código', 'Remova o valor do código, revogue a credencial e use um gerenciador de segredos.'),
 'RS002': ('high', 'TLS sem verificação de certificado', 'Ative a validação do certificado e configure uma CA confiável.'),
 'RS003': ('high', 'Comando com shell habilitado', 'Use uma lista de argumentos e shell=False; valide entradas externas.'),
 'RS004': ('medium', 'Modo debug habilitado', 'Desative debug em produção e configure por ambiente.'),
 'RS005': ('medium', 'JWT com verificação desabilitada', 'Valide assinatura, algoritmo permitido, expiração, issuer e audience.'),
 'RS100': ('medium', 'Autenticação do endpoint precisa de revisão', 'Verifique proteção global, do router e da rota. Declare rotas públicas na configuração.'),
 'RS101': ('high', 'Rota administrativa sem autorização aparente', 'Exija uma política de autorização no servidor e teste com usuário sem privilégio.'),
 'RS102': ('medium', 'Revisar autorização por objeto', 'Confirme propriedade/tenant do recurso e teste acesso cruzado entre usuários.'),
}
SECRET = re.compile(r"""(?i)\b(?:api[_-]?key|secret[_-]?key|password|access[_-]?token)\b\s*[:=]\s*["']([^"'\n]{8,})["']""")

def redact(value):
    value = SECRET.sub(lambda m: m.group(0).replace(m.group(1), '[REDACTED]'), value)
    return re.sub(r'\b(?:AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,})\b', '[REDACTED]', value)

def finding(rule, file, line, evidence, confidence='medium'):
    severity, title, recommendation = RULES[rule]
    key = f'{rule}:{file}:{line}'
    return dict(id=hashlib.sha256(key.encode()).hexdigest()[:16], rule=rule, severity=severity,
                title=title, file=file, line=line, evidence=redact(evidence)[:350],
                confidence=confidence, status='needs_review', source='reposhield-static',
                recommendation=recommendation)

def route_info(text, rel, public, findings, endpoints, errors):
    """Parse FastAPI/Flask decorators without importing untrusted modules."""
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        errors.append(f'{rel}: sintaxe Python não analisada na linha {exc.lineno}')
        return
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                continue
            verb = dec.func.attr.lower()
            if verb not in {'get','post','put','patch','delete','route','head','options','api_route'}:
                continue
            if not dec.args or not isinstance(dec.args[0], ast.Constant) or not isinstance(dec.args[0].value, str):
                continue
            route = dec.args[0].value
            methods = [verb.upper()]
            if verb in {'route','api_route'}:
                methods = ['GET']
                for kw in dec.keywords:
                    if kw.arg == 'methods':
                        try: methods = [str(x).upper() for x in ast.literal_eval(kw.value)]
                        except (ValueError, TypeError): methods = ['UNKNOWN']
            source = ast.get_source_segment(text, node) or ''
            decorators = ' '.join(ast.get_source_segment(text, x) or '' for x in node.decorator_list)
            # Deliberately conservative: evidence of a dependency does not prove authentication.
            hint = bool(re.search(r'(?i)(Depends|Security|login_required|jwt_required|current_user|authenticate)', source+' '+decorators))
            authorization = bool(re.search(r'(?i)(require_role|has_permission|is_admin|authorize|check_permission)', source+' '+decorators))
            is_public = route in public
            endpoints.append(dict(file=rel,line=dec.lineno,path=route,methods=methods,
                authentication='public_declared' if is_public else 'hint_found' if hint else 'unknown',
                authorization='hint_found' if authorization else 'unknown',framework='python-decorator',
                caveat='Prefixos, middleware e dependências globais precisam de revisão.'))
            if not is_public and not hint:
                findings.append(finding('RS100',rel,dec.lineno,f'{"/".join(methods)} {route}', 'low'))
            if not is_public and re.search(r'(^|/)(admin|management)(/|$)',route) and not authorization:
                findings.append(finding('RS101',rel,dec.lineno,f'{"/".join(methods)} {route}', 'low'))
            if not is_public and re.search(r'\{\w*(id|uuid)\w*\}|<[^>]*(id|uuid)[^>]*>',route):
                findings.append(finding('RS102',rel,dec.lineno,f'{"/".join(methods)} {route}', 'low'))

def scan(project):
    root = Path(project).expanduser().resolve()
    if not root.is_dir(): raise ValueError('Diretório do projeto não existe.')
    config = {}
    if (root/'.reposhield.json').is_file():
        config = json.loads((root/'.reposhield.json').read_text())
    public = config.get('public_routes', ['/health','/healthz'])
    patterns = list(config.get('exclude', []))
    if (root/'.gitignore').is_file():
        patterns += (root/'.gitignore').read_text(errors='replace').splitlines()
    spec = pathspec.PathSpec.from_lines('gitwildmatch', patterns)
    findings, endpoints, errors = [], [], []
    scanned, skipped, total = 0, 0, 0
    partial = False
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not (Path(directory)/d).is_symlink())
        for name in sorted(files):
            path = Path(directory)/name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink() or spec.match_file(rel) or (path.suffix not in EXTENSIONS and path.name != '.env'):
                skipped += 1; continue
            if scanned >= 2000:
                partial = True; break
            try:
                size = path.stat().st_size
                if size > 300_000:
                    skipped += 1; errors.append(f'{rel}: excede 300 KB'); partial = True; continue
                if total + size > 15_000_000:
                    partial = True; break
                text = path.read_text(encoding='utf-8')
            except (OSError, UnicodeError):
                errors.append(f'{rel}: leitura indisponível'); partial = True; continue
            scanned += 1; total += size
            for number, line in enumerate(text.splitlines(),1):
                for rule, pattern in [
                    ('RS001', SECRET),
                    ('RS002', r'\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false'),
                    ('RS003', r'\bshell\s*=\s*True\b'),
                    ('RS004', r'\bdebug\s*[:=]\s*(?:True|true)\b'),
                    ('RS005', r'verify_signature[\'\"]?\s*:\s*False|verify\s*=\s*False.*jwt'),
                ]:
                    if re.search(pattern,line): findings.append(finding(rule,rel,number,line.strip()))
            if path.suffix == '.py': route_info(text,rel,public,findings,endpoints,errors)
            if path.suffix in {'.js','.ts','.jsx','.tsx'}:
                for match in re.finditer(r"""\b(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*["']([^"']+)["']""",text):
                    endpoints.append(dict(file=rel,line=text[:match.start()].count('\n')+1,path=match[2],methods=[match[1].upper()],authentication='unknown',authorization='unknown',framework='express-pattern',caveat='Middleware e proteção global não resolvidos.'))
        if partial and (scanned >= 2000 or total >= 14_700_000): break
    if errors: partial = True
    return dict(version=1,created_at=datetime.now(timezone.utc).isoformat(),project=root.name,
        findings=findings,endpoints=endpoints,coverage=dict(files=scanned,skipped=skipped,bytes=total,partial=partial),
        errors=errors,ai=None,limitations=['Análise heurística; não confirma explorabilidade.',
        'Python: decorators FastAPI/Flask. JavaScript: inventário básico Express.',
        'Não resolve middleware, prefixos ou dependências globais; ausência de achados não prova segurança.',
        'Não inclui auditoria de CVEs, teste dinâmico nem correção automática nesta versão.'])

def sarif(report):
    return {'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json','runs':[{
        'tool':{'driver':{'name':'RepoShield','version':'0.1.0','rules':[{'id':k,'shortDescription':{'text':v[1]}} for k,v in RULES.items()]}},
        'results':[{'ruleId':f['rule'],'level':'error' if f['severity'] in {'critical','high'} else 'warning',
            'message':{'text':f['title']+' — '+f['recommendation']},
            'locations':[{'physicalLocation':{'artifactLocation':{'uri':__import__('urllib.parse',fromlist=['quote']).quote(f['file'])},'region':{'startLine':f['line']}}}]} for f in report['findings']]}]}

def markdown(report):
    out = [f"# RepoShield — {report['project']}",f"Arquivos analisados: {report['coverage']['files']}", '']
    for f in report['findings']:
        out += [f"## {f['severity'].upper()} · {f['title']}",f"`{f['file']}:{f['line']}` · confiança {f['confidence']}",f['recommendation'],'']
    out += ['## Limitações', *['- '+x for x in report['limitations']]]
    return '\n'.join(out)
