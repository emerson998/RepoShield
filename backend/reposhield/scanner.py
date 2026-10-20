"""Bounded, non-executing static analysis. Findings are hypotheses, not proof."""
import ast
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
import pathspec
from . import audit
from . import runtime
from .routes import python_routes, js_routes

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
RULES.update(audit.RULES)
RULES.update(runtime.RULES)
LEGACY_META = {
 'RS001': ('secrets','CWE-798'), 'RS002': ('transport','CWE-295'),
 'RS003': ('injection','CWE-78'), 'RS004': ('secrets','CWE-489'),
 'RS005': ('tokens','CWE-347'), 'RS100': ('authentication','CWE-306'),
 'RS101': ('authorization','CWE-862'), 'RS102': ('authorization','CWE-639'),
}
SECRET = re.compile(r"""(?i)\b(?:api[_-]?key|secret[_-]?key|password|access[_-]?token)\b\s*[:=]\s*["']([^"'\n]{8,})["']""")

def redact(value):
    value = SECRET.sub(lambda m: m.group(0).replace(m.group(1), '[REDACTED]'), value)
    return re.sub(r'\b(?:AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,})\b', '[REDACTED]', value)

def finding(rule, file, line, evidence, confidence='medium'):
    severity, title, recommendation = RULES[rule]
    key = f'{rule}:{file}:{line}:{redact(evidence)}'
    meta = audit.META.get(rule) or runtime.META.get(rule) or dict(category=LEGACY_META[rule][0],cwe=LEGACY_META[rule][1],validation='Confirme o fluxo em ambiente de teste e adicione um teste de regressão.')
    return dict(id=hashlib.sha256(key.encode()).hexdigest()[:16], rule=rule, severity=severity,
                title=title, file=file, line=line, evidence=redact(evidence)[:350],
                confidence=confidence, status='needs_review', source='reposhield-static',
                recommendation=recommendation, **meta)

def scan(project, *, runtime_enabled=False):
    root = Path(project).expanduser().resolve()
    if not root.is_dir(): raise ValueError('Diretório do projeto não existe.')
    config = {}
    if (root/'.reposhield.json').is_symlink(): raise ValueError('Configuração não pode ser um link simbólico.')
    if (root/'.reposhield.json').is_file():
        if (root/'.reposhield.json').stat().st_size>100_000: raise ValueError('Configuração excede 100 KB.')
        config = json.loads((root/'.reposhield.json').read_text())
    if not isinstance(config,dict): raise ValueError('Configuração deve ser um objeto JSON.')
    for field in ('public_routes','exclude'):
        if field in config and (not isinstance(config[field],list) or not all(isinstance(x,str) for x in config[field])):
            raise ValueError(f'{field} deve ser uma lista de strings.')
    public = config.get('public_routes', ['/health','/healthz'])
    patterns = list(config.get('exclude', []))
    if (root/'.gitignore').is_file() and not (root/'.gitignore').is_symlink():
        patterns += (root/'.gitignore').read_text(errors='replace').splitlines()
    spec = pathspec.PathSpec.from_lines('gitwildmatch', patterns)
    findings, endpoints, errors = [], [], []
    indicators = {}
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
            extra, refs = audit.analyze_file(text,rel,finding)
            findings.extend(extra)
            for category, hits in refs.items():
                indicators.setdefault(category,[]).extend(hits)
                indicators[category] = indicators[category][:12]
            if path.suffix == '.py':
                try: ast.parse(text)
                except SyntaxError as exc: errors.append(f'{rel}: sintaxe Python não analisada na linha {exc.lineno}')
                eps, extra = python_routes(text,rel,public,finding)
                endpoints.extend(eps); findings.extend(extra)
            elif path.suffix in {'.js','.ts','.jsx','.tsx'}:
                eps, extra = js_routes(text,rel,public,finding)
                endpoints.extend(eps); findings.extend(extra)
            if path.suffix == '.json':
                try:
                    eps, extra, issues = audit.openapi_routes(text,rel,public,finding)
                    endpoints.extend(eps); findings.extend(extra); errors.extend(issues)
                except (TypeError,AttributeError,ValueError):
                    errors.append(f'{rel}: contrato OpenAPI inválido ou não suportado')
        if partial and (scanned >= 2000 or total >= 14_700_000): break
    runtime_report = None
    if runtime_enabled:
        runtime_report = runtime.run(config,finding)
        findings.extend(runtime_report.pop("findings"))
        errors.extend(runtime_report["errors"])
    if errors: partial = True
    findings = list({f['id']:f for f in findings}.values())
    levels={'critical':0,'high':1,'medium':2,'low':3}
    findings.sort(key=lambda f:(levels[f['severity']],f['file'],f['line'],f['rule']))
    checklist = audit.controls(findings,indicators,endpoints)
    return dict(version=2,runtime=runtime_report,engine_version='0.2.0',controls=checklist,summary=dict(
        rules=len(RULES),controls=len(checklist),findings=len(findings),
        requires_manual=sum(c['status']=='manual_required' for c in checklist)),created_at=datetime.now(timezone.utc).isoformat(),project=root.name,
        findings=findings,endpoints=endpoints,coverage=dict(files=scanned,skipped=skipped,bytes=total,partial=partial),
        errors=errors,ai=None,limitations=['Análise heurística; não confirma explorabilidade.',
        'Python: decorators e herança local de routers. JavaScript: snippets Express heurísticos. OpenAPI: contratos 3.x JSON locais.',
        'Não resolve imports, middleware arbitrário ou semântica de guards; ausência de achados não prova segurança.',
        'Runtime opcional só verifica GETs explícitos locais. Sem auditoria de CVEs, brute force ou correção automática.'])

def sarif(report):
    return {'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json','runs':[{
        'tool':{'driver':{'name':'RepoShield','version':'0.2.0','rules':[{'id':k,'shortDescription':{'text':v[1]},'help':{'text':v[2]}} for k,v in RULES.items()]}},
        'results':[{'ruleId':f['rule'],'level':'error' if f['severity'] in {'critical','high'} else 'warning',
            'message':{'text':f['title']+' — '+f['recommendation']},
            'properties':{'confidence':f['confidence'],'category':f.get('category'),'cwe':f.get('cwe')},
            'locations':[{'physicalLocation':{'artifactLocation':{'uri':__import__('urllib.parse',fromlist=['quote']).quote(f['file'])},'region':{'startLine':f['line']}}}]} for f in report['findings']]}]}

def markdown(report):
    from .report import markdown as render
    return render(report)
