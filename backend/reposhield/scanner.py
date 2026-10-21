"""Bounded, non-executing static analysis. Findings are hypotheses, not proof."""
import ast
import hashlib
import json
import os
import re
import subprocess
from datetime import date, datetime, timezone
from pathlib import Path
import pathspec
from . import __version__, assurance, dotnet
from . import audit
from . import runtime
from . import java
from . import triage, performance
from .adapters import ADAPTERS, NAMES
from .adapters import base as adapter_base
from .adapters.sarif import import_sarif
from .routes import python_routes, js_routes
from .syntax import clean, placeholder

EXCLUDED = {'.git', '.venv', 'venv', 'node_modules', 'dist', 'build', '__pycache__', '.next', '.reposhield', 'bin', 'obj', '.vs'}
EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.env', '.cs', '.csproj', '.props', '.targets',
              '.java', '.properties', '.xml', '.sql'}
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
RULES.update(dotnet.RULES)
RULES.update(audit.RULES)
RULES.update(runtime.RULES)
RULES.update(java.RULES)
LEGACY_META = {
 'RS001': ('secrets','CWE-798'), 'RS002': ('transport','CWE-295'),
 'RS003': ('injection','CWE-78'), 'RS004': ('secrets','CWE-489'),
 'RS005': ('tokens','CWE-347'), 'RS100': ('authentication','CWE-306'),
 'RS101': ('authorization','CWE-862'), 'RS102': ('authorization','CWE-639'),
}
SECRET = re.compile(r"""(?i)\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|signing[_-]?key|jwt[_-]?key|password|access[_-]?token)\b["']?\s*[:=]\s*["']([^"'\n]{8,})["']""")

def redact(value):
    value = SECRET.sub(lambda m: m.group(0).replace(m.group(1), '[REDACTED]'), value)
    value = re.sub(r'(?i)(\b(?:password|pwd)\s*=\s*)[^;"\'\n]+', r'\1[REDACTED]', value)
    return re.sub(r'\b(?:AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,})\b', '[REDACTED]', value)

RUNTIME_GUARD_CONFIG = ('.json', '.yml', '.yaml', '.config', '.properties', '.env')


def _parent_dir(rel):
    return rel.rpartition('/')[0]


def _config_file(rel):
    # runtime_guard applies only to configuration files, never to source code.
    return rel.rsplit('/', 1)[-1].lower().endswith(RUNTIME_GUARD_CONFIG)


def _same_tree(a, b):
    # The project root ('') contains every directory; otherwise one must be an ancestor of the other.
    return a == b or not a or not b or a.startswith(b+'/') or b.startswith(a+'/')


def finding(rule, file, line, evidence, confidence='medium'):
    severity, title, recommendation = RULES[rule]
    key = f'{rule}:{file}:{line}:{redact(evidence)}'
    meta = audit.META.get(rule) or dotnet.META.get(rule) or runtime.META.get(rule) or java.META.get(rule) or dict(category=LEGACY_META[rule][0],cwe=LEGACY_META[rule][1],validation='Confirme o fluxo em ambiente de teste e adicione um teste de regressão.')
    # Rule-independent key: the same weakness on the same line found by two rules is one finding.
    fingerprint = hashlib.sha256(f'{file}:{line}:{meta["cwe"]}'.encode()).hexdigest()[:16]
    return dict(id=hashlib.sha256(key.encode()).hexdigest()[:16], fingerprint=fingerprint, rule=rule, severity=severity,
                title=title, file=file, line=line, evidence=redact(evidence)[:350],
                confidence=confidence, status='needs_review', source='reposhield-static',
                recommendation=recommendation, **meta)

def scan(project, *, runtime_enabled=False, dependencies_enabled=False, tools=None, imports=(), allow_downloads=False,
         baseline=None, diff_base=None, today=None, performance_enabled=True, query_plans=()):
    if query_plans and not performance_enabled:
        raise ValueError('Importação de planos exige análise de performance habilitada.')
    root = Path(project).expanduser().resolve()
    if not root.is_dir(): raise ValueError('Diretório do projeto não existe.')
    if tools is not None:
        unknown = sorted(name for name in set(tools) if name != 'auto' and name not in NAMES)
        if unknown: raise ValueError(f'Ferramenta desconhecida: {unknown[0]}. Disponíveis: auto, ' + ', '.join(sorted(NAMES)))
    today = today or date.today()
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
    perf_findings, perf_files = [], 0
    perf_errors, perf_plans = [], []
    by_extension, skipped_reasons, unsupported_source = {}, {}, {}
    excluded_directories = 0
    scanned, skipped, total = 0, 0, 0
    partial = False
    fallbacks, classes, guarded = [], [], {}  # digest -> set of .cs directories holding the guard
    java_configs = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        excluded_directories += sum(d in EXCLUDED or (Path(directory)/d).is_symlink() for d in dirs)
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not (Path(directory)/d).is_symlink())
        for name in sorted(files):
            path = Path(directory)/name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink() or spec.match_file(rel) or (path.suffix not in EXTENSIONS and path.name != '.env'):
                reason = 'symlink' if path.is_symlink() else 'configured_ignore' if spec.match_file(rel) else 'unsupported_extension'
                skipped_reasons[reason] = skipped_reasons.get(reason, 0)+1
                if reason == 'unsupported_extension' and path.suffix in {'.go','.rb','.php','.rs','.kt','.vb','.fs','.vue','.svelte'}:
                    unsupported_source[path.suffix] = unsupported_source.get(path.suffix, 0)+1
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
            by_extension[path.suffix or path.name] = by_extension.get(path.suffix or path.name, 0)+1
            if performance_enabled and path.suffix in {'.cs', '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.sql'}:
                perf_files += 1
                perf_findings.extend(performance.analyze(text, rel))
            code_text = clean(text) if path.suffix == '.cs' else text
            for number, line in enumerate(code_text.splitlines(),1):
                # Placeholders such as <senha>, ${VAR} or changeme are documentation, not secrets.
                values = [m[1].strip() for m in SECRET.finditer(line) if not placeholder(m[1])]
                if values:
                    secret = finding('RS001',rel,number,line.strip())
                    secret['_value_sha'] = dotnet.value_digest(values[0])  # temporary; removed after dedupe
                    findings.append(secret)
                for rule, pattern in [
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
            if path.suffix == '.cs':
                eps, extra = dotnet.analyze(text, rel, public, finding)
                endpoints.extend(eps); findings.extend(extra)
                classes.extend(dotnet.classes(text))
                for digest, guard_rel in dotnet.guard_hashes(text, rel):
                    guarded.setdefault(digest, set()).add(_parent_dir(guard_rel))
                line_no = dotnet.fallback_policy(text)
                if line_no: fallbacks.append((rel, line_no))
            if path.suffix in {'.cs','.json','.config','.csproj','.props','.targets'}:
                findings.extend(dotnet.config_secrets(text, rel, finding))
            if path.suffix == '.java':
                eps, extra = java.analyze(text, rel, public, finding)
                endpoints.extend(eps); findings.extend(extra)
                java_configs.append((rel, java.security_config(text, rel)))
            elif path.suffix == '.xml' and 'intercept-url' in text:
                java_configs.append((rel, java.security_config(text, rel)))
            if path.suffix in {'.properties','.yml','.yaml'}:
                findings.extend(java.config_secrets(text, rel, finding))
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
    findings = dotnet.resolve_project(endpoints, findings, fallbacks, classes)
    findings = java.resolve_project(endpoints, findings, java_configs)
    # Imported SARIF and external adapters join the findings before dedupe and classification.
    tools_report = []
    for raw_path in imports:
        path = Path(raw_path)
        try:
            if path.is_symlink() or not path.is_file():
                raise ValueError('arquivo ausente ou link simbólico')
            imported = import_sarif(adapter_base.read_bounded(path), root=root)
        except (OSError, ValueError, adapter_base.ToolError) as exc:
            errors.append(f'SARIF importado inválido: {path.name}')
            tools_report.append(dict(name=f'import:{path.name}', axis='import', network='none', version=None, status='failed',
                                     findings=0, detail='leitura indisponível' if isinstance(exc, OSError) else str(exc)[:300],
                                     requested='import'))
            continue
        findings.extend(imported)
        tools_report.append(dict(name=f'import:{path.name}', axis='import', network='none', version=None, status='imported',
                                 findings=len(imported), detail='', requested='import'))
    osv_deps = osv_record = None
    if tools:
        requested = set(tools)
        selected = []
        for adapter in ADAPTERS:
            if adapter.axis == 'runtime' and not runtime_enabled:
                if adapter.name in requested:
                    tools_report.append(dict(name=adapter.name, axis=adapter.axis, network=adapter.network, version=None,
                                             status='skipped_network', findings=0, detail='Exige --runtime.', requested='explicit'))
                continue
            selected.append(adapter)
        options = {}
        runtime_cfg = config.get('runtime')
        if runtime_enabled and isinstance(runtime_cfg, dict) and 'base_url' in runtime_cfg:
            options['base_url'] = runtime_cfg['base_url']
        result = adapter_base.run_adapters(root, selected, requested=requested, allow_downloads=allow_downloads,
                                           dependencies_consent=dependencies_enabled, options=options)
        for record in result['tools']:
            record['requested'] = 'explicit' if record['name'] in requested else 'auto'
            tools_report.append(record)
        findings.extend(result['findings'])
        osv_deps = result['dependencies']
        osv_record = next((r for r in result['tools'] if r['name'] == 'osv-scanner'), None)
    runtime_report = None
    if runtime_enabled:
        runtime_report = runtime.run(config,finding)
        findings.extend(runtime_report.pop("findings"))
        errors.extend(runtime_report["errors"])
    if errors: partial = True
    levels={'critical':0,'high':1,'medium':2,'low':3}
    # Secrets: one finding per line across rules. Other categories can legitimately
    # repeat on a line (e.g. GET and POST of one OpenAPI path), so keep them by id.
    unique = {}
    for f in findings:
        key = f['fingerprint'] if f['category'] == 'secrets' else f['id']
        kept = unique.get(key)
        if kept is None:
            unique[key] = f; continue
        # Prefer higher severity, then the specific rule over the generic RS001.
        if (levels[f['severity']], f['rule'] == 'RS001') < (levels[kept['severity']], kept['rule'] == 'RS001'):
            f, kept = kept, f
            unique[key] = kept
        if f['rule'] != kept['rule'] and f['rule'] not in kept.setdefault('also_matched', []):
            kept['also_matched'].append(f['rule'])
    findings = list(unique.values())
    for f in findings:
        # Only a digest ever reaches this point; the temporary field never reaches the report.
        digest = f.pop('_value_sha', None)
        if digest in guarded and _config_file(f['file']) and any(_same_tree(_parent_dir(f['file']), d) for d in guarded[digest]):
            f['runtime_guard'] = True
            f['context_note'] = 'Valor reconhecido em verificação de ambiente no código (.cs); parece bloqueado fora de desenvolvimento. Confirme que não é aceito em produção.'
    findings.sort(key=lambda f:(levels[f['severity']],f['file'],f['line'],f['rule']))
    # The checklist describes the whole project; the diff filter below only narrows report['findings'].
    checklist = audit.controls(findings,indicators,endpoints)
    assurance.classify(findings)
    triage.assign_keys(findings)
    rules, suppression_errors = triage.load_suppressions(config, today)
    if suppression_errors: partial = True
    errors.extend(suppression_errors)
    triage_warnings = triage.apply_suppressions(findings, rules, today)
    suppressed = sum(f.get('disposition') == 'suppressed' for f in findings)
    baseline_report = None
    if baseline:
        baseline_path = Path(baseline)
        if baseline_path.is_symlink() or not baseline_path.is_file():
            raise ValueError('Linha de base deve ser um arquivo regular, não um link simbólico.')
        if baseline_path.stat().st_size > triage.MAX_BASELINE_CHARS:
            raise ValueError('Linha de base excede 20 MB.')
        keys = triage.load_baseline(baseline_path.read_text(encoding='utf-8', errors='replace'))
        baseline_report = dict(file=baseline_path.name, **triage.apply_baseline(findings, keys))
    diff_report = None
    if diff_base:
        if not adapter_base.git_history_safe(root):
            raise ValueError('Diff exige repositório git sem comandos configurados.')
        def runner(args):
            try:
                result = adapter_base.execute(args, cwd=root, timeout=120)
            except (OSError, adapter_base.ToolError, subprocess.TimeoutExpired):
                return 1, ''
            return result.returncode, result.stdout
        changed = triage.changed_lines(root, diff_base, runner)
        if changed is None:
            raise ValueError('Não foi possível calcular o diff contra ' + diff_base + '.')
        findings = triage.apply_diff(findings, changed)
        perf_findings = triage.apply_diff(perf_findings, changed)
        diff_report = dict(base=diff_base, note=triage.diff_scope_note(diff_base), files=len(changed))
    for plan_path in query_plans:
        try:
            observations, metadata = performance.read_plan(plan_path)
            perf_findings.extend(observations)
            perf_plans.append(metadata)
        except (OSError, ValueError) as exc:
            perf_errors.append(f'Plano {Path(plan_path).name}: {exc}')
    perf_report = performance.report(perf_findings, perf_files, enabled=performance_enabled,
                                     partial=partial if performance_enabled else False, errors=perf_errors,
                                     plans=perf_plans, diff=diff_report)
    triage_report = dict(suppressed=suppressed, baseline=baseline_report, diff=diff_report, warnings=triage_warnings)
    report = dict(version=4,performance=perf_report,runtime=runtime_report,engine_version=__version__,controls=checklist,summary=dict(
        rules=len(RULES),controls=len(checklist),findings=len(findings),
        requires_manual=sum(c['status']=='manual_required' for c in checklist)),created_at=datetime.now(timezone.utc).isoformat(),project=root.name,
        findings=findings,endpoints=endpoints,coverage=dict(files=scanned,skipped=skipped,bytes=total,partial=partial,by_extension=by_extension,skipped_reasons=skipped_reasons,excluded_directories=excluded_directories,unsupported_source=unsupported_source),
        errors=errors,ai=None,tools=tools_report,triage=triage_report,limitations=['Análise heurística; não confirma explorabilidade.',
        'C#/.NET: padrões locais em controllers e Minimal APIs; FallbackPolicy com RequireAuthenticatedUser e [Authorize] herdado de classe base (por nome, no projeto) são resolvidos; não resolve filtros globais, MapGroup ou semântica de policies.',
        'Python: decorators e herança local de routers. JavaScript: snippets Express heurísticos. OpenAPI: contratos 3.x JSON locais.',
        'Java/Spring: heurística por anotações, SecurityFilterChain simples e intercept-url; não resolve meta-anotações, SpEL nem herança.',
        'Não resolve imports, middleware arbitrário ou semântica de guards; ausência de achados não prova segurança.',
        'Runtime opcional só verifica GETs explícitos locais. OSV opcional limitado ao lock npm raiz; sem brute force ou correção automática.'])

    # OSV-Scanner serves dependencies when it returned a usable result; otherwise the internal npm check.
    if osv_deps is not None and osv_deps.get('status') != 'incomplete':
        report['dependencies'] = osv_deps
    elif dependencies_enabled:
        from .dependencies import check
        report['dependencies'] = check(root)
        if osv_record is not None and osv_record['status'] != 'not_applicable':
            report['dependencies'].setdefault('warnings', []).append('OSV-Scanner indisponível; usada a consulta interna (somente npm).')
    else:
        report['dependencies'] = None
    report['verdict'] = assurance.evaluate(report)
    return report

def _sarif_result(f):
    result = {'ruleId':f['rule'],'level':'error' if f['severity'] in {'critical','high'} else 'warning',
        'message':{'text':f['title']+' — '+f['recommendation']},
        'properties':{'confidence':f['confidence'],'category':f.get('category'),'cwe':f.get('cwe'),
            'reposhieldSeverity':f['severity'],
            'tags':[f['cwe']] if f.get('cwe') else []},
        'locations':[{'physicalLocation':{'artifactLocation':{'uri':__import__('urllib.parse',fromlist=['quote']).quote(f['file'])},'region':{'startLine':f['line']}}}]}
    if f.get('disposition') == 'suppressed':
        result['suppressions'] = [{'kind':'external','status':'accepted','justification':(f.get('suppressed_by') or {}).get('justification','')}]
    if f.get('baseline') in ('existing', 'new'):
        result['baselineState'] = 'unchanged' if f['baseline'] == 'existing' else 'new'
    return result

def sarif(report):
    return {'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json','runs':[{
        'properties':{'verdict':report.get('verdict'),'dependencies':report.get('dependencies'),'tools':report.get('tools'),'performance':report.get('performance')},
        'tool':{'driver':{'name':'RepoShield','version':__version__,'rules':[{'id':k,'shortDescription':{'text':v[1]},'help':{'text':v[2]}} for k,v in RULES.items()]}},
        'results':[_sarif_result(f) for f in report['findings']]}]}

def markdown(report):
    from .report import markdown as render
    return render(report)

