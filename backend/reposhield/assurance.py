"""Deterministic release gate. Never interpret absence of findings as safety."""
from pathlib import PurePosixPath
import re
from .report import TOOL_STATUS_LABELS


DEV_CONFIG = [re.compile(p) for p in (
    r'(?i)^appsettings\.(development|local|dev)(\..+)?\.json$',
    r'(?i)\.(development|dev|local)\.(json|ya?ml|properties)$',
    r'(?i)^application-(dev|local)\.(ya?ml|properties)$',
)]
NON_BLOCKING = {'test_context', 'runtime_guarded', 'dev_config', 'suppressed', 'baseline'}
# Regras de configuração do próprio RepoShield; achados de ferramentas externas (rule com '/') não entram.
DEV_CONFIG_RULES = {'RS001', 'RS403', 'RS502'}


def dev_config(path):
    name = PurePosixPath(path).name
    return any(pattern.search(name) for pattern in DEV_CONFIG)


def classify(findings):
    for item in findings:
        path = PurePosixPath(item['file'])
        test = bool(set(path.parts) & {'tests', 'test', '__tests__', '__mocks__', 'fixtures'}) or bool(
            re.search(r'(?:\.(?:spec|test)\.[^.]+$|^test_.*\.py$|_test\.py$)', path.name))
        item['context'] = 'test' if test else 'production_or_unknown'
        # Keep all evidence, especially possible real secrets in test files.
        item['disposition'] = 'review_required'
        if item.get('source_suppressed'):
            # Já suprimido na ferramenta de origem (SARIF); não sobrescreve.
            item['disposition'] = 'suppressed'
        elif item.get('runtime_guard'):
            item['disposition'] = 'runtime_guarded'
        elif item.get('category') == 'secrets' and item.get('rule') in DEV_CONFIG_RULES and dev_config(item['file']):
            item['disposition'] = 'dev_config'
            item['context_note'] = 'Credencial em configuração de desenvolvimento; confirme que não é reutilizada em produção e que o valor não é real.'
        elif test and item['rule'] == 'RS209':
            item['disposition'] = 'test_context'
            item['context_note'] = 'Armazenamento em teste; não comprova exposição em produção. Confira o serviço utilizado pelo teste.'


def evaluate(report):
    findings = report['findings']
    blockers = [f['id'] for f in findings if f.get('disposition') not in NON_BLOCKING]
    runtime = report.get('runtime') or {}
    results = runtime.get('results', [])
    failed = [r['case'] for r in results if not r['matched']]
    tools = report.get('tools') or []
    triage = report.get('triage') or {}
    gaps = []
    if report['coverage']['partial'] or report.get('errors'):
        gaps.append('Análise incompleta ou com erros; resolva as etapas indicadas no relatório.')
    if report['coverage'].get('unsupported_source'):
        gaps.append('Código sem analisador: '+', '.join(sorted(report['coverage']['unsupported_source']))+'. Esses arquivos não foram avaliados.')
    if not report['coverage']['files']:
        gaps.append('Nenhum arquivo suportado foi analisado.')
    if not results:
        gaps.append('Nenhum contrato HTTP foi verificado. Configure runtime e execute com --runtime.')
    if blockers:
        gaps.append(f'{len(blockers)} achado(s) pendente(s) de investigação ou correção.')
    if any(f.get('disposition') == 'test_context' for f in findings):
        gaps.append('Há armazenamento de token em testes; confirme o comportamento correspondente em produção.')
    for tool in tools:
        status = tool.get('status')
        if (tool.get('requested') == 'explicit' and status in {'not_installed', 'failed', 'skipped_network'}) or (
                tool.get('requested') == 'auto' and status == 'failed'):
            gaps.append(f"Ferramenta {tool.get('name', '?')} não executada ({TOOL_STATUS_LABELS.get(status, status)}); eixo {tool.get('axis')} não verificado.")
        if tool.get('requested') == 'import' and status == 'failed':
            gaps.append(f"Importação {tool.get('name', '?')} falhou; eixo {tool.get('axis')} não verificado.")
    deps = report.get('dependencies') or {}
    if deps.get('status') not in {'passed', 'failed'}:
        gaps.append('Auditoria de dependências não concluída. Use --dependencies (OSV-Scanner se instalado; senão consulta interna npm).')
    vulns = deps.get('vulnerabilities', [])
    production = [v for v in vulns if v.get('reachability', 'production') == 'production']
    blocking = [v for v in production if v.get('severity') in {'critical', 'high'}]
    review = [v for v in production if v.get('severity', 'unknown') not in {'critical', 'high'}]
    dev_only = [v for v in vulns if v.get('reachability') == 'dev_only']
    conditional = [v for v in vulns if v.get('reachability') == 'conditional']
    if blocking:
        gaps.append(f"{len(blocking)} vulnerabilidade(s) critical/high em dependência de produção; atualize para a versão corrigida.")
    if review:
        gaps.append(f"{len(review)} advisory(ies) em dependência de produção com severidade média/baixa/desconhecida; revise alcance e atualização.")
    if conditional:
        gaps.append(f"{len(conditional)} advisory(ies) grave(s) condicionados a recurso aparentemente ausente (ex.: SSR); confirme manualmente que não se aplicam.")
    warnings = list(deps.get('warnings', []))
    if dev_only:
        warnings.append(f"{len(dev_only)} advisory(ies) só em dependências de desenvolvimento/build; não bloqueiam a liberação.")
    not_applicable = [v for v in vulns if v.get('reachability') == 'not_applicable']
    if not_applicable:
        warnings.append(f"{len(not_applicable)} advisory(ies) condicionados a recurso ausente no projeto (ex.: SSR); não bloqueiam.")
    runtime_guarded = sum(f.get('disposition') == 'runtime_guarded' for f in findings)
    if runtime_guarded:
        warnings.append(f"{runtime_guarded} achado(s) de segredo com valor reconhecido como bloqueado fora de desenvolvimento; confirme que não é aceito em produção. Não bloqueiam.")
    dev_configs = sum(f.get('disposition') == 'dev_config' for f in findings)
    if dev_configs:
        warnings.append(f"{dev_configs} achado(s) de credencial em configuração de desenvolvimento; confirme que não é reutilizada em produção. Não bloqueiam.")
    def from_source(f):
        return bool(f.get('source_suppressed')) or (f.get('suppressed_by') or {}).get('match') == 'sarif'
    suppressed_findings = [f for f in findings if f.get('disposition') == 'suppressed']
    source_suppressed = sum(from_source(f) for f in suppressed_findings)
    suppressed = len(suppressed_findings) - source_suppressed
    if suppressed:
        warnings.append(f'{suppressed} achado(s) suprimido(s) com justificativa; revise antes da validade.')
    if source_suppressed:
        warnings.append(f'{source_suppressed} achado(s) suprimido(s) na ferramenta de origem; confira a justificativa.')
    existing = sum(f.get('disposition') == 'baseline' for f in findings)
    if existing:
        warnings.append(f'{existing} achado(s) já existentes na linha de base; não bloqueiam este scan.')
    auto_missed = [f"{t.get('name', '?')} ({TOOL_STATUS_LABELS.get(t.get('status'), t.get('status'))})"
                   for t in tools if t.get('requested') == 'auto' and t.get('status') not in {'executed', 'imported', 'failed'}]
    if auto_missed:
        warnings.append('Ferramentas automáticas não executadas: '+', '.join(auto_missed)+'.')
    warnings.extend(triage.get('warnings', []))
    exclusions = ['Lógica de negócio, conteúdo das respostas e efeitos colaterais.',
                  'Dependências fora do lock npm raiz, vulnerabilidades não catalogadas e rotas não testadas.',
                  'Controles do checklist sem teste específico, infraestrutura e produção.']
    if triage.get('diff'):
        exclusions.append(f"Código fora das linhas alteradas em relação a {triage['diff'].get('base', '?')} (modo diff).")
    scope = 'Regras estáticas disponíveis, dependências npm no OSV e contratos de status HTTP dos GETs locais explicitamente configurados.'
    external = [f"{t['name']} {t['version']}" if t.get('version') else t.get('name', '?')
                for t in tools if t.get('status') in {'executed', 'imported'}]
    if external:
        scope += ' Ferramentas externas: '+', '.join(external)+'.'
    if failed or blocking:
        status, label = 'rejected', 'REPROVADO — verificações detectaram problemas'
    elif gaps:
        status, label = 'inconclusive', 'INCONCLUSIVO — segurança não demonstrada'
    elif triage.get('diff'):
        status, label = 'passed_diff', 'APROVADO NO DIFF — linhas alteradas sem pendências; não vale como liberação do projeto'
    else:
        status, label = 'passed_scoped', 'APROVADO NO ESCOPO VERIFICADO'
    return dict(status=status, label=label, release_allowed=status == 'passed_scoped',
                scope=scope,
                reasons=gaps, warnings=warnings, failed_cases=failed, review_findings=blockers,
                checks_executed=len(results), checks_passed=sum(r['matched'] for r in results),
                application_security='not_certified',
                exclusions=exclusions)
