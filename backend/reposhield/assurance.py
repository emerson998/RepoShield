"""Deterministic release gate. Never interpret absence of findings as safety."""
from pathlib import PurePosixPath
import re


def classify(findings):
    for item in findings:
        path = PurePosixPath(item['file'])
        test = bool(set(path.parts) & {'tests', 'test', '__tests__', '__mocks__', 'fixtures'}) or bool(
            re.search(r'(?:\.(?:spec|test)\.[^.]+$|^test_.*\.py$|_test\.py$)', path.name))
        item['context'] = 'test' if test else 'production_or_unknown'
        # Keep all evidence, especially possible real secrets in test files.
        item['disposition'] = 'review_required'
        if test and item['rule'] == 'RS209':
            item['disposition'] = 'test_context'
            item['context_note'] = 'Armazenamento em teste; não comprova exposição em produção. Confira o serviço utilizado pelo teste.'


def evaluate(report):
    findings = report['findings']
    blockers = [f['id'] for f in findings if f.get('disposition') != 'test_context']
    runtime = report.get('runtime') or {}
    results = runtime.get('results', [])
    failed = [r['case'] for r in results if not r['matched']]
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
    deps = report.get('dependencies') or {}
    if deps.get('status') not in {'passed', 'failed'}:
        gaps.append('Auditoria de dependências não concluída. Use --dependencies para consultar versões npm no OSV.')
    if deps.get('status') == 'failed':
        gaps.append(f"{len(deps['vulnerabilities'])} correspondência(s) com advisories OSV; revise alcance e atualização.")
    if failed or deps.get('status') == 'failed':
        status, label = 'rejected', 'REPROVADO — verificações detectaram problemas'
    elif gaps:
        status, label = 'inconclusive', 'INCONCLUSIVO — segurança não demonstrada'
    else:
        status, label = 'passed_scoped', 'APROVADO NO ESCOPO VERIFICADO'
    return dict(status=status, label=label, release_allowed=status == 'passed_scoped',
                scope='Regras estáticas disponíveis, dependências npm no OSV e contratos de status HTTP dos GETs locais explicitamente configurados.',
                reasons=gaps, failed_cases=failed, review_findings=blockers,
                checks_executed=len(results), checks_passed=sum(r['matched'] for r in results),
                application_security='not_certified',
                exclusions=['Lógica de negócio, conteúdo das respostas e efeitos colaterais.',
                            'Dependências fora do lock npm raiz, vulnerabilidades não catalogadas e rotas não testadas.',
                            'Controles do checklist sem teste específico, infraestrutura e produção.'])
