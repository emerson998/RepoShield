"""Actionable Markdown remediation plan, independent of optional AI availability."""
import re

REASONS = {
 'secrets':'Credenciais ou configurações expostas podem permitir acesso indevido e revelar detalhes internos da aplicação.',
 'transport':'Sem transporte autenticado e criptografado, dados e credenciais podem ser interceptados ou adulterados.',
 'injection':'Entrada não confiável interpretada como comando, código ou SQL pode alterar a operação pretendida e expor dados.',
 'tokens':'Tokens sem validação adequada podem ser aceitos fora do contexto esperado ou continuar válidos além do período permitido.',
 'authentication':'Uma operação restrita precisa identificar o solicitante no servidor antes de acessar dados ou executar ações.',
 'authorization':'Estar autenticado não concede acesso a todos os objetos, tenants ou ações administrativas.',
 'passwords':'Armazenamento inadequado de senhas aumenta o impacto de vazamentos e facilita ataques offline às credenciais.',
 'sessions':'Cookies de sessão representam a identidade do usuário; atributos e duração inadequados ampliam sua exposição.',
 'csrf':'Quando o navegador envia cookies automaticamente, um site externo pode tentar induzir ações com a sessão da vítima.',
 'cors':'Origens excessivamente permissivas podem permitir que páginas não confiáveis interajam com respostas sensíveis.',
 'serialization':'Alguns formatos de desserialização podem executar instruções ou construir objetos perigosos ao processar dados não confiáveis.',
 'xss':'Conteúdo não confiável renderizado como HTML pode executar scripts no contexto de outro usuário.',
 'logging':'Logs podem replicar dados sensíveis em arquivos, serviços de observabilidade e backups com acesso mais amplo.',
 'recovery':'Recuperação de conta e tokens previsíveis ou reutilizáveis podem permitir que outra pessoa assuma a identidade do usuário.',
 'login':'Diferenças no fluxo de login podem revelar contas existentes e facilitar ataques direcionados.',
 'ssrf':'Uma URL controlada pelo usuário pode induzir o servidor a acessar destinos internos ou serviços que o usuário não deveria alcançar.',
 'files':'Caminhos ou uploads sem restrições podem permitir leitura, gravação ou exposição de arquivos fora do escopo autorizado.',
 'headers':'Cabeçalhos de segurança ajudam o navegador a restringir execução de conteúdo e interpretação indevida das respostas.',
 'rate_limit':'Tentativas ilimitadas facilitam força bruta, credential stuffing e abuso do fluxo de autenticação.',
 'openapi':'Um contrato de autenticação ambíguo ou inválido pode gerar clientes e testes incompatíveis com a política real do serviço.',
}
RULE_REASONS = {
 'RS209':'Tokens em Web Storage podem ser lidos por JavaScript da mesma origem, inclusive em um ataque XSS. Um token fictício em teste não comprova exposição em produção.',
 'RS100':'O analisador não encontrou um guard de autenticação reconhecido nesta rota. Isso exige revisão: middleware ou proteção herdada podem existir fora do alcance do scan.',
 'RS101':'Uma função administrativa deve verificar privilégios além da identidade; sem essa decisão, um usuário comum pode executar ações privilegiadas.',
 'RS102':'Um identificador de objeto pode ser alterado pelo cliente. O servidor deve verificar propriedade, tenant e permissões; esta regra não confirma uma falha IDOR.',
 'RS222':'Login precisa de uma política contra tentativas abusivas. O scan não encontrou um limitador reconhecido no escopo analisado; ele pode existir em outro componente.',
 'RS223':'Recuperação de senha é um caminho alternativo de autenticação. Expiração, uso único e resposta uniforme precisam ser verificados para evitar tomada de conta.',
 'RS224':'Logout e rotação de refresh precisam obedecer à política de invalidação; tokens antigos reutilizáveis podem manter acesso indevido.',
 'RS225':'O contrato OpenAPI declara pelo menos uma alternativa sem credenciais. Isso pode ser intencional; confirme se a rota deveria ser pública.',
 'RS226':'Um requisito que referencia um esquema inexistente não descreve de forma válida como o cliente deve autenticar.',
 'RS300':'O status observado divergiu da política que você declarou para este caso. A divergência pode indicar proteção incorreta, expectativa errada ou outra falha de execução; investigue o corpo e o contexto em teste.',
}
LABELS={'findings':'Achados para investigar','indicator_only':'Indício encontrado; precisa validar','manual_required':'Validação manual necessária'}
TOOL_STATUS_LABELS = {'executed':'executada','not_installed':'não instalada','not_applicable':'não se aplica',
 'skipped_network':'bloqueada: exige consentimento de rede','failed':'falhou','imported':'importada via SARIF'}
TOOL_NETWORK_LABELS = {'none':'nenhuma','rules_download':'baixa regras','db_download':'baixa base','per_query':'consulta por pacote'}

def text(value):
    """Render repository-controlled strings as text, never active HTML or Markdown."""
    value=str(value).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
    return re.sub(r'([\\`*_{}\[\]()#+!|])',r'\\\1',value).replace('\n',' ')

REACH_LABELS = {'production': 'produção', 'dev_only': 'dev/build', 'not_applicable': 'não aplicável', 'conditional': 'condicional (revisar)'}

def dependency_line(v):
    reach = v.get('reachability', 'production')
    line = f"{text(v['package']+'@'+v['version'])} — {text(v['advisory'])} [{text(v.get('severity', 'unknown'))}, {text(REACH_LABELS.get(reach, reach))}]"
    if v.get('condition'): line += ' · ' + text(v['condition'])
    if v.get('fixed_in'): line += ' · corrigido em ' + text(', '.join(v['fixed_in']))
    if v.get('aliases'): line += ' · aliases: ' + text(', '.join(v['aliases']))
    return line

def is_non_blocking(f):
    return f.get('disposition') in {'suppressed', 'baseline'} or bool(f.get('suppressed_by')) or f.get('baseline') == 'existing'

def finding_block(i, f, level):
    heading = '#' * level
    reason=RULE_REASONS.get(f['rule'],REASONS.get(f.get('category'),'Este padrão exige revisão para confirmar se viola a política de segurança da aplicação.'))
    source = f.get('source') or 'reposhield-static'
    origin = f" · Origem: {text(source)}" if source != 'reposhield-static' else ''
    existing = ' (já existente na linha de base)' if f.get('baseline') == 'existing' else ''
    lines = [f"{heading} {i}. {text(f['severity'].upper())} · {text(f['title'])}{existing}", '',
        f"- Regra: {text(f['rule'])} · Referência: {text(f.get('cwe','não informada'))}.",
        f"- Local: {text(f['file'])}, linha {f['line']}.",
        f"- Contexto: {text(f.get('context','não classificado'))}. {text(f.get('context_note',''))}",
        f"- Confiança: {text(f['confidence'])}{origin}."]
    sp = f.get('suppressed_by')
    if sp:
        lines.append(f"- Suprimido por {text(sp.get('author', 'não informado'))} até {text(sp.get('expires', 'sem data'))}: {text(sp.get('justification', ''))}")
    lines += ['', '**O que foi encontrado**', '', '> '+text(f['evidence']), '',
        '**Por que ajustar ou investigar**', '', reason, '',
        '**Como ajustar**', '',
        '1. Localize o trecho indicado e confirme a origem dos dados e as proteções herdadas.',
        '2. '+text(f['recommendation']),
        '3. Preserve os fluxos legítimos e documente exceções intencionais com justificativa.', '',
        '**Como validar**', '', text(f.get('validation','Reproduza em ambiente de teste e confirme o comportamento esperado.')), '',
        '- [ ] Evidência confirmada ou falso positivo justificado.',
        '- [ ] Ajuste aplicado e revisado, quando necessário.',
        '- [ ] Teste de regressão passou e nova análise foi executada.', '']
    return lines

def tools_block(tools):
    if not tools: return []
    out = ['## Ferramentas executadas', '',
        '| Ferramenta | Versão | Eixo | Rede | Situação | Achados | Detalhe |',
        '| --- | --- | --- | --- | --- | --- | --- |']
    for t in tools:
        status = str(t.get('status') or '')
        network = str(t.get('network') or '')
        out.append(f"| {text(t.get('name') or '')} | {text(t.get('version') or 'não informada')} | {text(t.get('axis') or '')} | "
                   f"{text(TOOL_NETWORK_LABELS.get(network, network))} | {text(TOOL_STATUS_LABELS.get(status, status))} | "
                   f"{t.get('findings', 0)} | {text(t.get('detail') or '')} |")
    return out + ['']

def triage_block(triage):
    triage = triage or {}
    suppressed = triage.get('suppressed', 0)
    baseline = triage.get('baseline')
    diff = triage.get('diff')
    warnings = triage.get('warnings') or []
    if not (suppressed or baseline or diff or warnings): return []
    out = ['## Triagem', '', f"Achados suprimidos com justificativa: {suppressed}.", '']
    if baseline:
        out += [f"Linha de base {text(baseline.get('file', ''))}: {baseline.get('new', 0)} novo(s), {baseline.get('existing', 0)} existente(s).", '']
    if diff:
        out += [f"Modo diff em relação a {text(diff.get('base', ''))}: {text(diff.get('note', ''))}", '']
    if warnings:
        out += ['**Avisos de triagem:**', *['- '+text(w) for w in warnings], '']
    return out

def markdown(report):
    findings=report['findings'];coverage=report['coverage']
    pending=[f for f in findings if not is_non_blocking(f)]
    parked=[f for f in findings if is_non_blocking(f)]
    out=[f"# RepoShield — Plano de ajustes de segurança: {text(report['project'])}", '',
        f"Data: {text(report['created_at'])} · Motor: {text(report.get('engine_version','0.1.0'))}", '',
        '## Resumo executivo','',
        f"- Arquivos analisados: {coverage['files']}; ignorados: {coverage['skipped']}.",
        f"- Achados para investigar: {len(pending)}." + (f" Não bloqueantes (suprimidos ou na linha de base): {len(parked)}." if parked else ''),
        f"- Cobertura: {'PARCIAL — consulte erros e limites' if coverage['partial'] else 'análise encerrada dentro dos limites configurados'}.",
        '- A ausência de achados não aprova a segurança da aplicação.', '',
        '## Ordem de execução','',
        '1. Confirme as evidências e a política esperada antes de alterar o código.',
        '2. Priorize os achados de severidade alta; severidade e confiança são medidas distintas.',
        '3. Aplique cada ajuste em branch e valide com testes de regressão.',
        '4. Revise os controles manuais e execute novamente o RepoShield.', '',
        '## Ajustes por achado','']
    coverage_section = ['## Cobertura por tipo de arquivo', '',
        *['- '+text(ext)+': '+str(count)+' arquivo(s) lido(s).' for ext, count in sorted(coverage.get('by_extension', {}).items())],
        *['- Ignorados — '+text(reason)+': '+str(count)+'.' for reason, count in sorted(coverage.get('skipped_reasons', {}).items())],
        '- Diretórios excluídos sem percorrer conteúdo: '+str(coverage.get('excluded_directories', 0))+'.',
        'Arquivos lidos não significam cobertura semântica completa. Os arquivos dentro de diretórios excluídos não entram na contagem de ignorados.', '',
        *['- Código sem suporte: '+text(ext)+' ('+str(count)+' arquivos).' for ext, count in sorted(coverage.get('unsupported_source', {}).items())], '']
    out[4:4] = coverage_section
    head = []
    verdict = report.get('verdict')
    if verdict:
        head += ['## Veredito', '', '**'+text(verdict['label'])+'**', '',
                   'Escopo: '+text(verdict['scope']), '',
                   f"Contratos HTTP: {verdict['checks_passed']}/{verdict['checks_executed']} corresponderam ao esperado.", '',
                   *['- '+text(reason) for reason in verdict['reasons']], '',
                   *(['**Avisos:**', *['- '+text(w) for w in verdict.get('warnings', [])], ''] if verdict.get('warnings') else []),
                   '**Fora da aprovação:**', *['- '+text(reason) for reason in verdict['exclusions']], '']
    head += tools_block(report.get('tools'))
    head += triage_block(report.get('triage'))
    out[4:4] = head
    if not findings: out += ['Nenhum achado pelas regras executadas. Ainda é necessário concluir o checklist manual.','']
    elif not pending: out += ['Nenhum achado pendente; os achados suprimidos ou já existentes estão em "Não bloqueantes".','']
    for i,f in enumerate(pending,1): out += finding_block(i,f,3)
    if parked:
        out += ['### Não bloqueantes','', 'Suprimidos com justificativa ou já existentes na linha de base. Não bloqueiam este scan.','']
        for i,f in enumerate(parked,1): out += finding_block(i,f,4)
    out += ['## Checklist complementar de segurança','', 'Nenhum estado deste checklist significa aprovado.','']
    for c in report.get('controls',[]):
        out += [f"### {text(c['title'])}", '',f"Estado: {LABELS.get(c['status'],text(c['status']))}.", '',
            '- [ ] '+text(c['validation']), '']
    if report.get('runtime'):
        out += ['## Matriz de acesso em execução','',
            '| Caso | Caminho | Identidade | Esperado | Recebido | Resultado |',
            '| --- | --- | --- | --- | --- | --- |']
        for r in report['runtime']['results']:
            out.append(f"| {text(r['case'])} | {text(r['path'])} | {text(r['identity'])} | {text(r['expected'])} | {r['actual']} | {'Corresponde' if r['matched'] else 'Divergente'} |")
        out += ['', 'Correspondência de status não comprova isolamento do corpo ou ausência de efeitos colaterais.','']
    if report.get('dependencies'):
        deps = report['dependencies']
        out += ['## Dependências — OSV', '', 'Estado: '+text(deps.get('status','')), text(deps.get('scope','')),
                f"Pacotes consultados: {deps['packages']}", '',
                *['- '+dependency_line(v) for v in deps['vulnerabilities']],
                *['- '+text(e) for e in deps['errors']],
                *['- Aviso: '+text(w) for w in deps.get('warnings', [])], '']
    if report.get('ai'):
        out += ['## Revisão consultiva por IA','', 'Sugestões adicionais; não substituem a confirmação dos achados.','']
        out += ['> '+text(line) for line in report['ai']['text'].splitlines()]
        out += ['']
    if report.get('errors'):
        out += ['## Etapas incompletas ou erros','', *['- '+text(e) for e in report['errors']], '']
    out += ['## Limitações da varredura','', *['- '+text(x) for x in report['limitations']], '']
    return '\n'.join(out)
