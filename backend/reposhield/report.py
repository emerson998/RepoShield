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

def text(value):
    """Render repository-controlled strings as text, never active HTML or Markdown."""
    value=str(value).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
    return re.sub(r'([\\`*_{}\[\]()#+!|])',r'\\\1',value).replace('\n',' ')

def markdown(report):
    findings=report['findings'];coverage=report['coverage']
    out=[f"# RepoShield — Plano de ajustes de segurança: {text(report['project'])}", '',
        f"Data: {text(report['created_at'])} · Motor: {text(report.get('engine_version','0.1.0'))}", '',
        '## Resumo executivo','',
        f"- Arquivos analisados: {coverage['files']}; ignorados: {coverage['skipped']}.",
        f"- Achados para investigar: {len(findings)}.",
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
    verdict = report.get('verdict')
    if verdict:
        section = ['## Veredito', '', '**'+text(verdict['label'])+'**', '',
                   'Escopo: '+text(verdict['scope']), '',
                   f"Contratos HTTP: {verdict['checks_passed']}/{verdict['checks_executed']} corresponderam ao esperado.", '',
                   *['- '+text(reason) for reason in verdict['reasons']], '',
                   '**Fora da aprovação:**', *['- '+text(reason) for reason in verdict['exclusions']], '']
        out[4:4] = section
    if not findings: out += ['Nenhum achado pelas regras executadas. Ainda é necessário concluir o checklist manual.','']
    for i,f in enumerate(findings,1):
        reason=RULE_REASONS.get(f['rule'],REASONS.get(f.get('category'),'Este padrão exige revisão para confirmar se viola a política de segurança da aplicação.'))
        out += [f"### {i}. {text(f['severity'].upper())} · {text(f['title'])}", '',
            f"- Regra: {text(f['rule'])} · Referência: {text(f.get('cwe','não informada'))}.",
            f"- Local: {text(f['file'])}, linha {f['line']}.",
            f"- Contexto: {text(f.get('context','não classificado'))}. {text(f.get('context_note',''))}",
            f"- Confiança: {text(f['confidence'])} · Origem: {text(f['source'])}.",
            '', '**O que foi encontrado**', '', '> '+text(f['evidence']), '',
            '**Por que ajustar ou investigar**', '', reason, '',
            '**Como ajustar**', '',
            '1. Localize o trecho indicado e confirme a origem dos dados e as proteções herdadas.',
            '2. '+text(f['recommendation']),
            '3. Preserve os fluxos legítimos e documente exceções intencionais com justificativa.', '',
            '**Como validar**', '', text(f.get('validation','Reproduza em ambiente de teste e confirme o comportamento esperado.')), '',
            '- [ ] Evidência confirmada ou falso positivo justificado.',
            '- [ ] Ajuste aplicado e revisado, quando necessário.',
            '- [ ] Teste de regressão passou e nova análise foi executada.', '']
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
        out += ['## Dependências npm — OSV', '', 'Estado: '+text(deps['status']), text(deps['scope']),
                f"Pacotes consultados: {deps['packages']}", '',
                *['- '+text(v['package']+'@'+v['version']+' — '+v['advisory']) for v in deps['vulnerabilities']],
                *['- '+text(e) for e in deps['errors']], '']
    if report.get('ai'):
        out += ['## Revisão consultiva por IA','', 'Sugestões adicionais; não substituem a confirmação dos achados.','']
        out += ['> '+text(line) for line in report['ai']['text'].splitlines()]
        out += ['']
    if report.get('errors'):
        out += ['## Etapas incompletas ou erros','', *['- '+text(e) for e in report['errors']], '']
    out += ['## Limitações da varredura','', *['- '+text(x) for x in report['limitations']], '']
    return '\n'.join(out)

