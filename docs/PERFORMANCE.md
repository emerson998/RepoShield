# Análise de performance — RepoShield 0.9

O scan inclui um eixo de performance local, com prioridades independentes de segurança.
Ele procura indícios no código e pode analisar planos PostgreSQL fornecidos em JSON.
Não conecta ao banco, não executa a aplicação, não executa SQL/EXPLAIN, não cria índices
nem afirma que um trecho é lento sem medição.

## Uso

```bash
reposhield scan .
reposhield scan . --format json --output report.json
reposhield scan . --no-performance
reposhield scan . --performance-fail-on high
reposhield scan . --diff-base origin/main --performance-fail-on high
reposhield scan . --query-plan ./plan.json
```

- `--performance-fail-on` é um limiar opcional e separado: `low`, `medium`, `high`.
  Retorna 1 quando uma prioridade igual ou superior aparece. O relatório é salvo antes.
- `--gate` e `--fail-on` continuam considerando apenas segurança.
- Erros na importação de planos retornam 2, com relatório estático preservado.
- Sem limiar de performance, indícios não mudam o código de saída de segurança.
- A análise segue as exclusões e os limites do scanner: 2.000 arquivos, 300 KB/arquivo,
  15 MB por scan. Não segue links simbólicos. SQL usa extensão `.sql`.
- `--no-performance` não pode ser combinado com planos ou limiar de performance.
- A API aceita `performance: true|false` em `POST /api/scans`, padrão `true`.
- O painel tem a aba **Performance**, busca, filtro de prioridade, evidências e validação.
- Planos aceitam caminhos somente na CLI; não há endpoint para ler arquivos arbitrários.

## Catálogo

| Regra | Prioridade | Indício | Limite principal |
|---|---|---|---|
| RP001 | Alta | Consulta em loop C#/EF ou chamada db/session/cursor em loop Python | Não resolve chamadas entre arquivos ou N+1 implícito por lazy loading |
| RP002 | Média | Materialização de consulta EF antes de Where/Skip/Take/OrderBy | Expressões locais, sem rastrear aliases de IQueryable |
| RP003 | Média | ToList/ToArray de fonte EF sem Take aparente | Uma consulta pequena ou exportação pode ser intencional |
| RP004 | Média | Consulta EF síncrona em método async | Precisa confirmar se a fonte é de fato um provedor remoto |
| RP005 | Média | Chamada Async seguida de .Result/.Wait() | Não rastreia variáveis Task |
| RP006 | Baixa | SELECT * em SQL ou literal SQL | Não estima largura das linhas; COUNT(*) não dispara |
| RP007 | Média | Função em coluna após WHERE/AND/OR | Índices funcionais ou otimizações do banco podem resolver o padrão |
| RP008 | Média | LIKE com curinga inicial em literal | Não avalia collation, índices especializados ou seletividade |
| RP009 | Média | OFFSET literal de pelo menos 10.000 | Limiares não substituem plano e volume reais |
| RP010 | Média | requests/time.sleep/subprocess bloqueante em função Python async | Reconhece aliases de imports, sem resolução completa de tipos |
| RP011 | Média | I/O aguardado sequencialmente em loop Python/JS/TS | Sequenciamento pode ser necessário; não recomenda concorrência ilimitada |
| RP101 | Alta | Seq Scan descartando >=10.000 linhas e >=10 vezes as retornadas | Contadores por loop; um Seq Scan sozinho não dispara |
| RP102 | Média | Cardinalidade estimada/real diverge >=10 vezes, uma >=1.000 linhas | Nós nunca executados não disparam |
| RP103 | Alta | Sort em disco ou blocos temporários escritos | Não soma custos pai/filho nem sugere alteração global de memória |
| RP104 | Média | Nó de plano com >=1.000 loops | Repetição pode ser adequada; precisa interpretar nó pai e custos |

As prioridades organizam investigação, não estimam ganho ou severidade de segurança.
O scanner não detecta todas as variações sintáticas. C#/JS exigem loops com chaves;
EF reconhece fontes com nomes `db`, `ctx`, `context` e sufixos `Context`/`Db`.
Comentários e strings comuns não são tratados como código executável. SQL em Java
usa literais simples; SQL dinâmico, stored procedures e ORMs adicionais não têm
resolução semântica nesta versão.

## Planos PostgreSQL: importação offline

Exporte um plano no formato JSON usando seu cliente PostgreSQL e importe o arquivo.
A saída aceita é uma lista com objetos `Plan`, como em `examples/performance/postgresql-plan.json`.
Planos apenas estimados são aceitos e identificados sem métricas reais. Para análise
com linhas e loops reais, forneça um plano já coletado com métricas de execução.

A coleta de `EXPLAIN ANALYZE` executa a consulta: cabe ao operador escolher ambiente,
dados e operações apropriados. O RepoShield somente lê o JSON pronto.

Limites por arquivo: 5 MB e 20.000 nós. JSON inválido, métrica inválida, link simbólico
ou limite excedido produzem erro no eixo de performance. O relatório não copia texto
da query, filtros, parâmetros, nomes de tabelas ou credenciais do plano; preserva
somente o nome do arquivo, ordinal de nó e os contadores necessários à evidência.

Não há importação de planos SQL Server/MySQL nesta versão. Não há auditoria de
índices ausentes, duplicados ou não usados sem metadados adicionais do banco.

## Relatório e integração

JSON: `report.performance` tem `enabled`, `status`, `findings`, `summary`, `coverage`,
`plans`, `errors`, `scope` e `limitations`. Estados: `disabled`, `partial`,
`review_required`, `not_applicable` ou `no_indicators`.

Cada achado tem `priority`, `confidence`, `status`, arquivo, linha, evidência,
impacto provável, recomendação e validação. `needs_measurement` significa hipótese estática;
`plan_observation` significa observação de um arquivo importado, sem comprovar a
latência total da aplicação. `plan_node` identifica o nó; a linha 1 nesses achados
é convencional e não representa localização exata no JSON.

Markdown inclui seção própria. SARIF mantém o eixo em `runs[].properties.performance`,
sem publicar as heurísticas como vulnerabilidades em `results`. O histórico SQLite
preserva o relatório completo. A IA opcional recebe também os indícios de performance
redigidos dentro do orçamento compartilhado de 80 achados e 48.000 caracteres;
segurança tem prioridade. O consentimento de IA continua obrigatório.

O modo diff filtra os achados estáticos de performance por linhas alteradas; planos
explicitamente importados permanecem integrais. Baseline e supressões de segurança
não removem indícios de performance nesta versão. Arquivos de teste são identificados
como contexto de teste, sem esconder os indícios automaticamente.

## Protocolo de validação

1. Confirme a origem da consulta, os parâmetros e a necessidade do fluxo.
2. Reproduza em ambiente de teste com volume, distribuição e concorrência representativos.
3. Registre quantidade de queries por requisição, p50/p95, leituras, linhas e bytes retornados,
   CPU e memória. Esses indicadores precisam ser coletados por instrumentação externa.
4. Avalie o plano e escolha uma alteração por vez: projeção, lote, paginação, filtro ou índice.
5. Compare antes/depois e preserve autorização por objeto/tenant e correção funcional.

## Exemplo reproduzível

```bash
reposhield scan examples/performance \
  --query-plan examples/performance/postgresql-plan.json \
  --format markdown --output .reposhield/performance-demo.md
```

As fixtures são sintéticas e não devem ser executadas como aplicação de produção.
