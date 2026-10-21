# RepoShield — Plano de ajustes de segurança: performance

Data: 2026-10-21T19:33:35.518041\+00:00 · Motor: 0.9.0

## Veredito

**INCONCLUSIVO — segurança não demonstrada**

Escopo: Regras estáticas disponíveis, dependências npm no OSV e contratos de status HTTP dos GETs locais explicitamente configurados.

Contratos HTTP: 0/0 corresponderam ao esperado.

- Nenhum contrato HTTP foi verificado. Configure runtime e execute com --runtime.
- Auditoria de dependências não concluída. Use --dependencies \(OSV-Scanner se instalado; senão consulta interna npm\).

**Fora da aprovação:**
- Lógica de negócio, conteúdo das respostas e efeitos colaterais.
- Dependências fora do lock npm raiz, vulnerabilidades não catalogadas e rotas não testadas.
- Controles do checklist sem teste específico, infraestrutura e produção.

## Cobertura por tipo de arquivo

- .cs: 1 arquivo(s) lido(s).
- .json: 1 arquivo(s) lido(s).
- .sql: 1 arquivo(s) lido(s).
- Diretórios excluídos sem percorrer conteúdo: 0.
Arquivos lidos não significam cobertura semântica completa. Os arquivos dentro de diretórios excluídos não entram na contagem de ignorados.


## Resumo executivo

- Arquivos analisados: 3; ignorados: 0.
- Achados para investigar: 0.
- Cobertura: análise encerrada dentro dos limites configurados.
- A ausência de achados não aprova a segurança da aplicação.

## Ordem de execução

1. Confirme as evidências e a política esperada antes de alterar o código.
2. Priorize os achados de severidade alta; severidade e confiança são medidas distintas.
3. Aplique cada ajuste em branch e valide com testes de regressão.
4. Revise os controles manuais e execute novamente o RepoShield.

## Ajustes por achado

Nenhum achado pelas regras executadas. Ainda é necessário concluir o checklist manual.

## Checklist complementar de segurança

Nenhum estado deste checklist significa aprovado.

### Login e enumeração

Estado: Validação manual necessária.

- [ ] Validar respostas equivalentes, política de tentativas e reautenticação.

### Armazenamento de senhas

Estado: Validação manual necessária.

- [ ] Verificar hash, custo, política e migração de credenciais.

### Força bruta e abuso

Estado: Validação manual necessária.

- [ ] Testar limites distribuídos por conta, origem e operação.

### MFA e recuperação de segundo fator

Estado: Validação manual necessária.

- [ ] Verificar desafio, expiração, replay e recuperação sem bypass.

### Recuperação de senha

Estado: Validação manual necessária.

- [ ] Testar expiração, uso único e ausência de enumeração.

### JWT, refresh e logout

Estado: Validação manual necessária.

- [ ] Testar assinatura, algoritmo, issuer, audience, expiração e revogação.

### Sessões e cookies

Estado: Validação manual necessária.

- [ ] Validar flags, rotação, fixação e duração absoluta/ociosa.

### Autenticação dos endpoints

Estado: Validação manual necessária.

- [ ] Testar acesso anônimo e credenciais inválidas em todas as rotas restritas.

### Papéis, objetos e tenants

Estado: Validação manual necessária.

- [ ] Testar matriz de papéis e acesso cruzado por objeto/tenant.

### CSRF

Estado: Validação manual necessária.

- [ ] Testar mutações cross-site nos fluxos autenticados por cookies.

### CORS

Estado: Validação manual necessária.

- [ ] Testar origens permitidas, negadas e requisições com credenciais.

### SQL e execução de código

Estado: Validação manual necessária.

- [ ] Rastrear entradas até sinks e validar parametrização.

### Desserialização

Estado: Validação manual necessária.

- [ ] Revisar formato, origem e autenticidade das entradas.

### XSS e saída HTML

Estado: Validação manual necessária.

- [ ] Validar escape contextual, sanitização e política CSP.

### Requisições de saída / SSRF

Estado: Validação manual necessária.

- [ ] Validar destinos, redirects e resolução DNS.

### Upload e acesso a arquivos

Estado: Validação manual necessária.

- [ ] Testar tamanho, tipo real, traversal, armazenamento e propriedade.

### Logs e dados sensíveis

Estado: Validação manual necessária.

- [ ] Verificar redação, auditoria de eventos e acesso aos logs.

### TLS e transporte

Estado: Validação manual necessária.

- [ ] Validar certificados, HTTPS e configuração do proxy.

### Cabeçalhos de segurança

Estado: Validação manual necessária.

- [ ] Inspecionar CSP, HSTS e políticas de conteúdo.

### Segredos e configuração

Estado: Validação manual necessária.

- [ ] Revisar segredos, rotação e diferenças entre ambientes.

### Contrato OpenAPI

Estado: Validação manual necessária.

- [ ] Comparar contrato com implementação, autenticação e escopos.

### Dependências e CVEs

Estado: Validação manual necessária.

- [ ] Executar auditoria com base de CVEs atualizada e revisar alcance.

### Lógica de negócio

Estado: Validação manual necessária.

- [ ] Testar transições, limites, concorrência e operações sensíveis.

### OAuth e OIDC

Estado: Validação manual necessária.

- [ ] Validar state, nonce, PKCE, redirect URI e vínculo com a conta.

## Performance — queries e acesso a dados

Estado: review\_required. Não altera o veredito de segurança.

Análise estática local de C\#/EF, Python, JavaScript/TypeScript e SQL; SQL literal em Java; planos PostgreSQL JSON importados explicitamente.

Arquivos examinados: 2. Cobertura parcial: False.

- Plano postgresql-plan.json: 2 nós; métricas reais fornecidas: True.

### RP001 · HIGH · Consulta dentro de loop: possível N\+1

- Local: Orders.cs:5
- Estado: needs\_measurement · Confiança: medium.

> db.Orders.Where\(order =&gt; order.CustomerId == id\).ToList\(\)

**Impacto provável**

O número de consultas pode crescer com a quantidade de itens, multiplicando viagens ao banco e latência.

**Como investigar e ajustar**

Agrupe as consultas ou use carregamento em lote; preserve filtros por usuário/tenant.

**Como medir e validar**

Em ambiente de teste com dados representativos, conte comandos SQL por requisição, compare p50/p95, linhas/bytes retornados, leituras, CPU e memória antes/depois. Inspecione o plano de execução; o padrão estático não confirma lentidão.


### RP101 · HIGH · Plano PostgreSQL: muitas linhas descartadas em Seq Scan

- Local: postgresql-plan.json:1 · nó 2
- Estado: plan\_observation · Confiança: high.

> nó 2: Seq Scan; linhas/loop=10; loops=1; estimativa/loop=20000; descartadas/loop=50000; blocos temporários escritos=0

**Impacto provável**

O plano fornecido mostra muitas linhas lidas e descartadas; isso pode indicar trabalho evitável em um filtro seletivo.

**Como investigar e ajustar**

Investigue seletividade e índices com o plano completo; Seq Scan pode ser a melhor opção em outros volumes.

**Como medir e validar**

Compare com o SQL e parâmetros originais, versão do banco, volume e concorrência. O plano importado é uma observação fornecida pelo usuário, não uma medição executada pelo RepoShield.


### RP103 · HIGH · Plano PostgreSQL: uso de disco temporário

- Local: postgresql-plan.json:1 · nó 1
- Estado: plan\_observation · Confiança: high.

> nó 1: Sort; linhas/loop=0; loops=0; estimativa/loop=0; descartadas/loop=0; blocos temporários escritos=0

**Impacto provável**

O plano registra uso de armazenamento temporário, que pode adicionar I/O e latência à operação.

**Como investigar e ajustar**

Investigue projeção, ordenação, cardinalidade e memória por operação; não aumente work\_mem globalmente sem medir concorrência.

**Como medir e validar**

Compare com o SQL e parâmetros originais, versão do banco, volume e concorrência. O plano importado é uma observação fornecida pelo usuário, não uma medição executada pelo RepoShield.


### RP003 · MEDIUM · Coleção consultada sem limite aparente

- Local: Orders.cs:5
- Estado: needs\_measurement · Confiança: medium.

> db.Orders.Where\(order =&gt; order.CustomerId == id\).ToList\(\)

**Impacto provável**

O volume carregado pode crescer junto com a tabela e elevar uso de memória, rede e tempo de resposta.

**Como investigar e ajustar**

Avalie projeção e paginação com limite máximo; exportações podem exigir streaming em lotes.

**Como medir e validar**

Em ambiente de teste com dados representativos, conte comandos SQL por requisição, compare p50/p95, linhas/bytes retornados, leituras, CPU e memória antes/depois. Inspecione o plano de execução; o padrão estático não confirma lentidão.


### RP004 · MEDIUM · Consulta síncrona em método async

- Local: Orders.cs:5
- Estado: needs\_measurement · Confiança: medium.

> db.Orders.Where\(order =&gt; order.CustomerId == id\).ToList\(\)

**Impacto provável**

A consulta síncrona pode ocupar a thread enquanto aguarda o banco, limitando concorrência sob carga.

**Como investigar e ajustar**

Use a operação async do provedor e propague CancellationToken quando disponível.

**Como medir e validar**

Em ambiente de teste com dados representativos, conte comandos SQL por requisição, compare p50/p95, linhas/bytes retornados, leituras, CPU e memória antes/depois. Inspecione o plano de execução; o padrão estático não confirma lentidão.


### RP002 · MEDIUM · Materialização antes de filtro ou paginação

- Local: Orders.cs:7
- Estado: needs\_measurement · Confiança: medium.

> db.Orders.ToListAsync\(\)\).Where\(order =&gt; order.Active\).ToList\(\)

**Impacto provável**

Filtrar depois de materializar pode transferir e manter em memória linhas que o banco poderia descartar.

**Como investigar e ajustar**

Mantenha Where/Skip/Take no IQueryable antes de ToList/AsEnumerable; confira o SQL gerado.

**Como medir e validar**

Em ambiente de teste com dados representativos, conte comandos SQL por requisição, compare p50/p95, linhas/bytes retornados, leituras, CPU e memória antes/depois. Inspecione o plano de execução; o padrão estático não confirma lentidão.


### RP003 · MEDIUM · Coleção consultada sem limite aparente

- Local: Orders.cs:7
- Estado: needs\_measurement · Confiança: medium.

> db.Orders.ToListAsync\(\)\).Where\(order =&gt; order.Active\).ToList\(\)

**Impacto provável**

O volume carregado pode crescer junto com a tabela e elevar uso de memória, rede e tempo de resposta.

**Como investigar e ajustar**

Avalie projeção e paginação com limite máximo; exportações podem exigir streaming em lotes.

**Como medir e validar**

Em ambiente de teste com dados representativos, conte comandos SQL por requisição, compare p50/p95, linhas/bytes retornados, leituras, CPU e memória antes/depois. Inspecione o plano de execução; o padrão estático não confirma lentidão.


### RP004 · MEDIUM · Consulta síncrona em método async

- Local: Orders.cs:7
- Estado: needs\_measurement · Confiança: medium.

> db.Orders.ToListAsync\(\)\).Where\(order =&gt; order.Active\).ToList\(\)

**Impacto provável**

A consulta síncrona pode ocupar a thread enquanto aguarda o banco, limitando concorrência sob carga.

**Como investigar e ajustar**

Use a operação async do provedor e propague CancellationToken quando disponível.

**Como medir e validar**

Em ambiente de teste com dados representativos, conte comandos SQL por requisição, compare p50/p95, linhas/bytes retornados, leituras, CPU e memória antes/depois. Inspecione o plano de execução; o padrão estático não confirma lentidão.


### RP102 · MEDIUM · Plano PostgreSQL: estimativa de cardinalidade divergente

- Local: postgresql-plan.json:1 · nó 2
- Estado: plan\_observation · Confiança: high.

> nó 2: Seq Scan; linhas/loop=10; loops=1; estimativa/loop=20000; descartadas/loop=50000; blocos temporários escritos=0

**Impacto provável**

Estimativas divergentes podem levar a escolhas inadequadas de join e memória; precisam ser avaliadas no plano completo.

**Como investigar e ajustar**

Revise estatísticas, distribuição e correlação; compare planos com dados representativos.

**Como medir e validar**

Compare com o SQL e parâmetros originais, versão do banco, volume e concorrência. O plano importado é uma observação fornecida pelo usuário, não uma medição executada pelo RepoShield.


### RP007 · MEDIUM · Função em coluna no filtro SQL

- Local: queries.sql:4
- Estado: needs\_measurement · Confiança: medium.

> WHERE LOWER\(customer\_email

**Impacto provável**

A expressão sobre a coluna pode dificultar o uso de um índice comum; índices de expressão e o otimizador podem mudar esse resultado.

**Como investigar e ajustar**

Confira o plano e considere reescrever o predicado ou um índice de expressão adequado ao banco.

**Como medir e validar**

Em ambiente de teste com dados representativos, conte comandos SQL por requisição, compare p50/p95, linhas/bytes retornados, leituras, CPU e memória antes/depois. Inspecione o plano de execução; o padrão estático não confirma lentidão.


### RP008 · MEDIUM · Busca SQL com curinga inicial

- Local: queries.sql:5
- Estado: needs\_measurement · Confiança: medium.

> LIKE '%…' \(literal omitido\)

**Impacto provável**

O curinga inicial pode impedir uma busca por prefixo em índice comum e exigir examinar muitas linhas.

**Como investigar e ajustar**

Confira volume e plano; avalie busca textual ou índice especializado conforme o banco.

**Como medir e validar**

Em ambiente de teste com dados representativos, conte comandos SQL por requisição, compare p50/p95, linhas/bytes retornados, leituras, CPU e memória antes/depois. Inspecione o plano de execução; o padrão estático não confirma lentidão.


### RP009 · MEDIUM · Paginação SQL com OFFSET elevado

- Local: queries.sql:7
- Estado: needs\_measurement · Confiança: medium.

> OFFSET 50000

**Impacto provável**

Páginas profundas podem exigir percorrer e descartar muitas linhas antes de retornar o resultado.

**Como investigar e ajustar**

Avalie paginação por cursor com ordenação estável; valide consistência e tempo nas páginas finais.

**Como medir e validar**

Em ambiente de teste com dados representativos, conte comandos SQL por requisição, compare p50/p95, linhas/bytes retornados, leituras, CPU e memória antes/depois. Inspecione o plano de execução; o padrão estático não confirma lentidão.


### RP006 · LOW · SELECT \*: revisar projeção

- Local: queries.sql:2
- Estado: needs\_measurement · Confiança: medium.

> SELECT \*

**Impacto provável**

Colunas desnecessárias podem aumentar transferência e materialização; o impacto depende da largura e quantidade das linhas.

**Como investigar e ajustar**

Selecione as colunas necessárias; meça bytes retornados e leituras antes/depois.

**Como medir e validar**

Em ambiente de teste com dados representativos, conte comandos SQL por requisição, compare p50/p95, linhas/bytes retornados, leituras, CPU e memória antes/depois. Inspecione o plano de execução; o padrão estático não confirma lentidão.

### Limites de performance

- Achados estáticos são hipóteses; ausência de achados não comprova boa performance.
- Não conecta ao banco, não executa SQL/EXPLAIN, não aplica índices e não mede p95 ou throughput.
- Não resolve chamadas entre arquivos, aliases de IQueryable, lazy loading implícito ou todos os ORMs. Loops C\#/JS exigem chaves.
- Planos importados podem estar desatualizados; métricas por nó não certificam a latência da aplicação.
- Baseline e supressões de segurança não se aplicam à performance; --diff-base filtra apenas os achados estáticos.


## Limitações da varredura

- Análise heurística; não confirma explorabilidade.
- C\#/.NET: padrões locais em controllers e Minimal APIs; FallbackPolicy com RequireAuthenticatedUser e \[Authorize\] herdado de classe base \(por nome, no projeto\) são resolvidos; não resolve filtros globais, MapGroup ou semântica de policies.
- Python: decorators e herança local de routers. JavaScript: snippets Express heurísticos. OpenAPI: contratos 3.x JSON locais.
- Java/Spring: heurística por anotações, SecurityFilterChain simples e intercept-url; não resolve meta-anotações, SpEL nem herança.
- Não resolve imports, middleware arbitrário ou semântica de guards; ausência de achados não prova segurança.
- Runtime opcional só verifica GETs explícitos locais. OSV opcional limitado ao lock npm raiz; sem brute force ou correção automática.
