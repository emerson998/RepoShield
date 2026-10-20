# RepoShield — Plano de ajustes de segurança: examples

Data: 2026-10-20T23:44:11.646797\+00:00 · Motor: 0.2.0

## Resumo executivo

- Arquivos analisados: 1; ignorados: 0.
- Achados para investigar: 6.
- Cobertura: análise encerrada dentro dos limites configurados.
- A ausência de achados não aprova a segurança da aplicação.

## Ordem de execução

1. Confirme as evidências e a política esperada antes de alterar o código.
2. Priorize os achados de severidade alta; severidade e confiança são medidas distintas.
3. Aplique cada ajuste em branch e valide com testes de regressão.
4. Revise os controles manuais e execute novamente o RepoShield.

## Ajustes por achado

### 1. HIGH · Rota administrativa sem autorização aparente

- Regra: RS101 · Referência: CWE-862.
- Local: vulnerable\_app.py, linha 10.
- Confiança: low · Origem: reposhield-static.

**O que foi encontrado**

> DELETE /admin/users/\{user\_id\}

**Por que ajustar ou investigar**

Uma função administrativa deve verificar privilégios além da identidade; sem essa decisão, um usuário comum pode executar ações privilegiadas.

**Como ajustar**

1. Localize o trecho indicado e confirme a origem dos dados e as proteções herdadas.
2. Exija uma política de autorização no servidor e teste com usuário sem privilégio.
3. Preserve os fluxos legítimos e documente exceções intencionais com justificativa.

**Como validar**

Confirme o fluxo em ambiente de teste e adicione um teste de regressão.

- [ ] Evidência confirmada ou falso positivo justificado.
- [ ] Ajuste aplicado e revisado, quando necessário.
- [ ] Teste de regressão passou e nova análise foi executada.

### 2. MEDIUM · Modo debug habilitado

- Regra: RS004 · Referência: CWE-489.
- Local: vulnerable\_app.py, linha 3.
- Confiança: medium · Origem: reposhield-static.

**O que foi encontrado**

> app=FastAPI\(debug=True\)

**Por que ajustar ou investigar**

Credenciais ou configurações expostas podem permitir acesso indevido e revelar detalhes internos da aplicação.

**Como ajustar**

1. Localize o trecho indicado e confirme a origem dos dados e as proteções herdadas.
2. Desative debug em produção e configure por ambiente.
3. Preserve os fluxos legítimos e documente exceções intencionais com justificativa.

**Como validar**

Confirme o fluxo em ambiente de teste e adicione um teste de regressão.

- [ ] Evidência confirmada ou falso positivo justificado.
- [ ] Ajuste aplicado e revisado, quando necessário.
- [ ] Teste de regressão passou e nova análise foi executada.

### 3. MEDIUM · Autenticação do endpoint precisa de revisão

- Regra: RS100 · Referência: CWE-306.
- Local: vulnerable\_app.py, linha 7.
- Confiança: low · Origem: reposhield-static.

**O que foi encontrado**

> GET /orders/\{order\_id\}

**Por que ajustar ou investigar**

O analisador não encontrou um guard de autenticação reconhecido nesta rota. Isso exige revisão: middleware ou proteção herdada podem existir fora do alcance do scan.

**Como ajustar**

1. Localize o trecho indicado e confirme a origem dos dados e as proteções herdadas.
2. Verifique proteção global, do router e da rota. Declare rotas públicas na configuração.
3. Preserve os fluxos legítimos e documente exceções intencionais com justificativa.

**Como validar**

Confirme o fluxo em ambiente de teste e adicione um teste de regressão.

- [ ] Evidência confirmada ou falso positivo justificado.
- [ ] Ajuste aplicado e revisado, quando necessário.
- [ ] Teste de regressão passou e nova análise foi executada.

### 4. MEDIUM · Revisar autorização por objeto

- Regra: RS102 · Referência: CWE-639.
- Local: vulnerable\_app.py, linha 7.
- Confiança: low · Origem: reposhield-static.

**O que foi encontrado**

> GET /orders/\{order\_id\}

**Por que ajustar ou investigar**

Um identificador de objeto pode ser alterado pelo cliente. O servidor deve verificar propriedade, tenant e permissões; esta regra não confirma uma falha IDOR.

**Como ajustar**

1. Localize o trecho indicado e confirme a origem dos dados e as proteções herdadas.
2. Confirme propriedade/tenant do recurso e teste acesso cruzado entre usuários.
3. Preserve os fluxos legítimos e documente exceções intencionais com justificativa.

**Como validar**

Confirme o fluxo em ambiente de teste e adicione um teste de regressão.

- [ ] Evidência confirmada ou falso positivo justificado.
- [ ] Ajuste aplicado e revisado, quando necessário.
- [ ] Teste de regressão passou e nova análise foi executada.

### 5. MEDIUM · Autenticação do endpoint precisa de revisão

- Regra: RS100 · Referência: CWE-306.
- Local: vulnerable\_app.py, linha 10.
- Confiança: low · Origem: reposhield-static.

**O que foi encontrado**

> DELETE /admin/users/\{user\_id\}

**Por que ajustar ou investigar**

O analisador não encontrou um guard de autenticação reconhecido nesta rota. Isso exige revisão: middleware ou proteção herdada podem existir fora do alcance do scan.

**Como ajustar**

1. Localize o trecho indicado e confirme a origem dos dados e as proteções herdadas.
2. Verifique proteção global, do router e da rota. Declare rotas públicas na configuração.
3. Preserve os fluxos legítimos e documente exceções intencionais com justificativa.

**Como validar**

Confirme o fluxo em ambiente de teste e adicione um teste de regressão.

- [ ] Evidência confirmada ou falso positivo justificado.
- [ ] Ajuste aplicado e revisado, quando necessário.
- [ ] Teste de regressão passou e nova análise foi executada.

### 6. MEDIUM · Revisar autorização por objeto

- Regra: RS102 · Referência: CWE-639.
- Local: vulnerable\_app.py, linha 10.
- Confiança: low · Origem: reposhield-static.

**O que foi encontrado**

> DELETE /admin/users/\{user\_id\}

**Por que ajustar ou investigar**

Um identificador de objeto pode ser alterado pelo cliente. O servidor deve verificar propriedade, tenant e permissões; esta regra não confirma uma falha IDOR.

**Como ajustar**

1. Localize o trecho indicado e confirme a origem dos dados e as proteções herdadas.
2. Confirme propriedade/tenant do recurso e teste acesso cruzado entre usuários.
3. Preserve os fluxos legítimos e documente exceções intencionais com justificativa.

**Como validar**

Confirme o fluxo em ambiente de teste e adicione um teste de regressão.

- [ ] Evidência confirmada ou falso positivo justificado.
- [ ] Ajuste aplicado e revisado, quando necessário.
- [ ] Teste de regressão passou e nova análise foi executada.

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

Estado: Achados para investigar.

- [ ] Testar acesso anônimo e credenciais inválidas em todas as rotas restritas.

### Papéis, objetos e tenants

Estado: Achados para investigar.

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

Estado: Achados para investigar.

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

## Limitações da varredura

- Análise heurística; não confirma explorabilidade.
- Python: decorators e herança local de routers. JavaScript: snippets Express heurísticos. OpenAPI: contratos 3.x JSON locais.
- Não resolve imports, middleware arbitrário ou semântica de guards; ausência de achados não prova segurança.
- Runtime opcional só verifica GETs explícitos locais. Sem auditoria de CVEs, brute force ou correção automática.
