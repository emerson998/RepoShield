# Roteiro de revisão de uma aplicação nova

Execute com dados sintéticos. Documente evidência, responsável, decisão e teste
de regressão. Revise arquitetura e políticas antes de interpretar achados.

## Login e enumeração

Validar respostas equivalentes, política de tentativas e reautenticação.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## Armazenamento de senhas

Verificar hash, custo, política e migração de credenciais.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## Força bruta e abuso

Testar limites distribuídos por conta, origem e operação.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## MFA e recuperação de segundo fator

Verificar desafio, expiração, replay e recuperação sem bypass.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## Recuperação de senha

Testar expiração, uso único e ausência de enumeração.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## JWT, refresh e logout

Testar assinatura, algoritmo, issuer, audience, expiração e revogação.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## Sessões e cookies

Validar flags, rotação, fixação e duração absoluta/ociosa.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## Autenticação dos endpoints

Testar acesso anônimo e credenciais inválidas em todas as rotas restritas.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## Papéis, objetos e tenants

Testar matriz de papéis e acesso cruzado por objeto/tenant.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## CSRF

Testar mutações cross-site nos fluxos autenticados por cookies.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## CORS

Testar origens permitidas, negadas e requisições com credenciais.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## SQL e execução de código

Rastrear entradas até sinks e validar parametrização.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## Desserialização

Revisar formato, origem e autenticidade das entradas.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## XSS e saída HTML

Validar escape contextual, sanitização e política CSP.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## Requisições de saída / SSRF

Validar destinos, redirects e resolução DNS.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## Upload e acesso a arquivos

Testar tamanho, tipo real, traversal, armazenamento e propriedade.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## Logs e dados sensíveis

Verificar redação, auditoria de eventos e acesso aos logs.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## TLS e transporte

Validar certificados, HTTPS e configuração do proxy.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## Cabeçalhos de segurança

Inspecionar CSP, HSTS e políticas de conteúdo.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## Segredos e configuração

Revisar segredos, rotação e diferenças entre ambientes.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## Contrato OpenAPI

Comparar contrato com implementação, autenticação e escopos.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## Dependências e CVEs

Executar auditoria com base de CVEs atualizada e revisar alcance.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## Lógica de negócio

Testar transições, limites, concorrência e operações sensíveis.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## OAuth e OIDC

Validar state, nonce, PKCE, redirect URI e vínculo com a conta.

- [ ] Evidência examinada e comportamento testado.
- [ ] Política e exceções documentadas.
- [ ] Teste de regressão adicionado quando aplicável.

## Limites de automação

Scans não comprovam segurança. MFA, OAuth, isolamento multitenant e lógica de negócio
exigem cenários específicos. Auditoria de dependências exige uma base de CVEs atualizada.
Antes de produção, valide infraestrutura, segredos, observabilidade, recuperação e revisão humana.
