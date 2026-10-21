# 🛡️ RepoShield

**Segurança começa no código.** Workspace local de triagem de segurança com React,
FastAPI e CLI. Inventaria endpoints, procura padrões de risco e oferece revisão
consultiva opcional com **Claude CLI ou Codex CLI**.

> Versão 0.4.0 · Auditoria assistida de segurança. Resultados são hipóteses com evidências, não
> vulnerabilidades confirmadas. Não substitui revisão humana ou testes de segurança.

## Um comando → plano de ajustes em Markdown

Com o RepoShield instalado, execute na raiz da aplicação:

```bash
reposhield scan .
```

O comando executa todas as regras estáticas disponíveis e salva automaticamente
**`.reposhield/security-review.md`** dentro do projeto analisado. Não precisa abrir
a interface. Cada achado informa arquivo/linha, severidade, confiança, evidência,
**por que ajustar**, **como ajustar** e **como validar**. Também inclui prioridades,
checklist manual, erros e limites da cobertura. O arquivo é atualizado a cada scan;
use `--output` se quiser manter relatórios separados.

Para complementar o mesmo relatório com o CLI de IA escolhido:

```bash
reposhield scan . --provider claude --consent
# ou
reposhield scan . --provider codex --consent
```

Para incluir a matriz local já configurada, adicione `--runtime`. Sem esse flag,
não há requisições HTTP. A varredura executa todos os detectores disponíveis para
os arquivos suportados, mas não constitui uma auditoria completa de toda stack.
Controles não verificáveis automaticamente são explicitados no checklist.

```bash
reposhield scan ./minha-api --output ./relatorios/seguranca.md
reposhield scan . --stdout  # saída no terminal, sem arquivo automático
```

Se a IA falhar, o relatório estático ainda é salvo, registra a etapa incompleta e
o comando retorna código 2. Achados que atingem `--fail-on` também preservam o
arquivo antes de retornar código 1. Um exemplo está em [docs/EXAMPLE_REPORT.md](docs/EXAMPLE_REPORT.md).

## Começar

Requisitos: Python 3.11+, Node.js 22+ e npm. Os CLIs de IA são opcionais.
Execute os comandos na raiz do projeto:

```bash
python -m venv .venv
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e './backend[dev]'
cd frontend
npm ci
npm run build
cd ..
reposhield serve --root /caminho/para/seus/projetos
```

Abra **http://127.0.0.1:8765** e cole o token mostrado no terminal. Informe o caminho
relativo do projeto dentro da raiz permitida. Exemplo: raiz `/home/dev` e projeto
`./minha-api`. O backend serve o build React; não há serviço remoto.

Para experimentar a fixture insegura: `reposhield serve --root .` e analise
`./examples`. Não publique ou execute essa fixture como serviço.

## Funcionalidades disponíveis

- Interface responsiva com filtros de severidade e busca por regra/arquivo.
- Evidências com localização, confiança e recomendação.
- Inventário FastAPI/Flask por AST, herança local de dependências/prefixos, Express por padrões e OpenAPI 3 JSON.
- Revisão de autenticação aparente, rotas administrativas e autorização por objeto.
- 46 regras: senhas, JWT, cookies, login, recuperação, injeções, SSRF, arquivos, CORS e outros.
- Histórico local em SQLite e exportações JSON, Markdown e SARIF 2.1.0.
- Jobs em background, uma análise por vez e revisão opcional por IA.
- Exclusões, `.gitignore`, limites de arquivos, tamanho e bytes.
- Token local, validação de Host/Origin, restrição de raiz e descarte de symlinks.

## Terminal e CI

```bash
reposhield scan ./examples
reposhield scan ./minha-api --format json --output report.json
reposhield scan ./minha-api --format sarif --output report.sarif --fail-on high
reposhield scan ./minha-api --provider claude --consent --format json
reposhield scan ./minha-api --provider codex --consent --format json
```

Códigos de saída: `0` análise finalizada; `1` atingiu o limiar `--fail-on`; `2` erro;
`3` cobertura parcial sem limiar atingido. O limiar considera somente regras locais,
nunca interpreta a resposta livre da IA. A CLI sem provedor não precisa de login.

## Claude CLI e Codex CLI

Instale e autentique o CLI desejado conforme a documentação oficial: [Claude Code](https://code.claude.com/docs/en/cli-reference) ou [Codex CLI](https://developers.openai.com/codex/cli/reference/). Confirme
`claude --help` ou `codex --help` na mesma sessão onde iniciará o RepoShield.
O painel detecta os executáveis pelo PATH; o login é feito no terminal, fora do app.

A integração usa `claude -p` com ferramentas desabilitadas ou `codex exec` com
sandbox read-only. O processo roda em diretório temporário, sem montar o projeto.
São enviados até 80 achados redigidos, com um orçamento de 48.000 caracteres,
para gerar recomendações em português. Não recebe o código inteiro, não confirma
explorabilidade e não aplica patches. Timeout: 180 segundos. CLI inexistente,
erro de autenticação ou incompatibilidade de versão aparecem no relatório da web;
a análise estática continua disponível. A CLI salva o relatório local antes de encerrar com erro se a revisão falhar.

A redação reduz exposição de segredos reconhecidos, mas não garante anonimização.
Os CLIs podem usar serviços externos e configurações locais. A seleção exige
consentimento explícito. Com `none`, nenhum CLI é invocado.

## Configuração do projeto analisado

Crie `.reposhield.json` **no projeto alvo**:

```json
{
  "public_routes": ["/health", "/login"],
  "exclude": ["tests/", "examples/", "**/*.min.js"]
}
```

Rotas públicas são declaradas pelo path do decorator, antes de prefixos de router na versão 0.1; na versão 0.2, use o path resolvido (quando houver herança local).
A lista substitui os padrões `/health` e `/healthz`. `.gitignore` raiz é respeitado;
arquivos de ignore aninhados ainda não são processados.

Variáveis: `REPOSHIELD_ROOT` (raiz permitida da API), `REPOSHIELD_TOKEN` (token de
sessão), `REPOSHIELD_DB` (caminho do SQLite; padrão `~/.reposhield/history.db`).
`serve --root` define a raiz e gera um token se nenhum foi configurado.

## Autenticação de endpoints: o que os resultados significam

| Estado | Significado |
| --- | --- |
| `public_declared` | Rota declarada pública na configuração |
| `hint_found` | Encontrado indício sintático; não comprova proteção efetiva |
| `unknown` | Proteção não resolvida; exige investigação |

`Depends` pode executar algo que não autentica ninguém. Middleware e dependências
no app/router podem proteger uma rota sem aparecer na função. As regras RS100,
RS101 e RS102 têm confiança baixa por esse motivo. RS102 marca revisão de
propriedade/tenant, sem afirmar que existe IDOR. Prefixos e dependências de app/router são reconstruídos quando a definição e montagem estão no mesmo arquivo. Imports e middleware arbitrário não são resolvidos. Express recebe indícios de guards em snippets limitados. Requisições aos endpoints só ocorrem com runtime ativado explicitamente.

## Arquitetura

```text
frontend/                 React + Vite + lucide-react
backend/reposhield/
  scanner.py              Motor e exportação compartilhados
  audit.py                Regras e checklist de 24 áreas
  routes.py               Extração e herança de endpoints
  runtime.py              Matriz GET local opt-in
  api.py                  API local e jobs em background
  cli.py                  Terminal, exportação e limiares de CI
  providers.py            Adaptadores CLI para revisão consultiva
  store.py                Histórico SQLite
backend/tests/            Casos de scanner, API e adaptadores
examples/                 Fixture sintética de demonstração
```

API protegida: `GET /api/settings`, `GET/POST /api/scans`,
`GET /api/scans/{id}`, `GET /api/scans/{id}/export?format=json|sarif|markdown`.
Envie o header `X-RepoShield-Token`. A API não habilita CORS amplo.
O endpoint público `/api/health` retorna somente estado.

## Desenvolvimento e validação

```bash
pip install -e './backend[dev]'
pytest backend/tests -q
reposhield serve --root .
# Em outro terminal:
cd frontend
npm ci
npm run dev
```

Vite usa proxy para a API na porta 8765. O painel está em http://127.0.0.1:5173.
Após mudar o frontend de produção, rode novamente `npm run build` e reinicie a API.
O workflow de CI executa testes do backend, build do frontend e gera SARIF da fixture.

## Limites e roadmap

Limites atuais: 2.000 arquivos, 300 KB por arquivo e 15 MB de conteúdo por análise.
Falhas de parse/leitura e limites atingidos geram cobertura parcial. Arquivos
binários, diretórios de build, dependências e links simbólicos são excluídos.
O histórico lista as 50 análises mais recentes; não há política de retenção automática.
A API é uma ferramenta pessoal local, não um serviço multiusuário.

Próximas entregas: integração com Semgrep/Gitleaks e auditoria de dependências de outros ecossistemas,
resolução entre arquivos e middleware, falsos positivos com justificativa, comparação
de scans, testes dinâmicos de mutações e correções em branches com diffs revisáveis.
Os itens deste roadmap **não estão implementados nesta versão**; há runtime GET local e resolução local de routers disponíveis. Não há score de segurança
artificial ou promessa de detectar todas as vulnerabilidades.

## Contribuir e licença

Veja [CONTRIBUTING.md](CONTRIBUTING.md) e [SECURITY.md](SECURITY.md).
Licença [MIT](LICENSE).


## Auditoria de aplicação nova (v0.2)

1. Execute o scan estático antes de conectar a aplicação a dados reais.
2. Declare rotas públicas intencionais. Login público ainda recebe verificações de abuso.
3. Investigue os achados por severidade, evidência, CWE e orientação de validação.
4. Abra o **Checklist**: 24 áreas incluem MFA, OAuth, sessões, autorização por objeto,
   tenant, recuperação, logs, arquivos e lógica de negócio.
5. Use uma instância local com dados sintéticos para verificar o contrato de acesso.
6. Faça revisão manual e testes específicos nas áreas sem evidência automatizada.

Estados do checklist: `findings` (achados), `indicator_only` (indício sintático) e
`manual_required` (exige revisão). Nenhum significa aprovado. A cobertura de regras
não é certificação OWASP nem uma contagem de vulnerabilidades confirmadas.

### Matriz de acesso em runtime — ativação explícita

Configure `.reposhield.json` no projeto alvo (copie apenas os casos relevantes):

```json
{
  "public_routes": ["/health", "/login"],
  "runtime": {
    "base_url": "http://127.0.0.1:8000",
    "cases": [
      {"path": "/health", "expected_status": [200]},
      {"path": "/admin/users", "expected_status": [401, 403]},
      {"path": "/admin/users", "token_env": "REPOSHIELD_TEST_USER", "expected_status": [403]},
      {"path": "/admin/users", "token_env": "REPOSHIELD_TEST_ADMIN", "expected_status": [200]},
      {"path": "/orders/other-user-order", "token_env": "REPOSHIELD_TEST_USER", "expected_status": [403, 404]}
    ]
  }
}
```

Os identificadores de objetos devem existir e pertencer às contas sintéticas
apropriadas. Um 404 não comprova autorização se o objeto não existir. Declare os
status esperados conforme sua política. Tokens vêm exclusivamente de variáveis
`REPOSHIELD_TEST_*` definidas antes de iniciar o app; nunca os salve no JSON.

```bash
# Defina os tokens sintéticos no ambiente da sua sessão sem incluí-los no repositório.
reposhield scan ./minha-api --runtime --format json --output report.json
# Ou ative "Autorizar GETs locais" na interface antes do scan.
```

Sem `--runtime` ou o checkbox, nenhuma requisição é feita. O plano aceita de 1 a
20 GETs com IP literal de loopback, timeout de 5 segundos por caso, sem redirects
ou armazenamento de corpo. Não aponte para GETs com efeitos colaterais. Apenas
Bearer tokens são suportados nessa versão. São comparados status e atributos de
cabeçalhos/cookies; não há login automático, força bruta ou criação de contas.

As verificações de CSP aplicam-se a HTML. Cookies sem flags geram revisão, pois um
cookie pode não autenticar sessão e Secure depende do ambiente HTTPS. Redirecionar
para login pode ser correto para uma página, mas não para uma API; configure o
contrato esperado. O relatório registra a divergência, sem inferir automaticamente
que dados protegidos foram expostos.

### Catálogo e referências

Veja [docs/RULES.md](docs/RULES.md) para todas as regras e
[docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) para o roteiro de validação.
O catálogo usa CWE e recomendações inspiradas nas fontes primárias:

- [OWASP API Security Top 10](https://api-security.owasp.org/editions/2023/en/0x11-t10/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

Essas referências organizam a revisão, sem alegação de cobertura integral dos padrões.


## Veredito e bloqueio de entrega (v0.3)

O relatório, JSON e painel exibem uma decisão determinística, independente da IA:

| Veredito | Critério | `--gate` |
| --- | --- | --- |
| REPROVADO | Divergência de contrato HTTP ou versão npm associada a advisory OSV | 1 |
| INCONCLUSIVO | Achados pendentes, erros, ausência de runtime/dependências ou nenhuma análise de arquivo | 3 |
| APROVADO NO ESCOPO VERIFICADO | Contratos configurados correspondem, OSV concluído sem advisories e nenhuma pendência estática | 0 |

A aprovação NÃO certifica segurança global ou produção. A ferramenta não conhece a política de negócio
nem comprova isolamento do corpo das respostas. O checklist de 24 áreas continua indicando o trabalho
fora desse escopo. Não declare apenas `/health` e interprete sua aprovação como teste de autenticação.
Achados estáticos continuam hipóteses: bloqueiam aprovação como INCONCLUSIVO, sem inventar explorabilidade.

Na raiz do frontend npm (com package-lock v2/v3), execute:

```bash
reposhield scan . --dependencies --runtime --gate
```

Antes, inicie a aplicação local e configure `runtime.base_url` e `runtime.cases` conforme a seção de
matriz de acesso acima: caso anônimo negado, usuário comum negado para administração, administrador
permitido, acesso cruzado negado e acesso legítimo permitido. Defina os recursos e políticas reais;
a ferramenta não inventa contas ou executa o servidor automaticamente.

`--dependencies` autoriza enviar **nomes e versões**, inclusive pacotes privados presentes no lock,
à API pública OSV por HTTPS. Não envia código, não instala pacotes e não executa scripts npm.
Inclui dependências de desenvolvimento e transitivas listadas no lock raiz; não varre outros locks.
Limites: 5 MB por lock, 1000 pares únicos, lotes de 100 e timeout de 20 segundos por lote.
Lock ausente/antigo, workspace, versão não exata, erro de rede, resposta inválida ou paginação deixam
esta etapa incompleta. Uma correspondência de advisory exige avaliar alcance e atualizar a dependência;
não é prova de que a aplicação é explorável. Referência: https://google.github.io/osv.dev/post-v1-querybatch/.

Sem as opções de rede, `reposhield scan . --gate` permanece local e pode retornar INCONCLUSIVO.
Sem `--gate`, códigos antigos continuam disponíveis: 0 significa execução concluída, não aprovação;
`--fail-on` mantém o bloqueio por severidade. Erro de IA retorna 2 e conserva o relatório.
Na interface, ative separadamente as autorizações de GETs locais e consulta ao OSV.

RS209 agora identifica arquivos de teste (`*.spec.*`, `*.test.*`, `test_*.py`, diretórios de testes).
A evidência é preservada com contexto, sem afirmar uma vulnerabilidade de produção. Ainda exige conferir
o armazenamento real; possíveis segredos em testes nunca são suprimidos. O texto de risco de RS209
passa a explicar acesso por JavaScript/XSS, em vez de confundir armazenamento com validação de JWT.

## Análise local de Angular e .NET (v0.4)

```bash
reposhield scan /caminho/hidrocalc-front --gate
reposhield scan /caminho/hidrocalc-back --gate
```

Esses comandos não iniciam HTTP, OSV ou CLI de IA. O status pode continuar INCONCLUSIVO:
a alteração aumenta a cobertura estática, não transforma ausência de achados em aprovação.
O código 3 com `--gate` indica pendências, não falha de gravação do relatório.

### RS209 — chaves indiretas

Detecta chamadas multilinha a localStorage/sessionStorage.setItem com:
- Chave literal sensível (`"token"`, `"jwt"`, `"session"`).
- Constante local simples, por exemplo `const KEY = "app:token"`.
- Indício no identificador, como `TOKEN_KEY`, `this.tokenKey` ou `response.token`.

O caso `localStorage.setItem(TOKEN_KEY, response.token)` é detectado no arquivo de
produção, com a linha da chamada, preservando separadamente a evidência do teste.
Comentários e strings que apenas descrevem chamadas não são tratados como sinks.
São indícios, não análise de fluxo completa: imports, aliases de storage, wrappers,
computed properties, concatenações e sombreamento de variáveis não são resolvidos.

### C#/.NET

Arquivos `.cs`, `.csproj`, `.props` e `.targets` passam a ser lidos. `bin`, `obj` e `.vs`
são excluídos como diretórios gerados. JSON, incluindo appsettings, já é lido.

- Inventário heurístico de controllers com atributos HttpGet/Post/etc., Route,
  Authorize (inclusive Roles/Policy) e AllowAnonymous.
- Minimal APIs MapGet/Post/etc. e indícios locais de RequireAuthorization/AllowAnonymous.
- RS400: AllowAnyOrigin e SetIsOriginAllowed com lambda literal true.
- RS401: propriedades de validação JWT explicitamente false.
- RS402: callbacks conhecidos que aceitam certificados TLS indiscriminadamente.
- RS403: possíveis segredos em JSON e senhas em connection strings, com evidência redigida.

Não compila o projeto, não executa dotnet e não usa Roslyn. Não resolve atributos
multilinha complexos, raw strings C#, namespaces de atributos, herança, filtros globais,
fallback policies, MapGroup, extensões, preprocessor ou rotas convencionais. Um atributo
Authorize é apenas indício; não comprova proteção efetiva. Dependências NuGet não são
auditadas pelo módulo OSV npm.

### Cobertura explícita

Markdown, JSON e painel mostram arquivos lidos por extensão, motivos de exclusão,
diretórios excluídos e fontes conhecidas sem analisador (como VB, Java, Go, PHP, Vue).
Arquivos dentro de diretórios excluídos não são percorridos nem contabilizados como
arquivos ignorados. Fontes não suportadas identificadas impedem aprovação do gate.
