# 🛡️ RepoShield

**Segurança começa no código.** Workspace local de triagem de segurança com React,
FastAPI e CLI. Inventaria endpoints, procura padrões de risco e oferece revisão
consultiva opcional com **Claude CLI ou Codex CLI**.

> Versão 0.1.0 · MVP funcional. Resultados são hipóteses com evidências, não
> vulnerabilidades confirmadas. Não substitui revisão humana ou testes de segurança.

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
- Inventário FastAPI/Flask por AST e inventário básico Express por padrões.
- Revisão de autenticação aparente, rotas administrativas e autorização por objeto.
- Padrões de segredos, TLS desabilitado, shell, debug e JWT sem validação.
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
para gerar recomendações em português. Não recebe o código inteiro, não valida
explorabilidade e não aplica patches. Timeout: 180 segundos. CLI inexistente,
erro de autenticação ou incompatibilidade de versão aparecem no relatório da web;
a análise estática continua disponível. A CLI encerra com erro se a revisão falhar.

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

Rotas públicas são declaradas pelo path do decorator, antes de prefixos de router.
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
propriedade/tenant, sem afirmar que existe IDOR. Prefixos e montagem de routers não
são reconstruídos. Express recebe inventário básico; análise de guards JS/TS
está no roadmap. O scanner nunca faz requisições aos endpoints.

## Arquitetura

```text
frontend/                 React + Vite + lucide-react
backend/reposhield/
  scanner.py              Motor estático compartilhado
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

Próximas entregas: integração com Semgrep/Gitleaks e auditoria de dependências,
resolução de routers e middleware, falsos positivos com justificativa, comparação
de scans, testes dinâmicos autorizados e correções em branches com diffs revisáveis.
Esses recursos **não estão implementados nesta versão**. Não há score de segurança
artificial ou promessa de detectar todas as vulnerabilidades.

## Contribuir e licença

Veja [CONTRIBUTING.md](CONTRIBUTING.md) e [SECURITY.md](SECURITY.md).
Licença [MIT](LICENSE).
