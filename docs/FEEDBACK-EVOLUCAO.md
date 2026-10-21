# Feedback de evolução do RepoShield

**Data:** 2026-10-21
**Base:** três rodadas reais (v0.2.0, v0.3.0 e v0.4.0) contra o projeto HidroCalc
(`hidrocalc-back` em .NET e `hidrocalc-front` em Angular), com cada achado
conferido manualmente no código.

**Tese:** o RepoShield deve **orquestrar** scanners maduros e concentrar o
esforço próprio no que eles não fazem: **triagem de contexto, veredito e
relatório acionável em português**. Reescrever detectores que já existem
(segredos, SAST, CVEs) consome a maior parte do esforço e entrega menos
cobertura que as ferramentas de mercado.

---

## 1. O que o caso real mostrou

### 1.1 Evolução entre versões

| Versão | Back-end (.NET) | Front-end (Angular) | Veredito |
|---|---|---|---|
| 0.2.0 | 8 arquivos lidos, 709 ignorados. C# não suportado. 0 achados (sem significado). | 1 achado (token), só no arquivo de teste | — |
| 0.3.0 | Igual à 0.2.0 | Mesmo achado, agora marcado "contexto: teste". OSV opcional: 41 alertas | Back: inconclusivo · Front: reprovado |
| 0.4.0 | **128 `.cs` analisados.** 22 achados | Token detectado também no código de produção | Back: inconclusivo · Front: reprovado |

A evolução de cobertura foi rápida e na direção certa. O problema agora é
**precisão**: pouco do que é reportado é acionável.

### 1.2 Precisão medida na v0.4.0

| Projeto | Achados | Reais e acionáveis | Falsos positivos ou não aplicáveis |
|---|---|---|---|
| Back | 22 | **1**: login sem limite de tentativas | 5 "segredos" (3 connection strings com placeholder `<senha>` + a chave JWT de dev reportada 2 vezes, que o `Program.cs` já impede de subir fora de dev) · 16 "autorização por objeto" em controllers cobertos por `FallbackPolicy` + `[Authorize]` |
| Front | 2 | **1**: token JWT em `localStorage` | 1 duplicado (o mesmo padrão no teste) |
| Front (deps) | 41 alertas / 11 pacotes | **0 exploráveis hoje** | 38 em ferramentas de build (vite, undici, hono, MCP SDK…). 3 no `@angular/router`, mas só com SSR, que o projeto não usa |

**Resultado: 2 problemas reais em 65 itens reportados.** Um relatório com essa
proporção acaba ignorado pelo time ou não pode ser usado como gate de CI. A
própria ferramenta reprova o front por alertas que não se aplicam.

### 1.3 O que funcionou (e deve ser preservado)

- **Local por padrão:** nada sai da máquina sem flag explícita (`--dependencies`, `--provider` + `--consent`).
- **Veredito honesto:** "inconclusivo" em vez de "aprovado" quando falta cobertura.
- **Relatório em português** com "por que ajustar", "como ajustar" e "como validar".
- **Classificação de contexto** (`assurance.classify`), que separa teste de produção. É a semente do diferencial proposto abaixo.
- **Cobertura transparente:** o relatório informa extensões não suportadas e arquivos ignorados.

---

## 2. Causas no código

Cada falso positivo do caso real tem origem localizada:

| Sintoma | Causa | Arquivo |
|---|---|---|
| Front sempre reprovado por dependências | O lock é lido sem considerar `"dev": true`. Qualquer correspondência no OSV vira `rejected`, sem olhar severidade ou alcance | `dependencies.py:22-31`, `assurance.py:41-44` |
| Alertas sem severidade | O `querybatch` do OSV devolve só os IDs. Severidade, faixa afetada e versão corrigida exigem `GET /v1/vulns/{id}`, que não é feito | `dependencies.py:40-55` |
| Placeholders tratados como segredo | `config_secrets` não descarta valores como `<senha>`, `changeme` ou `${VAR}` | `dotnet.py` |
| A mesma linha reportada duas vezes | `RS001` e a regra .NET de segredo disparam em `appsettings.json:18` com IDs diferentes. A deduplicação usa a regra como chave | `scanner.py:45`, `scanner.py:142` |
| 16 avisos de autorização por objeto | `FallbackPolicy` e `[Authorize]` de classe não são resolvidos (a própria limitação já está declarada no relatório) | `dotnet.py`, `scanner.py:152` |
| Auditoria de dependências só para npm | O ecossistema `npm` e o `package-lock.json` estão fixos no código | `dependencies.py:14,39` |
| Projeto com workspace aborta a auditoria inteira | Qualquer dependência local gera `ValueError` em vez de ser ignorada | `dependencies.py:24-25` |
| Versão do motor repetida em 3 lugares | `'0.4.0'` literal em `scanner.py:147`, `scanner.py:165` e `pyproject.toml` | — |

Esses itens são correções pontuais e valem mesmo sem a integração externa
(seção 6).

---

## 3. Arquitetura proposta: orquestrador com adaptadores

```text
                     ┌───────────────────────────────────────┐
  projeto ──────────►│  Descoberta: linguagens, locks,       │
                     │  Dockerfile, IaC, frameworks          │
                     └───────────────┬───────────────────────┘
                                     │ plano de execução
        ┌────────────┬───────────────┼──────────────┬─────────────┐
        ▼            ▼               ▼              ▼             ▼
   Regras próprias  Gitleaks     OSV-Scanner     Semgrep        Trivy
   (contexto e      (segredos +  (dependências,  (SAST          (imagem,
    framework)       histórico)   todos os        multilíngue)   IaC)
                                  ecossistemas)
        │            │               │              │             │
        └────────────┴──── SARIF / JSON ────────────┴─────────────┘
                                     │
                     ┌───────────────▼───────────────────────┐
                     │  Normalização → Finding único          │
                     │  Deduplicação por arquivo, linha, CWE  │
                     │  Triagem de contexto (diferencial)     │
                     │  Supressões com justificativa          │
                     └───────────────┬───────────────────────┘
                                     ▼
                  Veredito · Relatório pt-BR · SARIF · IA opcional
```

### 3.1 Contrato do adaptador

```python
class Adapter(Protocol):
    name: str                       # "gitleaks"
    def available(self) -> ToolInfo  # binário no PATH, versão, licença
    def applies(self, project) -> bool
    def network(self) -> NetworkUse  # none | rules_download | db_download | per_query
    def run(self, project, workdir) -> RawResult   # nunca executa código do projeto
    def normalize(self, raw) -> list[Finding]
```

Regras do contrato:

- **Ferramenta ausente não é erro.** Ela aparece como "não executada" na
  cobertura, e o veredito fica inconclusivo naquele eixo. Mantém o comportamento
  honesto que já existe hoje.
- **Uso de rede declarado por adaptador** e sujeito ao mesmo consentimento do
  `--dependencies`. Sem flag, só rodam adaptadores com `network() == none`.
- **Versão fixa e verificada.** Registrar no relatório a versão de cada
  ferramenta e de cada base de vulnerabilidades usada.
- **Execução isolada:** sem acesso de escrita ao projeto, com timeout e limite
  de saída, como já é feito com os CLIs de IA.

### 3.2 Importador SARIF genérico: o maior ganho por esforço

Semgrep, Gitleaks, Trivy, OSV-Scanner, CodeQL, Bandit, ESLint e o analisador
do .NET (`/p:ErrorLog`) **exportam SARIF**. Um único importador SARIF bem feito
cobre a maior parte dos adaptadores. Cada um passa a ser só "como invocar"
mais um mapeamento de severidade.

Esse importador também permite que o time **traga resultados que já tem**
(por exemplo, um SARIF do CodeQL gerado no CI) sem rodar nada localmente:
`reposhield scan . --import resultados.sarif`.

### 3.3 Modelo de achado normalizado

O modelo atual já tem quase tudo. Faltam:

| Campo | Para quê |
|---|---|
| `source` (`gitleaks@8.x`, `reposhield`) | Rastrear origem e versão |
| `fingerprint` estável (arquivo + CWE + trecho normalizado, sem a regra) | Deduplicar entre ferramentas e entre execuções |
| `reachability` (`production`, `test`, `build_tool`, `dev_only`, `unknown`) | Base do veredito sem ruído (seção 4) |
| `fixed_in`, `cvss`, `aliases` (CVE/GHSA) | Dependências acionáveis |
| `suppressed_by` + justificativa + validade | Exceções revisáveis em vez de ignorar em silêncio |

---

## 4. O diferencial que deve continuar próprio

As ferramentas externas **detectam**. Nenhuma delas responde bem a "isso
importa **neste** projeto?". É aí que o RepoShield agrega valor:

1. **Alcance de dependências.**
   - Separar `dev` de produção pelo próprio lock (`"dev": true` no npm, `PrivateAssets` no NuGet, `<scope>test</scope>` no Maven).
   - Cruzar a condição do alerta com a configuração do projeto. Exemplo real: os 3 alertas do `@angular/router` só valem com `@angular/ssr`, que o projeto não tem.
2. **Semântica de framework.**
   - .NET: resolver `FallbackPolicy`, `[Authorize]` de classe, `RequireAuthorization()` em grupos de Minimal API.
   - Spring: `intercept-url` e `@Secured`.
   - Angular: `canActivate`.

   Isso elimina a maior fonte de ruído (16 dos 22 achados do back).
3. **Contexto de valor.** Distinguir placeholder, valor de exemplo e chave de
   dev já bloqueada em runtime (o `Program.cs` do HidroCalc recusa subir com a
   chave padrão) de um segredo real.
4. **Veredito com política.** Reprovar por severidade **e** alcance, não por
   simples correspondência. Exemplo de política padrão:
   - `critical`/`high` em produção → reprova;
   - só em build ou dev → aviso;
   - `unknown` → inconclusivo.
5. **Relatório em pt-BR e IA consultiva** sobre os achados já normalizados e
   deduplicados. A IA recebe menos ruído e responde melhor.

---

## 5. Ferramentas recomendadas por eixo

| Eixo | Ferramenta | Licença | Rede | Observações |
|---|---|---|---|---|
| Segredos (inclusive no histórico git) | **Gitleaks** | MIT | Nenhuma | Binário único, SARIF nativo. Varre commits antigos, o que o RepoShield hoje não faz. **Primeira integração.** |
| Dependências, todos os ecossistemas | **OSV-Scanner** | Apache-2.0 | Consulta ou base offline (`--offline` com base baixada) | Substitui `dependencies.py`: npm, NuGet, Maven, pip, Go, Cargo… com severidade e versão corrigida. Resolve de uma vez a falta de NuGet e Maven. |
| SAST multilíngue | **Semgrep CE** | LGPL-2.1 (motor) | Download de regras, salvo se embutidas | Cobre C#, Java, TS, Python. Usar `--metrics=off` e um pacote de regras **versionado junto ao RepoShield** para manter a execução offline. Revisar a licença das regras do registry antes de redistribuir. |
| Contêiner e IaC | **Trivy** | Apache-2.0 | Download da base | Dockerfile, imagem, Kubernetes, Terraform. O HidroCalc tem Dockerfile e manifestos de CI. |
| Nativo do ecossistema (alternativa sem nova dependência) | `npm audit`, `dotnet list package --vulnerable`, `mvn dependency-check` | — | Consulta | Útil quando a ferramenta externa não está instalada. |
| Runtime (opt-in) | **OWASP ZAP baseline** | Apache-2.0 | Só local | Complementa a matriz de GETs atual com cabeçalhos, cookies e CSP. Exigir `--runtime` e apontar só para loopback, como hoje. |

Não recomendo integrar agora: CodeQL (pesado e com licença restrita fora de
open source; melhor aceitar o SARIF dele via importador) e scanners comerciais.

---

## 6. Roadmap sugerido

### v0.5: correções de precisão (sem dependência externa)
- [ ] Ignorar placeholders em segredos: `<...>`, `${...}`, `changeme`, `example`, `xxx`.
- [ ] Fingerprint sem a regra, para deduplicar a mesma linha entre regras.
- [ ] Ler `"dev": true` do lock e calcular `reachability`.
- [ ] Buscar severidade e versão corrigida no OSV (`/v1/vulns/{id}`, com cache).
- [ ] Veredito por severidade × alcance (política da seção 4).
- [ ] Resolver `FallbackPolicy` e `[Authorize]` de classe no .NET.
- [ ] Dependência local ou de workspace: ignorar com aviso, sem abortar a auditoria.
- [ ] Versão do motor em um único lugar (`importlib.metadata`).

**Critério de aceite no HidroCalc:**
- back com no máximo 3 achados, incluindo o login;
- front com o token e nenhum alerta de dependência de build bloqueando;
- veredito do front sem "reprovado" causado só por pacotes de dev.

### v0.6: base de orquestração
- [ ] Interface `Adapter` com descoberta, uso de rede declarado e versão registrada.
- [ ] Importador SARIF genérico (`--import arquivo.sarif`).
- [ ] Adaptador Gitleaks (offline, inclui o histórico do git).
- [ ] Adaptador OSV-Scanner, substituindo `dependencies.py` (NuGet e Maven passam a ser cobertos).
- [ ] Seção "ferramentas executadas" no relatório, com versão e base de cada uma.

### v0.7: SAST e infraestrutura
- [ ] Adaptador Semgrep com pacote de regras embutido e versionado.
- [ ] Adaptador Trivy (Dockerfile, IaC).
- [ ] Analisador Java/Spring próprio (`intercept-url`, `@Secured`), para comparar legado e migrado em projetos de modernização.

### v1.0: uso contínuo
- [ ] Supressões em `.reposhield.json` com justificativa, autor e validade.
- [ ] Linha de base: reportar só o que é novo em relação ao último scan aceito.
- [ ] Scan por diff de branch, para uso em pull requests.
- [ ] Runtime com ZAP baseline (opt-in).

---

## 7. Riscos e cuidados

| Risco | Mitigação |
|---|---|
| Quebrar a promessa de "local por padrão" | Cada adaptador declara uso de rede. Sem flag, só rodam os offline. Regras do Semgrep embutidas. |
| Ferramenta externa ausente ou em versão incompatível | Detectar a versão e marcar o eixo como "não executado" (inconclusivo), nunca como aprovado. |
| Executar código do projeto sem querer | Nunca chamar `npm install`, `dotnet restore` ou build. Usar só os arquivos de lock. |
| Mais ferramentas, mais ruído | A normalização, a deduplicação e o alcance (seção 4) vêm **antes** de somar fontes. Por isso a v0.5 precede a v0.6. |
| Licenças | Não redistribuir binários. Documentar a instalação. Revisar as regras do Semgrep registry antes de embutir. |

---

## 8. Resumo para decisão

1. **Primeiro, precisão.** A v0.5 corrige os falsos positivos medidos sem
   adicionar nenhuma dependência.
2. **Depois, orquestração via SARIF.** Um importador genérico mais Gitleaks e
   OSV-Scanner cobrem segredos no histórico e dependências de todos os
   ecossistemas com pouco código novo.
3. **O valor próprio do RepoShield está na triagem.** Alcance, semântica de
   framework, veredito com política e relatório em português são o que nenhum
   scanner externo entrega.
