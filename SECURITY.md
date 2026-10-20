# Segurança

RepoShield é um ferramenta de triagem estática e verificação local opt-in, não um pentest nem uma certificação.
Não publique relatórios com dados privados ou falhas de terceiros sem autorização.

Se encontrar uma falha no próprio RepoShield, use o canal privado de segurança do
repositório, caso habilitado. Caso não exista, solicite um contato privado aos
mantenedores sem publicar detalhes exploráveis.

A API deve permanecer em loopback. Não exponha por proxy ou na rede. O token local
protege operações de leitura e scan; `/api/health` é público. O scan é limitado à
raiz configurada. Quem possui o token pode ler relatórios dessa instância.

A integração com IA envia trechos redigidos e metadados, que ainda podem conter
informações confidenciais. A redação é heurística. Revise regras e políticas antes
de usar com código sensível. Os CLIs usam as configurações e credenciais do usuário.
Codex roda em sandbox read-only, mas suas capacidades variam conforme configuração
local e versão; use apenas configuração confiável. Não há execução automática de
correções. O projeto analisado nunca é importado pelo scanner.

## Probes locais

Runtime só é ativado explicitamente. Revise o bloco runtime antes de autorizar:
GETs mal projetados podem ter efeitos colaterais. Use dados sintéticos e instância
isolada. Não encaminhe a porta do serviço a terceiros. Não são aceitos destinos
fora de loopback, redirects, credenciais na URL ou métodos de mutação. As contas
e os tokens de teste são fornecidos por você; o app não cria nem adivinha credenciais.
