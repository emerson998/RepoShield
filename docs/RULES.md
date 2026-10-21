# Catálogo de regras · v0.2.0

42 regras, com severidade de triagem. Confiança é separada de severidade.

| Regra | Severidade | Área | CWE | Verificação |
| --- | --- | --- | --- | --- |
| RS001 | high | secrets | CWE-798 | Possível segredo no código |
| RS002 | high | transport | CWE-295 | TLS sem verificação de certificado |
| RS003 | high | injection | CWE-78 | Comando com shell habilitado |
| RS004 | medium | secrets | CWE-489 | Modo debug habilitado |
| RS005 | medium | tokens | CWE-347 | JWT com verificação desabilitada |
| RS100 | medium | authentication | CWE-306 | Autenticação do endpoint precisa de revisão |
| RS101 | high | authorization | CWE-862 | Rota administrativa sem autorização aparente |
| RS102 | medium | authorization | CWE-639 | Revisar autorização por objeto |
| RS200 | high | passwords | CWE-916 | Hash inadequado para senha |
| RS201 | high | passwords | CWE-256 | Possível senha armazenada sem hash |
| RS202 | high | tokens | CWE-347 | JWT com algoritmo none permitido |
| RS203 | medium | tokens | CWE-613 | JWT sem expiração ou audience verificadas |
| RS204 | medium | sessions | CWE-1004 | Cookie sem HttpOnly explícito |
| RS205 | medium | sessions | CWE-614 | Cookie sem Secure explícito |
| RS206 | medium | csrf | CWE-352 | Cookie sem política SameSite explícita |
| RS207 | high | csrf | CWE-352 | Proteção CSRF desabilitada explicitamente |
| RS208 | medium | cors | CWE-942 | CORS com origem irrestrita |
| RS209 | medium | tokens | CWE-922 | Token persistido em Web Storage |
| RS210 | high | injection | CWE-89 | SQL construído com interpolação |
| RS211 | high | injection | CWE-95 | Execução dinâmica de código |
| RS212 | high | serialization | CWE-502 | Desserialização potencialmente insegura |
| RS213 | medium | xss | CWE-79 | Renderização HTML sem escape automático |
| RS214 | medium | logging | CWE-532 | Possível credencial enviada ao log |
| RS215 | medium | recovery | CWE-330 | Token de segurança gerado com PRNG comum |
| RS216 | medium | login | CWE-204 | Resposta pode enumerar usuários |
| RS217 | high | ssrf | CWE-918 | URL de requisição obtida diretamente da entrada |
| RS218 | high | files | CWE-22 | Caminho de arquivo obtido diretamente da entrada |
| RS219 | high | authorization | CWE-915 | Atualização de entidade com payload inteiro |
| RS220 | medium | transport | CWE-319 | Redirecionamento HTTPS desativado |
| RS221 | medium | headers | CWE-693 | Política de segurança de conteúdo desativada |
| RS222 | medium | rate_limit | CWE-307 | Login sem limitação aparente |
| RS223 | medium | recovery | CWE-640 | Recuperação de senha exige revisão |
| RS224 | medium | tokens | CWE-613 | Refresh/logout exige revisão de revogação |
| RS225 | medium | openapi | CWE-306 | OpenAPI permite acesso sem credenciais |
| RS226 | high | openapi | CWE-287 | OpenAPI referencia esquema de segurança inexistente |
| RS300 | high | authorization | CWE-862 | Matriz de acesso divergente do esperado |
| RS301 | medium | headers | CWE-693 | Resposta HTML sem Content-Security-Policy |
| RS302 | medium | headers | CWE-693 | Resposta sem X-Content-Type-Options nosniff |
| RS303 | medium | sessions | CWE-1004 | Cookie de resposta sem HttpOnly |
| RS304 | medium | sessions | CWE-614 | Cookie de resposta sem Secure |
| RS305 | medium | sessions | CWE-1275 | Cookie de resposta sem SameSite |
| RS306 | medium | cors | CWE-942 | CORS aceita origem de teste com credenciais |

## Interpretação

Regras estáticas reconhecem padrões; não há análise completa de fluxo de dados.
RS100–102 e RS222–224 são pontos de revisão com confiança baixa. RS225/226 descrevem
o contrato OpenAPI, não o comportamento real. RS300 compara status com expectativas
explícitas. RS301–306 observam cabeçalhos da resposta e ainda exigem contexto.
Cookies Python são inspecionados por AST; expressões dinâmicas e **kwargs permanecem
não resolvidos. O catálogo não inclui auditoria de CVEs nem scanners externos.


## Regras .NET adicionadas na v0.4

| Regra | Severidade | Evidência local |
| --- | --- | --- |
| RS400 | Média | CORS permite qualquer origem |
| RS401 | Alta | Validação JWT explicitamente desativada |
| RS402 | Alta | Bypass de certificado TLS |
| RS403 | Alta | Possível segredo literal em configuração |

São hipóteses estáticas. Controllers e Minimal APIs também utilizam RS100/101/102
para revisão de autenticação/autorização. RS209 inclui constantes locais e indícios
nos argumentos de setItem. Confira os limites no README.
