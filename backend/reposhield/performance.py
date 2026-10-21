"""Offline performance triage. Never connects to a database or executes SQL/code."""
import ast
import hashlib
import json
import re
from pathlib import Path

from .syntax import TOKENS, blank, clean, closing

RULES = {
    'RP001': ('high', 'Consulta dentro de loop: possível N+1', 'Agrupe as consultas ou use carregamento em lote; preserve filtros por usuário/tenant.'),
    'RP002': ('medium', 'Materialização antes de filtro ou paginação', 'Mantenha Where/Skip/Take no IQueryable antes de ToList/AsEnumerable; confira o SQL gerado.'),
    'RP003': ('medium', 'Coleção consultada sem limite aparente', 'Avalie projeção e paginação com limite máximo; exportações podem exigir streaming em lotes.'),
    'RP004': ('medium', 'Consulta síncrona em método async', 'Use a operação async do provedor e propague CancellationToken quando disponível.'),
    'RP005': ('medium', 'Espera bloqueante por Task', 'Use await em vez de .Result ou .Wait(); confira o contexto e evite bloquear threads de requisição.'),
    'RP006': ('low', 'SELECT *: revisar projeção', 'Selecione as colunas necessárias; meça bytes retornados e leituras antes/depois.'),
    'RP007': ('medium', 'Função em coluna no filtro SQL', 'Confira o plano e considere reescrever o predicado ou um índice de expressão adequado ao banco.'),
    'RP008': ('medium', 'Busca SQL com curinga inicial', 'Confira volume e plano; avalie busca textual ou índice especializado conforme o banco.'),
    'RP009': ('medium', 'Paginação SQL com OFFSET elevado', 'Avalie paginação por cursor com ordenação estável; valide consistência e tempo nas páginas finais.'),
    'RP010': ('medium', 'Operação bloqueante em função Python async', 'Use cliente assíncrono ou isolamento explícito em thread para operações bloqueantes; configure timeout.'),
    'RP011': ('medium', 'I/O aguardado sequencialmente em loop', 'Meça a necessidade de sequenciamento; quando independente, use concorrência limitada, respeitando quotas e transações.'),
    'RP101': ('high', 'Plano PostgreSQL: muitas linhas descartadas em Seq Scan', 'Investigue seletividade e índices com o plano completo; Seq Scan pode ser a melhor opção em outros volumes.'),
    'RP102': ('medium', 'Plano PostgreSQL: estimativa de cardinalidade divergente', 'Revise estatísticas, distribuição e correlação; compare planos com dados representativos.'),
    'RP103': ('high', 'Plano PostgreSQL: uso de disco temporário', 'Investigue projeção, ordenação, cardinalidade e memória por operação; não aumente work_mem globalmente sem medir concorrência.'),
    'RP104': ('medium', 'Plano PostgreSQL: execução repetida de nó', 'Investigue o nó pai e o volume multiplicado pelo número de loops; avalie joins e acesso em lote.'),
}
IMPACTS = {
    'RP001': 'O número de consultas pode crescer com a quantidade de itens, multiplicando viagens ao banco e latência.',
    'RP002': 'Filtrar depois de materializar pode transferir e manter em memória linhas que o banco poderia descartar.',
    'RP003': 'O volume carregado pode crescer junto com a tabela e elevar uso de memória, rede e tempo de resposta.',
    'RP004': 'A consulta síncrona pode ocupar a thread enquanto aguarda o banco, limitando concorrência sob carga.',
    'RP005': 'A espera bloqueante pode reduzir a disponibilidade de threads e, em alguns contextos, causar deadlock.',
    'RP006': 'Colunas desnecessárias podem aumentar transferência e materialização; o impacto depende da largura e quantidade das linhas.',
    'RP007': 'A expressão sobre a coluna pode dificultar o uso de um índice comum; índices de expressão e o otimizador podem mudar esse resultado.',
    'RP008': 'O curinga inicial pode impedir uma busca por prefixo em índice comum e exigir examinar muitas linhas.',
    'RP009': 'Páginas profundas podem exigir percorrer e descartar muitas linhas antes de retornar o resultado.',
    'RP010': 'I/O ou espera síncrona na função async pode bloquear o event loop e atrasar outras requisições.',
    'RP011': 'Operações independentes aguardadas em sequência somam suas latências; concorrência só ajuda quando o fluxo permite.',
    'RP101': 'O plano fornecido mostra muitas linhas lidas e descartadas; isso pode indicar trabalho evitável em um filtro seletivo.',
    'RP102': 'Estimativas divergentes podem levar a escolhas inadequadas de join e memória; precisam ser avaliadas no plano completo.',
    'RP103': 'O plano registra uso de armazenamento temporário, que pode adicionar I/O e latência à operação.',
    'RP104': 'Muitos loops podem multiplicar o trabalho de um nó; o custo por execução e o plano pai determinam o impacto.',
}
STATIC_VALIDATION = ('Em ambiente de teste com dados representativos, conte comandos SQL por requisição, '
                     'compare p50/p95, linhas/bytes retornados, leituras, CPU e memória antes/depois. '
                     'Inspecione o plano de execução; o padrão estático não confirma lentidão.')
MAX_PLAN_BYTES = 5_000_000
MAX_PLAN_NODES = 20_000


def make(rule, file, line, evidence, *, measured=False):
    from .scanner import redact
    priority, title, recommendation = RULES[rule]
    evidence = redact(evidence)[:350]
    key = json.dumps([rule, file, line, evidence], ensure_ascii=False)
    return dict(id=hashlib.sha256(key.encode()).hexdigest()[:16], rule=rule, file=file, line=line,
                priority=priority, title=title, evidence=evidence, impact=IMPACTS[rule], recommendation=recommendation,
                confidence='high' if measured else 'medium',
                context='test' if set(Path(file).parts) & {'test', 'tests', '__tests__', 'fixtures'} else 'production_or_unknown',
                status='plan_observation' if measured else 'needs_measurement',
                source='postgresql-explain' if measured else 'reposhield-static',
                validation=('Compare com o SQL e parâmetros originais, versão do banco, volume e concorrência. '
                            'O plano importado é uma observação fornecida pelo usuário, não uma medição executada pelo RepoShield.')
                           if measured else STATIC_VALIDATION)


def _line(text, offset):
    return text.count('\n', 0, offset) + 1


def _brace_regions(masked, pattern):
    for match in re.finditer(pattern, masked):
        start = masked.find('{', match.start(), match.end())
        if start >= 0:
            end = closing(masked, start, '{', '}')
            if end is not None:
                yield start, end


DB_ROOT = r'\b(?:db|ctx|context|[A-Za-z_]\w*(?:Context|Db))\s*\.\s*\w+'
QUERY = re.compile(DB_ROOT + r'[^;{}]{0,6000}', re.S)
READ = r'\.(?:ToList(?:Async)?|ToArray(?:Async)?|FirstOrDefault(?:Async)?|SingleOrDefault(?:Async)?|Count(?:Async)?|Any(?:Async)?|Find(?:Async)?)\s*\('


def _dotnet(text, file):
    masked = clean(text, strings=True)
    loops = list(_brace_regions(masked, r'\b(?:foreach|for|while)\s*\([^{}]*\)\s*\{'))
    asyncs = list(_brace_regions(masked, r'\basync\s+[^;{}=]{1,400}\([^;{}]*\)\s*\{'))
    result = []
    for match in QUERY.finditer(masked):
        expr = match[0]
        if not re.search(READ, expr):
            continue
        offset = match.start()
        evidence = text[offset:match.end()].strip()
        line = _line(text, offset)
        if any(start < offset < end for start, end in loops):
            result.append(make('RP001', file, line, evidence))
        if re.search(r'\.(?:ToList(?:Async)?|ToArray(?:Async)?|AsEnumerable)\s*\([^)]*\)[\s)]*\.(?:Where|Skip|Take|OrderBy)\s*\(', expr):
            result.append(make('RP002', file, line, evidence))
        if re.search(r'\.(?:ToList(?:Async)?|ToArray(?:Async)?)\s*\(', expr) and not re.search(r'\.(?:Take|First|Single|Find)\w*\s*\(', expr):
            result.append(make('RP003', file, line, evidence))
        if any(start < offset < end for start, end in asyncs) and re.search(r'\.(?:ToList|ToArray|FirstOrDefault|SingleOrDefault|Count|Any|Find)\s*\(', expr):
            result.append(make('RP004', file, line, evidence))
    # Awaitable sources only; ordinary model.Result or list.Wait is insufficient.
    for match in re.finditer(r'\b\w+Async\s*\([^;{}]*?\)\s*\.(?:Result\b|Wait\s*\()', masked):
        result.append(make('RP005', file, _line(text, match.start()), text[match.start():match.end()]))
    return result


def _python(text, file):
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    lines = text.splitlines()
    imports = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                imports[alias.asname or alias.name] = node.module + '.' + alias.name
    def name(node):
        if isinstance(node, ast.Name): return imports.get(node.id, node.id)
        if isinstance(node, ast.Attribute): return name(node.value) + '.' + node.attr
        return ''
    result = []
    class Visitor(ast.NodeVisitor):
        async_mode = False
        loop = 0
        def function(self, node, mode):
            previous = self.async_mode, self.loop
            self.async_mode, self.loop = mode, 0
            for child in node.body: self.visit(child)
            self.async_mode, self.loop = previous
        def visit_AsyncFunctionDef(self, node): self.function(node, True)
        def visit_FunctionDef(self, node): self.function(node, False)
        def visit_For(self, node):
            self.visit(node.iter)
            self.loop += 1
            for child in node.body: self.visit(child)
            self.loop -= 1
            for child in node.orelse: self.visit(child)
        visit_AsyncFor = visit_For
        def visit_While(self, node):
            self.loop += 1
            self.visit(node.test)
            for child in node.body: self.visit(child)
            self.loop -= 1
            for child in node.orelse: self.visit(child)
        def visit_Call(self, node):
            called = name(node.func)
            if self.async_mode and (called in {'time.sleep', 'subprocess.run', 'subprocess.call', 'subprocess.check_output'} or
                                    re.fullmatch(r'requests\.(?:get|post|put|patch|delete|request|head)', called)):
                result.append(make('RP010', file, node.lineno, lines[node.lineno - 1].strip()))
            if self.loop and re.fullmatch(r'(?:db|session|cursor)\.(?:execute|executemany|fetchone|fetchall)', called):
                result.append(make('RP001', file, node.lineno, lines[node.lineno - 1].strip()))
            self.generic_visit(node)
        def visit_Await(self, node):
            if self.loop and isinstance(node.value, ast.Call) and re.search(r'(?:fetch|request|get|post|execute|query|find|save)', name(node.value.func), re.I):
                result.append(make('RP011', file, node.lineno, lines[node.lineno - 1].strip()))
            self.generic_visit(node)
    Visitor().visit(tree)
    return result


def _sql(text, file, offset=0):
    # Preserve quoted literals for LIKE, discard SQL comments and string contents for other rules.
    tokens = re.compile(r"'(?:''|[^'])*'|--[^\n]*|/\*.*?\*/", re.S)
    comments = tokens.sub(lambda m: blank(m[0]) if m[0].startswith(('--', '/*')) else m[0], text)
    masked = tokens.sub(lambda m: blank(m[0]), text)
    result = []
    checks = [
        ('RP006', r'\bSELECT\s+(?:DISTINCT\s+)?(?:\w+\.)?\*', masked),
        ('RP007', r'\b(?:WHERE|AND|OR)\s+(?:LOWER|UPPER|DATE|YEAR|CAST|CONVERT)\s*\(\s*[\w.]+', masked),
        ('RP008', r"\bLIKE\s+'%[^']*'", comments),
        ('RP009', r'\bOFFSET\s+(\d+)', masked),
    ]
    for rule, pattern, source in checks:
        for match in re.finditer(pattern, source, re.I):
            if rule == 'RP009' and len(match[1].lstrip('0')) < 5:
                continue
            evidence = "LIKE '%…' (literal omitido)" if rule == 'RP008' else text[match.start():match.end()]
            result.append(make(rule, file, offset + _line(text, match.start()), evidence))
    return result


def analyze(text, file):
    suffix = Path(file).suffix.lower()
    if suffix == '.sql': return _sql(text, file)
    if suffix not in {'.cs', '.py', '.js', '.ts', '.jsx', '.tsx', '.java'}: return []
    result = _dotnet(text, file) if suffix == '.cs' else _python(text, file) if suffix == '.py' else []
    if suffix in {'.js', '.ts', '.jsx', '.tsx'}:
        masked = clean(text, strings=True)
        loops = list(_brace_regions(masked, r'\b(?:for|while)\s*\([^{}]*\)\s*\{'))
        for start, end in loops:
            for m in re.finditer(r'\bawait\s+[\w.]*\b(?:query|execute|findMany|findUnique|fetch|save)\s*\(', masked[start:end]):
                pos = start + m.start()
                result.append(make('RP011', file, _line(text, pos), text[pos:pos + len(m[0])]))
    # Python constants come from AST: ignore comments and docstrings, support triple quotes.
    if suffix == '.py':
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return result
        docs = {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)}
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs and re.search(r'\bSELECT\b', node.value, re.I):
                result.extend(_sql(node.value, file, node.lineno - 1))
        return result
    # SQL literals only; comments containing SQL are never analyzed.
    for match in TOKENS.finditer(text):
        if match[0].startswith(('//', '/*')) or not re.search(r'\bSELECT\b', match[0], re.I):
            continue
        literal = match[0]
        prefix = 2 if literal.startswith('@"') else 1
        result.extend(_sql(literal[prefix:-1], file, _line(text, match.start()) - 1))
    return result


def read_plan(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Plano deve ser arquivo regular, sem link simbólico.')
    with path.open('rb') as stream:
        raw = stream.read(MAX_PLAN_BYTES + 1)
    if len(raw) > MAX_PLAN_BYTES:
        raise ValueError('Plano PostgreSQL excede 5 MB.')
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        raise ValueError('Plano PostgreSQL JSON inválido.') from None
    if not isinstance(data, list) or not data or not all(isinstance(x, dict) and isinstance(x.get('Plan'), dict) for x in data):
        raise ValueError('Use a saída JSON de EXPLAIN do PostgreSQL: [{"Plan": {...}}].')
    result, nodes, actual = [], 0, False
    stack = [entry['Plan'] for entry in reversed(data)]
    while stack:
        node = stack.pop()
        nodes += 1
        if nodes > MAX_PLAN_NODES:
            raise ValueError('Plano PostgreSQL excede 20000 nós.')
        if not isinstance(node, dict) or not isinstance(node.get('Node Type'), str):
            raise ValueError('Nó de plano PostgreSQL inválido.')
        def num(key):
            value = node.get(key, 0)
            if type(value) not in (int, float) or not 0 <= value < 1e15:
                raise ValueError('Métrica numérica PostgreSQL inválida: '+key)
            return value
        rows, loops, estimate = num('Actual Rows'), num('Actual Loops'), num('Plan Rows')
        actual |= 'Actual Rows' in node
        removed = num('Rows Removed by Filter')
        # Counters in EXPLAIN ANALYZE are per loop; compare on the same basis.
        flags = []
        if node['Node Type'] == 'Seq Scan' and removed >= 10_000 and removed >= max(rows, 1) * 10:
            flags.append('RP101')
        if 'Actual Rows' in node and loops > 0 and max(rows, estimate) >= 1000 and max(rows, estimate) >= max(min(rows, estimate), 1) * 10:
            flags.append('RP102')
        if node.get('Sort Space Type') == 'Disk' or num('Temp Written Blocks') > 0:
            flags.append('RP103')
        if loops >= 1000:
            flags.append('RP104')
        # No query text, filters, relation names, parameters or connection details are copied.
        evidence = f"nó {nodes}: {node['Node Type'][:60]}; linhas/loop={rows}; loops={loops}; estimativa/loop={estimate}; descartadas/loop={removed}; blocos temporários escritos={num('Temp Written Blocks')}"
        for rule in flags:
            result.append(make(rule, path.name, 1, evidence, measured=True))
            result[-1]['plan_node'] = nodes
        children = node.get('Plans', [])
        if not isinstance(children, list): raise ValueError('Plans deve ser uma lista.')
        stack.extend(reversed(children))
    return result, dict(file=path.name, nodes=nodes, actual_metrics=actual, status='imported')


def report(findings, files, *, enabled=True, partial=False, errors=(), plans=(), diff=None):
    levels = {'high': 0, 'medium': 1, 'low': 2}
    unique = {f['id']: f for f in findings}
    items = sorted(unique.values(), key=lambda f: (levels[f['priority']], f['file'], f['line'], f['rule']))
    return dict(enabled=enabled, status='disabled' if not enabled else 'partial' if partial or errors else 'review_required' if items else 'not_applicable' if not files and not plans else 'no_indicators',
                findings=items, summary={level: sum(f['priority'] == level for f in items) for level in levels},
                coverage=dict(files=files, partial=bool(partial or errors), diff=diff), errors=list(errors), plans=list(plans),
                scope='Análise estática local de C#/EF, Python, JavaScript/TypeScript e SQL; SQL literal em Java; planos PostgreSQL JSON importados explicitamente.',
                limitations=['Achados estáticos são hipóteses; ausência de achados não comprova boa performance.',
                             'Não conecta ao banco, não executa SQL/EXPLAIN, não aplica índices e não mede p95 ou throughput.',
                             'Não resolve chamadas entre arquivos, aliases de IQueryable, lazy loading implícito ou todos os ORMs. Loops C#/JS exigem chaves.',
                             'Planos importados podem estar desatualizados; métricas por nó não certificam a latência da aplicação.',
                             'Baseline e supressões de segurança não se aplicam à performance; --diff-base filtra apenas os achados estáticos.'])
