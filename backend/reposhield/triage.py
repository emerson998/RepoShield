"""Triagem contínua: chave estável, supressões revisáveis, linha de base e filtro por diff.

Funções puras: não gravam arquivos e não executam git diretamente (o `runner` é injetado).
"""
import hashlib
import json
import re
from datetime import date

MAX_BASELINE_CHARS = 20 * 1024 * 1024
MAX_SUPPRESSION_DAYS = 365
_BASE_REF_RE = re.compile(r'[A-Za-z0-9._/@^~-]{1,200}')
_DATE_RE = re.compile(r'\d{4}-\d{2}-\d{2}')
_HUNK_RE = re.compile(r'^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')
_ID_FIELDS = ('fingerprint', 'stable_key', 'id')
_BASELINE_ERROR = 'Linha de base inválida: use o relatório JSON de um scan anterior.'


def _norm(evidence):
    text = re.sub(r'\s+', ' ', str(evidence or '').lower()).strip()
    return re.sub(r'\d+', '#', text)[:200]


def _group_key(finding):
    return (str(finding.get('file') or ''), str(finding.get('cwe') or finding.get('rule') or ''), _norm(finding.get('evidence')))


def _line(finding):
    try:
        return int(finding.get('line') or 0)
    except (TypeError, ValueError):
        return 0


def stable_key(finding, occurrence):
    """Chave que sobrevive a mudança de linha: não depende do número da linha."""
    file, cwe_or_rule, norm = _group_key(finding)
    return hashlib.sha256(f'{file}|{cwe_or_rule}|{norm}|{occurrence}'.encode()).hexdigest()[:16]


def assign_keys(findings):
    """Grava `stable_key` em cada finding. Duplicatas recebem occurrence 0, 1, 2... na ordem (file, line)."""
    counters = {}
    for finding in sorted(findings, key=lambda f: (str(f.get('file') or ''), _line(f))):
        group = _group_key(finding)
        occurrence = counters.get(group, 0)
        counters[group] = occurrence + 1
        finding['stable_key'] = stable_key(finding, occurrence)
    return findings


def load_suppressions(config, today):
    """Valida config['suppressions'] e devolve (regras_válidas, erros)."""
    if not isinstance(config, dict) or 'suppressions' not in config:
        return [], []
    items = config['suppressions']
    if not isinstance(items, list):
        return [], ["'suppressions' deve ser uma lista."]
    rules, errors = [], []
    for index, item in enumerate(items, start=1):
        error = _validate_suppression(item, index, today, rules)
        if error:
            errors.append(f'Supressão #{index}: {error}')
    return rules, errors


def _validate_suppression(item, index, today, rules):
    if not isinstance(item, dict):
        return 'deve ser um objeto.'
    id_fields = [k for k in _ID_FIELDS if item.get(k) is not None]
    has_pair = item.get('rule') is not None or item.get('file') is not None
    if len(id_fields) + (1 if has_pair else 0) != 1:
        return 'informe exatamente um critério: fingerprint, stable_key, id, ou rule + file.'
    if id_fields:
        if item.get('line') is not None:
            return 'line só pode ser usado junto com rule e file.'
        field = id_fields[0]
        value = item[field]
        if not isinstance(value, str) or not value.strip():
            return f'{field} deve ser uma string não vazia.'
        match = dict(field=field, value=value.strip(), rule=None, file=None, line=None)
    else:
        rule, file = item.get('rule'), item.get('file')
        if not isinstance(rule, str) or not rule.strip() or not isinstance(file, str) or not file.strip():
            return 'rule e file devem ser strings não vazias.'
        line = item.get('line')
        if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
            return 'line deve ser um inteiro positivo.'
        match = dict(field='rule+file', value=None, rule=rule.strip(), file=file.strip(), line=line)
    justification = item.get('justification')
    if not isinstance(justification, str) or len(justification.strip()) < 10:
        return 'justification é obrigatória (mínimo de 10 caracteres).'
    author = item.get('author')
    if not isinstance(author, str) or not author.strip():
        return 'author é obrigatório.'
    expires = item.get('expires')
    if not isinstance(expires, str) or not _DATE_RE.fullmatch(expires):
        return 'expires deve estar no formato AAAA-MM-DD.'
    try:
        expires_date = date.fromisoformat(expires)
    except ValueError:
        return f'expires é uma data inválida: {expires}.'
    if (expires_date - today).days > MAX_SUPPRESSION_DAYS:
        return f'expires excede {MAX_SUPPRESSION_DAYS} dias a partir de hoje.'
    rules.append(dict(match, index=index, justification=justification.strip(), author=author.strip(),
                      expires=expires_date, expires_text=expires))
    return None


def _matches(rule, finding):
    if rule['field'] != 'rule+file':
        return finding.get(rule['field']) == rule['value']
    if finding.get('rule') != rule['rule'] or finding.get('file') != rule['file']:
        return False
    return rule['line'] is None or _line(finding) == rule['line']


def apply_suppressions(findings, rules, today):
    """Marca como suprimidos os achados casados por regras válidas e não expiradas. Devolve avisos."""
    warnings = []
    for rule in rules:
        n = rule['index']
        matched = [f for f in findings if _matches(rule, f)]
        expired = rule['expires'] < today
        if not matched:
            if expired:
                warnings.append(f'Supressão #{n} expirada e sem achado correspondente; remova-a.')
            else:
                warnings.append(f'Supressão #{n} não corresponde a nenhum achado; remova-a.')
            continue
        if expired:
            warnings.append(f"Supressão #{n} expirou em {rule['expires_text']}; achado voltou a contar.")
            continue
        if rule['field'] == 'rule+file' and rule['line'] is None and any(f.get('severity') == 'critical' for f in matched):
            warnings.append(f'Supressão #{n} não aplicada: achado critical exige match por fingerprint, stable_key, id ou line.')
            continue
        for finding in matched:
            if rule['field'] == 'rule+file' and rule['line'] is None and finding.get('severity') == 'critical':
                continue
            finding['disposition'] = 'suppressed'
            finding['suppressed_by'] = dict(justification=rule['justification'], author=rule['author'],
                                            expires=rule['expires_text'], match=rule['field'])
    return warnings


def load_baseline(text):
    """Lê o JSON de um relatório anterior e devolve o conjunto de stable_key."""
    if not isinstance(text, str):
        raise ValueError(_BASELINE_ERROR)
    if len(text) > MAX_BASELINE_CHARS:
        raise ValueError('Linha de base excede 20 MB.')
    try:
        data = json.loads(text)
    except ValueError:
        raise ValueError(_BASELINE_ERROR) from None
    if not isinstance(data, dict) or not isinstance(data.get('findings'), list):
        raise ValueError(_BASELINE_ERROR)
    copies = [dict(f) for f in data['findings'] if isinstance(f, dict)]
    if any(not f.get('stable_key') for f in copies):
        assign_keys(copies)
    return {f['stable_key'] for f in copies if f.get('stable_key')}


def apply_baseline(findings, keys):
    """Marca cada achado como 'existing' ou 'new'. Achados existentes sem decisão viram 'baseline'.

    Os achados precisam de `stable_key` (ver assign_keys); sem ele são tratados como 'new'.
    """
    counts = dict(new=0, existing=0)
    for finding in findings:
        if finding.get('stable_key') in keys:
            finding['baseline'] = 'existing'
            # Segredo não vira 'baseline': a mesma chave pode esconder outro valor trocado na mesma linha.
            if finding.get('category') != 'secrets' and finding.get('disposition') in (None, 'review_required'):
                finding['disposition'] = 'baseline'
            counts['existing'] += 1
        else:
            finding['baseline'] = 'new'
            counts['new'] += 1
    return counts


_SHA_RE = re.compile(r'[0-9a-f]{7,64}')
_OCTAL_ESC = re.compile(r'[0-3][0-7]{2}')
_C_ESCAPES = {'a': '\a', 'b': '\b', 't': '\t', 'n': '\n', 'v': '\v', 'f': '\f', 'r': '\r', '"': '"', '\\': '\\'}


class _All:
    """Arquivo não rastreado: toda linha conta como alterada."""

    def __contains__(self, item):
        return True


ALL_LINES = _All()


def _unquote(path):
    """Tira as aspas do cabeçalho do diff e decodifica escapes C (\\ooo, \\n, \\", ...) em utf-8."""
    if len(path) < 2 or path[0] != '"' or path[-1] != '"':
        return path
    body, raw, i = path[1:-1], bytearray(), 0
    while i < len(body):
        if body[i] != '\\' or i + 1 >= len(body):
            raw += body[i].encode('utf-8')
            i += 1
        elif _OCTAL_ESC.match(body, i + 1):
            raw.append(int(body[i + 1:i + 4], 8))
            i += 4
        else:
            raw += _C_ESCAPES.get(body[i + 1], body[i + 1]).encode('utf-8')
            i += 2
    return raw.decode('utf-8', errors='replace')


def changed_lines(root, base_ref, runner):
    """Linhas adicionadas/alteradas (lado novo) por arquivo, desde base_ref até o working tree.

    Inclui alterações não commitadas e arquivos não rastreados (todas as linhas). Usa o merge-base,
    como `git diff base...`, mas também vê o que ainda não foi commitado.
    `runner(args) -> (returncode, stdout)` executa o comando no repositório `root`
    (root não entra nos args; o runner injetado é quem o usa). Devolve None se o git falhar.
    """
    if not isinstance(base_ref, str) or not _BASE_REF_RE.fullmatch(base_ref) or base_ref.startswith('-'):
        raise ValueError('Referência base inválida.')
    returncode, stdout = runner(['git', '-c', 'core.fsmonitor=false', 'merge-base', base_ref, 'HEAD'])
    base = stdout.strip()
    if returncode != 0 or not _SHA_RE.fullmatch(base):
        return None
    args = ['git', '-c', 'core.fsmonitor=false', '-c', 'core.quotepath=false', '-c', 'diff.external=', 'diff',
            '--no-ext-diff', '--no-textconv', '--no-color', '--src-prefix=a/', '--dst-prefix=b/', '--unified=0',
            '--diff-filter=ACMR', '--no-renames', base, '--']
    returncode, stdout = runner(args)
    if returncode != 0:
        return None
    changed = _parse_hunks(stdout)
    returncode, stdout = runner(['git', '-c', 'core.fsmonitor=false', '-c', 'core.quotepath=false', 'ls-files',
                                 '--others', '--exclude-standard', '-z'])
    if returncode != 0:
        return None
    for path in stdout.split('\0'):
        if path:
            changed[path] = ALL_LINES
    return changed


def _parse_hunks(stdout):
    changed = {}
    current = None
    old_left = new_left = 0
    for line in stdout.splitlines():
        # Dentro de um hunk, linhas '+++'/'---' são conteúdo, não cabeçalho.
        if old_left > 0 or new_left > 0:
            if line.startswith('-') and old_left > 0:
                old_left -= 1
                continue
            if line.startswith('+') and new_left > 0:
                new_left -= 1
                continue
            if line.startswith('\\'):
                continue
            old_left = new_left = 0
        if line.startswith('+++ '):
            path = line[4:].split('\t')[0].strip()
            if path == '/dev/null':
                current = None
            else:
                path = _unquote(path)
                current = path[2:] if path.startswith('b/') else path
                if current is not None:
                    changed.setdefault(current, set())
            continue
        match = _HUNK_RE.match(line)
        if match:
            old_left = int(match.group(1)) if match.group(1) is not None else 1
            new_start = int(match.group(2))
            new_count = int(match.group(3)) if match.group(3) is not None else 1
            new_left = new_count
            if current is not None:
                changed[current].update(range(new_start, new_start + new_count))
    return changed


def apply_diff(findings, changed):
    """Mantém só os achados em linhas alteradas. Achados 'runtime:*' ou '(desconhecido)' são descartados."""
    if changed is None:
        raise ValueError('Diff indisponível; não é possível filtrar os achados.')
    kept = []
    for finding in findings:
        file = str(finding.get('file') or '')
        if file.startswith('runtime:') or file == '(desconhecido)' or file not in changed:
            continue
        if _line(finding) in changed[file]:
            kept.append(finding)
    return kept


def diff_scope_note(base_ref):
    return f'Somente linhas alteradas em relação a {base_ref}.'
