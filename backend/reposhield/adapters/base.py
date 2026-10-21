"""Optional external scanners. A missing tool is never an error and never a pass.

Safety contract for every adapter:
- no shell, no stdin, minimal environment, working directory outside the project;
- the project is only read; never install, restore or build it;
- bounded time and output; network use is declared and gated by explicit consent.
"""
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

# none: fully offline. rules_download/db_download: fetch rules or databases, send nothing
# from the project. per_query: sends package names/versions (same consent as --dependencies).
NETWORK = ('none', 'rules_download', 'db_download', 'per_query')
SEVERITIES = ('critical', 'high', 'medium', 'low')
ENV_KEEP = ('PATH', 'PATHEXT', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'HOME', 'USERPROFILE', 'APPDATA',
            'LOCALAPPDATA', 'TEMP', 'TMP', 'LANG', 'LC_ALL', 'XDG_CACHE_HOME')
# Repository-controlled git settings that can run arbitrary programs during log/diff.
UNSAFE_GIT = re.compile(r'(?im)^\s*(?:textconv|external|fsmonitor|hookspath|askpass|pager|program|sshcommand|editor)\s*=')
# Chaves de `git config --list` que podem executar programas, mesmo fora do início de linha.
UNSAFE_GIT_KEYS = frozenset({
    'diff.external', 'core.fsmonitor', 'core.hookspath', 'core.pager', 'core.sshcommand', 'core.askpass',
    'core.attributesfile', 'core.editor', 'core.gitproxy', 'credential.helper', 'sequence.editor'})


def _inside(path, base):
    return path == base or base in path.parents


def resolve_binary(name, root=None):
    """Procura `name` no PATH ignorando entradas relativas, '.', e diretórios dentro de root ou do cwd.

    Evita executar um binário plantado no projeto (o Windows procura no diretório atual).
    """
    cwd = Path.cwd().resolve()
    blocked = [cwd] + ([Path(root).resolve()] if root is not None else [])
    safe = []
    for entry in os.environ.get('PATH', '').split(os.pathsep):
        if entry in ('', '.') or not os.path.isabs(entry) or not os.path.isdir(entry):
            continue
        resolved = Path(entry).resolve()
        if any(_inside(resolved, base) for base in blocked):
            continue
        safe.append(entry)
    if not safe:
        return None
    found = shutil.which(name, path=os.pathsep.join(safe))
    # Com o cwd em PATH, shutil.which pode devolver um binário do próprio cwd: falha fechada.
    if found is None or any(_inside(Path(found).resolve(), base) for base in blocked):
        return None
    return found


class ToolError(Exception):
    """Tool ran but its result is unusable; reported as 'failed', never as a pass."""


class Adapter:
    name = ''           # e.g. 'gitleaks'
    binary = ''         # executable looked up on PATH
    network = 'none'    # one of NETWORK
    axis = ''           # secrets | dependencies | sast | iac | runtime
    version_args = ('--version',)

    def available(self, root=None):
        """Return dict(path, version) or None when the binary is not installed."""
        path = resolve_binary(self.binary, root)
        if not path:
            return None
        try:
            out = execute([path, *self.version_args], timeout=30, limit=20_000).stdout
        except (OSError, ToolError, subprocess.TimeoutExpired):
            return dict(path=path, version='unknown')
        found = re.search(r'\d+\.\d+(?:\.\d+)?', out)
        return dict(path=path, version=found[0] if found else 'unknown')

    def applies(self, root):
        return True

    def run(self, root, workdir, tool, options):
        """Execute the tool. Write outputs only inside workdir. Return raw data for normalize."""
        raise NotImplementedError

    def normalize(self, raw, root, tool):
        """Return dict(findings=[...]) and optionally dependencies=<dependencies.check-like dict>."""
        raise NotImplementedError


class Result:
    def __init__(self, returncode, stdout, stderr):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def execute(args, *, cwd=None, timeout=300, limit=20_000_000):
    """Run a binary without shell; stdout/stderr go to temp files so memory stays bounded."""
    args = [str(a) for a in args]
    if not os.path.isabs(args[0]):
        resolved = resolve_binary(args[0], cwd)
        if resolved is None:
            raise ToolError(f'{args[0]} não encontrado em PATH seguro')
        args[0] = resolved
    env = {k: os.environ[k] for k in ENV_KEEP if k in os.environ}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0', GIT_OPTIONAL_LOCKS='0', NO_COLOR='1',
               NoDefaultCurrentDirectoryInExePath='1')
    with tempfile.TemporaryDirectory(prefix='reposhield-exec-') as tmp:
        out_path, err_path = Path(tmp)/'out', Path(tmp)/'err'
        with open(out_path, 'wb') as out, open(err_path, 'wb') as err:
            proc = subprocess.run(args, cwd=cwd or tmp, env=env, stdin=subprocess.DEVNULL,
                                  stdout=out, stderr=err, timeout=timeout, shell=False, check=False)
        if out_path.stat().st_size > limit:
            raise ToolError('saída excedeu o limite')
        return Result(proc.returncode, out_path.read_text(encoding='utf-8', errors='replace'),
                      err_path.read_text(encoding='utf-8', errors='replace')[-2000:])


def read_bounded(path, limit=50_000_000):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ToolError('relatório da ferramenta não foi gerado')
    if path.stat().st_size > limit:
        raise ToolError('relatório da ferramenta excedeu o limite')
    return path.read_text(encoding='utf-8', errors='replace')


def git_history_safe(root):
    """True only for a plain .git directory whose config cannot make git run programs."""
    git = Path(root)/'.git'
    if git.is_symlink() or not git.is_dir():
        return False
    config = git/'config'
    if config.is_symlink():
        return False
    worktree = git/'config.worktree'
    if worktree.exists() or worktree.is_symlink():
        return False
    text = config.read_text(encoding='utf-8', errors='replace') if config.is_file() else ''
    if UNSAFE_GIT.search(text) or re.search(r'(?im)^\s*\[include', text):
        return False
    if not config.is_file():
        return True  # sem arquivo de config não há chave a verificar
    # Pega o que a regex acima não vê, como '[diff "x"] textconv = ...' na mesma linha do cabeçalho.
    try:
        git_bin = resolve_binary('git', root)
        if git_bin is None:
            return False
        result = execute([git_bin, 'config', '--file', str(config), '--list', '-z', '--no-includes'],
                         timeout=30, limit=1_000_000)
        if result.returncode != 0:
            return False
        return not any(_unsafe_config_key(item.split('\n', 1)[0].lower()) for item in result.stdout.split('\0') if item)
    except (OSError, ToolError, subprocess.TimeoutExpired):
        return False


def _unsafe_config_key(key):
    return (key.endswith(('.textconv', '.command', '.program')) or key in UNSAFE_GIT_KEYS
            or key.startswith(('include.', 'includeif.', 'filter.')) or key == 'extensions.worktreeconfig')


def severity_from(level=None, score=None):
    """SARIF level and/or security-severity (CVSS-like number) to RepoShield severity."""
    try:
        value = float(score) if score is not None else None
    except (TypeError, ValueError):
        value = None
    if value is not None:
        return 'critical' if value >= 9 else 'high' if value >= 7 else 'medium' if value >= 4 else 'low'
    return {'error': 'high', 'warning': 'medium', 'note': 'low', 'none': 'low'}.get(str(level or '').lower(), 'medium')


def external_finding(*, tool, version, rule_id, severity, title, file, line, evidence, category, cwe=None,
                     recommendation='Confirme o achado no código e corrija conforme a orientação da ferramenta de origem.',
                     confidence='medium'):
    """Finding with the same shape as scanner.finding, for results produced by another tool."""
    from ..scanner import redact
    severity = severity if severity in SEVERITIES else 'medium'
    line = line if isinstance(line, int) and line > 0 else 1
    file = re.sub(r'^(?:\./)+', '', str(file or '').replace('\\', '/')) or '(desconhecido)'
    rule = f'{tool}/{rule_id}'
    evidence = redact(str(evidence or ''))[:350]
    key = f'{rule}:{file}:{line}:{evidence}'
    return dict(id=hashlib.sha256(key.encode()).hexdigest()[:16],
                fingerprint=hashlib.sha256(f'{file}:{line}:{cwe or rule}'.encode()).hexdigest()[:16],
                rule=rule, severity=severity, title=str(title)[:200], file=file, line=line, evidence=evidence,
                confidence=confidence, status='needs_review', source=f'{tool}@{version}',
                recommendation=recommendation, category=category, cwe=cwe,
                validation='Confirme no código e em ambiente de teste; o resultado vem de ferramenta externa.')


def run_adapters(root, adapters, *, requested, allow_downloads=False, dependencies_consent=False, options=None):
    """Run requested adapters. Returns dict(tools=[record], findings=[...], dependencies=None|dict).

    requested: set of adapter names, or {'auto'} for every installed adapter that applies.
    A record status is one of: executed, not_installed, not_applicable, skipped_network, failed.
    options: extra values passed to adapter.run (e.g. runtime base_url for ZAP).
    """
    root = Path(root)
    records, findings, dependencies = [], [], None
    for adapter in adapters:
        if 'auto' not in requested and adapter.name not in requested:
            continue
        record = dict(name=adapter.name, axis=adapter.axis, network=adapter.network, version=None,
                      status='not_installed', findings=0, detail='')
        records.append(record)
        tool = adapter.available(root)
        if tool is None:
            record['detail'] = f'{adapter.binary} não encontrado no PATH.'
            continue
        record['version'] = tool['version']
        if not adapter.applies(root):
            record['status'], record['detail'] = 'not_applicable', 'Nada a analisar neste projeto.'
            continue
        if adapter.network == 'per_query' and not dependencies_consent:
            record['status'], record['detail'] = 'skipped_network', 'Envia nomes/versões de pacotes; exige --dependencies.'
            continue
        if adapter.network in {'rules_download', 'db_download'} and not allow_downloads:
            record['status'], record['detail'] = 'skipped_network', 'Baixa regras ou base de dados; exige --allow-downloads.'
            continue
        try:
            with tempfile.TemporaryDirectory(prefix=f'reposhield-{adapter.name}-') as workdir:
                raw = adapter.run(root, Path(workdir), tool, dict(options or {}, allow_downloads=allow_downloads))
                out = adapter.normalize(raw, root, tool)
        # json.JSONDecodeError já é ValueError.
        except (OSError, ValueError, ToolError, subprocess.TimeoutExpired, KeyError, TypeError, AttributeError) as exc:
            record['status'], record['detail'] = 'failed', f'{type(exc).__name__}: {str(exc)[:300]}'
            continue
        record['status'] = 'executed'
        record['findings'] = len(out.get('findings', []))
        record['detail'] = out.get('detail', '')
        findings.extend(out.get('findings', []))
        if out.get('dependencies') is not None:
            dependencies = out['dependencies']
    return dict(tools=records, findings=findings, dependencies=dependencies)
