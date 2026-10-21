"""Adaptador OSV-Scanner: auditoria de lockfiles (rede per_query, mesmo consentimento de --dependencies).
Só lê lockfiles; nunca instala, restaura, compila ou usa --experimental-call-analysis."""
import json
import os
from pathlib import Path

from ..dependencies import _advisory
from .base import Adapter, ToolError, execute

LOCKFILES = {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'packages.lock.json', 'pom.xml',
             'gradle.lockfile', 'requirements.txt', 'poetry.lock', 'Pipfile.lock', 'go.mod', 'Cargo.lock',
             'composer.lock', 'Gemfile.lock'}
SKIP_DIRS = {'node_modules', '.git', 'bin', 'obj', 'dist', 'build', '.venv'}
DEV_GROUPS = {'dev', 'devdependencies', 'development', 'test'}
MAX_DEPTH = 3
LOCK_LIMIT = 5_000_000
V2_UNKNOWN = ('unknown command', 'flag provided but not defined')


def _is_lockfile(name):
    return name in LOCKFILES or name.endswith('.csproj')


def _lockfiles(root):
    """Lockfiles até MAX_DEPTH níveis de pasta, sem entrar em pastas de build/dependências."""
    root = Path(root)
    for current, dirs, files in os.walk(root):
        depth = len(Path(current).relative_to(root).parts)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS] if depth < MAX_DEPTH else []
        for name in files:
            if _is_lockfile(name):
                yield Path(current) / name


def _dict(value):
    return value if isinstance(value, dict) else {}


def _dicts(value):
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _summary(stderr):
    from ..scanner import redact
    lines = [line.strip() for line in str(stderr or '').splitlines() if line.strip()]
    return redact(lines[-1] if lines else 'sem detalhe')[:300]


def _fixed(vuln, name, ecosystem):
    """Versões corrigidas para o ecossistema do pacote (dependencies._advisory só cobre npm)."""
    fixed = set()
    for affected in _dicts(vuln.get('affected')):
        package = affected.get('package')
        if not isinstance(package, dict) or package.get('ecosystem') != ecosystem or package.get('name') != name:
            continue
        for rng in _dicts(affected.get('ranges')):
            for event in _dicts(rng.get('events')):
                if isinstance(event.get('fixed'), str):
                    fixed.add(event['fixed'])
    return sorted(fixed)


def _lock_states(root, source):
    """(name, version) -> 'prod' | 'dev' a partir de um package-lock.json do próprio projeto. Vazio se não for."""
    path = _dict(source).get('path')
    if not isinstance(path, str) or Path(path.replace('\\', '/')).name != 'package-lock.json':
        return {}
    candidate = Path(path) if Path(path).is_absolute() else root / path
    try:
        if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_size > LOCK_LIMIT:
            return {}
        candidate.resolve().relative_to(root.resolve())
        lock = json.loads(candidate.read_text(encoding='utf-8', errors='replace'))
    except (OSError, ValueError):
        return {}
    states = {}
    for location, item in _dict(_dict(lock).get('packages')).items():
        if not location or not isinstance(item, dict):
            continue
        name = item.get('name') or location.rsplit('node_modules/', 1)[-1]
        version = item.get('version')
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        # Mesma regra de dependencies.check: dev/devOptional true; desconhecido conta como produção.
        if item.get('dev') is True or item.get('devOptional') is True:
            states.setdefault((name, version), 'dev')
        else:
            states[(name, version)] = 'prod'
    return states


class OsvScanner(Adapter):
    name = 'osv-scanner'
    binary = 'osv-scanner'
    network = 'per_query'
    axis = 'dependencies'

    def applies(self, root):
        return any(True for _ in _lockfiles(root))

    def run(self, root, workdir, tool, options):
        path, target = tool['path'], str(root)
        attempts = (
            [path, 'scan', 'source', '--format', 'json', '--recursive', target],
            [path, '--format', 'json', '--recursive', target],
        )
        for index, args in enumerate(attempts):
            result = execute(args, timeout=600, limit=50_000_000)
            if result.returncode == 128:  # sem pacotes ou lockfile reconhecido: não é falha da ferramenta
                return dict(no_lockfiles=True)
            if result.returncode in (0, 1):  # 1 = vulnerabilidades encontradas
                data = json.loads(result.stdout)
                if not isinstance(data, dict):
                    raise ToolError('saída JSON do osv-scanner inesperada')
                return data
            if index == 0 and result.returncode in (2, 127) and any(m in result.stderr for m in V2_UNKNOWN):
                continue  # osv-scanner v1: sem subcomando 'scan'
            raise ToolError(f'osv-scanner terminou com código {result.returncode}: ' + _summary(result.stderr))
        raise ToolError('osv-scanner não aceitou as opções de v1 nem de v2')

    def normalize(self, raw, root, tool):
        root = Path(root)
        scope = f"Lockfiles de todos os ecossistemas suportados pelo OSV-Scanner {tool.get('version')}."
        if raw.get('no_lockfiles'):
            warning = 'OSV-Scanner não encontrou lockfiles suportados.'
            dependencies = dict(status='incomplete', packages=0, vulnerabilities=[], errors=[], warnings=[warning],
                                skipped_local=0, scope=scope)
            return dict(findings=[], dependencies=dependencies, detail=warning)
        packages, vulnerabilities, warnings = set(), [], []
        for result in _dicts(raw.get('results')):
            lock = _lock_states(root, result.get('source'))
            for entry in _dicts(result.get('packages')):
                package = _dict(entry.get('package'))
                name, version, ecosystem = package.get('name'), package.get('version'), package.get('ecosystem')
                if not all(isinstance(value, str) for value in (name, version, ecosystem)):
                    continue
                packages.add((ecosystem, name, version))
                groups = {g.lower() for g in (entry.get('groups') or []) if isinstance(g, str)}
                json_dev = (entry.get('dev') is True or package.get('dev') is True
                            or bool(groups & DEV_GROUPS))
                state = lock.get((name, version))
                if state == 'prod':
                    reach = 'production'
                elif state == 'dev' or json_dev:
                    reach = 'dev_only'
                else:
                    reach = 'production'
                for vuln in _dicts(entry.get('vulnerabilities')):
                    if not isinstance(vuln.get('id'), str):
                        continue
                    details = _advisory(vuln, name)
                    details['fixed_in'] = _fixed(vuln, name, ecosystem)
                    vulnerabilities.append(dict(package=name, version=version, ecosystem=ecosystem,
                                                advisory=vuln['id'], reachability=reach, **details))
        if not packages:
            warnings.append('Nenhum pacote encontrado nos lockfiles; nada foi comprovado.')
        status = 'failed' if vulnerabilities else 'passed' if packages else 'incomplete'
        dependencies = dict(status=status, packages=len(packages), vulnerabilities=vulnerabilities,
                            errors=[], warnings=warnings, skipped_local=0, scope=scope)
        return dict(findings=[], dependencies=dependencies,
                    detail=f'{len(packages)} pacote(s) consultados no OSV-Scanner.')
