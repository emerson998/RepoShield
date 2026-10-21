"""Trivy config scan (IaC: Dockerfile, Terraform, compose and Kubernetes/Helm YAML)."""
import json
import os
from pathlib import Path

from .base import Adapter, ToolError, execute, external_finding, read_bounded

SKIP_DIRS = {'node_modules', '.git', 'bin', 'obj', 'dist', 'build', '.venv'}
MAX_DEPTH = 4


def _is_iac(path):
    name = path.name.lower()
    if name.startswith('dockerfile') or name.endswith('.tf'):
        return True
    if name.startswith('docker-compose') and name.endswith(('.yml', '.yaml')):
        return True
    if name.endswith(('.yml', '.yaml')):
        try:
            with path.open('rb') as fh:
                head = fh.read(2048).decode('utf-8', 'replace')
        except OSError:
            return False
        return 'apiVersion:' in head and 'kind:' in head
    return False


def _relative(path, root):
    p = Path(str(path))
    if not p.is_absolute():
        return p.as_posix()
    try:
        return p.relative_to(Path(root)).as_posix()
    except ValueError:
        return p.as_posix()


class Trivy(Adapter):
    name = 'trivy'
    binary = 'trivy'
    network = 'db_download'
    axis = 'iac'
    version_args = ('--version',)

    def applies(self, root):
        root = Path(root)
        for dirpath, dirnames, filenames in os.walk(root):
            depth = len(Path(dirpath).relative_to(root).parts)
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS] if depth < MAX_DEPTH else []
            for name in filenames:
                path = Path(dirpath)/name
                if not path.is_symlink() and _is_iac(path):
                    return True
        return False

    def run(self, root, workdir, tool, options):
        report = Path(workdir)/'trivy.json'
        args = [tool['path'], 'config', '--format', 'json', '--output', str(report), '--quiet',
                '--exit-code', '0', str(root)]
        result = execute(args, timeout=600)
        if result.returncode != 0:
            raise ToolError(f'trivy saiu com código {result.returncode}.')
        return dict(text=read_bounded(report))

    def normalize(self, raw, root, tool):
        data = json.loads(raw['text'])
        findings = []
        for result in data.get('Results') or []:
            target = _relative(result.get('Target', ''), root)
            for item in result.get('Misconfigurations') or []:
                if item.get('Status') != 'FAIL':
                    continue
                rule = item.get('ID') or item.get('AVDID') or 'misconfiguration'
                cause = item.get('CauseMetadata') or {}
                kwargs = {}
                resolution = str(item.get('Resolution') or '')[:500]
                if resolution:
                    kwargs['recommendation'] = resolution
                line = cause.get('StartLine')
                evidence = item.get('Message', '')
                # Ex.: DS-0002 (sem USER) não aponta linha; external_finding usa 1, então deixa isso explícito.
                if not isinstance(line, int) or line < 1:
                    evidence = f'{evidence} (linha não informada pelo Trivy)'
                findings.append(external_finding(
                    tool='trivy', version=tool['version'], rule_id=rule,
                    severity=str(item.get('Severity') or 'UNKNOWN').lower(),
                    title=item.get('Title') or rule, file=target, line=line,
                    evidence=evidence, category='iac', cwe=None, **kwargs))
        return dict(findings=findings, detail='Checagens de configuração IaC do Trivy (apenas falhas).')
