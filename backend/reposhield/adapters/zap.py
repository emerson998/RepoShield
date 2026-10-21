"""OWASP ZAP baseline against a local origin declared in runtime.base_url. Never active scan. Sem zap-baseline no PATH, usa a imagem Docker local (sem baixar)."""
import ipaddress
import json
import os
import re
import subprocess
import sys
from urllib.parse import urlsplit, urlunsplit

from .base import Adapter, ToolError, execute, external_finding, read_bounded, resolve_binary

SEVERITY = {'3': 'high', '2': 'medium', '1': 'low', '0': 'low'}
IMAGE = 'ghcr.io/zaproxy/zaproxy:stable'


def _loopback(url):
    """Same rule as reposhield/runtime.py: http(s), loopback IP literal, no credentials, path, query or fragment."""
    if not isinstance(url, str):
        return False
    try:
        parts = urlsplit(url)
        loopback = ipaddress.ip_address(parts.hostname or '').is_loopback
        return (parts.scheme in {'http', 'https'} and loopback and not parts.username and not parts.password
                and parts.path in {'', '/'} and not parts.query and not parts.fragment)
    except ValueError:
        return False


def _docker_url(url):
    """Mesma origem vista de dentro do container: host trocado por host.docker.internal, porta preservada."""
    parts = urlsplit(url)
    port = f':{parts.port}' if parts.port else ''
    return urlunsplit((parts.scheme, f'host.docker.internal{port}', parts.path, parts.query, parts.fragment))


class ZapBaseline(Adapter):
    name = 'zap'
    binary = 'zap-baseline.py'
    network = 'none'
    axis = 'runtime'
    version_args = ('-h',)

    def available(self, root=None):
        tool = super().available(root)
        if tool is not None:
            return dict(tool, mode='native')
        docker = resolve_binary('docker', root)
        if docker is None:
            return None
        # Imagem não baixada = não instalado. Nunca baixa aqui.
        try:
            inspect = execute([docker, 'image', 'inspect', IMAGE, '--format', '{{.Id}}'], timeout=30, limit=20_000)
        except (OSError, ToolError, subprocess.TimeoutExpired):
            return None
        if inspect.returncode != 0:
            return None
        try:
            listing = execute([docker, 'run', '--rm', '--pull', 'never', '--network', 'none', '--entrypoint', 'ls',
                               IMAGE, '/zap'], timeout=60, limit=200_000).stdout
        except (OSError, ToolError, subprocess.TimeoutExpired):
            listing = ''
        found = re.search(r'zap-(\d+\.\d+\.\d+)\.jar', listing)
        return dict(path=docker, version=found[1] if found else 'unknown', mode='docker')

    def run(self, root, workdir, tool, options):
        base_url = options.get('base_url')
        if not _loopback(base_url):
            raise ToolError('ZAP só roda contra origem loopback configurada em runtime.base_url.')
        if tool.get('mode') == 'docker':
            if sys.platform.startswith('linux'):
                target, network = base_url, ['--network', 'host']
            else:
                target, network = _docker_url(base_url), []
            if os.name == 'posix':
                # O usuário 'zap' do container precisa gravar zap.json; o workdir só tem saídas nossas.
                os.chmod(workdir, 0o777)
            args = [tool['path'], 'run', '--rm', '--pull', 'never', *network, '-v', f'{workdir}:/zap/wrk:rw',
                    IMAGE, 'zap-baseline.py', '-t', target, '-J', 'zap.json', '-I', '-s']
        else:
            target = base_url
            args = [tool['path'], '-t', base_url, '-J', 'zap.json', '-I', '-s']
        result = execute(args, cwd=workdir, timeout=900)
        if result.returncode not in (0, 1, 2):
            raise ToolError(f'zap-baseline saiu com código {result.returncode}.')
        return dict(text=read_bounded(workdir/'zap.json'), base_url=base_url, target_url=target)

    def normalize(self, raw, root, tool):
        data = json.loads(raw['text'])
        configured, target = raw['base_url'], raw.get('target_url')
        findings = []
        for site in data.get('site') or []:
            for alert in site.get('alerts') or []:
                instances = alert.get('instances') or []
                evidence = f"{instances[0].get('uri', '')} {instances[0].get('method', '')}" if instances else ''
                if target and target != configured and evidence.startswith(target.rstrip('/')):
                    # Relatório mostra a URL configurada pelo usuário, não o host.docker.internal.
                    evidence = configured.rstrip('/') + evidence[len(target.rstrip('/')):]
                cweid = str(alert.get('cweid', ''))
                cwe = f'CWE-{cweid}' if cweid.isdigit() and int(cweid) > 0 else None
                solution = re.sub(r'<[^>]+>', '', str(alert.get('solution') or '')).strip()[:500]
                kwargs = {'recommendation': solution} if solution else {}
                findings.append(external_finding(
                    tool='zap', version=tool['version'], rule_id=str(alert.get('pluginid') or 'alerta'),
                    severity=SEVERITY.get(str(alert.get('riskcode', '')), 'medium'),
                    title=alert.get('alert') or alert.get('name') or 'alerta',
                    file=f"runtime:{raw['base_url']}", line=1, evidence=evidence, category='runtime', cwe=cwe,
                    **kwargs))
        return dict(findings=findings, detail='OWASP ZAP baseline (sem active scan).')
