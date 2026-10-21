"""Semgrep adapter using RepoShield's embedded rules only (no registry, no network)."""
import json
import re
from pathlib import Path

from .base import Adapter, ToolError, execute, external_finding, read_bounded

RULES_DIR = Path(__file__).parent.parent/'rules'/'semgrep'
SEVERITY = {'ERROR': 'high', 'WARNING': 'medium', 'INFO': 'low'}
CWE = re.compile(r'CWE-\d+')


def _rule_count():
    text = read_bounded(RULES_DIR/'reposhield.yml')
    return len(re.findall(r'(?m)^\s*-\s+id:', text))


def _rule_id(check_id):
    # Semgrep prefixes local rule ids with the config directory path; keep only our id.
    check_id = str(check_id or 'regra')
    at = check_id.rfind('reposhield.')
    return check_id[at:] if at >= 0 else check_id.rsplit('.', 1)[-1]


def _relative(path, root):
    p = Path(str(path))
    if not p.is_absolute():
        return p.as_posix()
    try:
        return p.relative_to(Path(root)).as_posix()
    except ValueError:
        return p.as_posix()


class Semgrep(Adapter):
    name = 'semgrep'
    binary = 'semgrep'
    network = 'none'
    axis = 'sast'

    def run(self, root, workdir, tool, options):
        report = Path(workdir)/'semgrep.json'
        args = [tool['path'], 'scan', '--config', str(RULES_DIR), '--json', '--metrics=off',
                '--disable-version-check', '--quiet', '--timeout', '30', '--max-target-bytes', '1000000',
                '--output', str(report), str(root)]
        result = execute(args, timeout=900)
        if result.returncode not in (0, 1):
            raise ToolError(f'semgrep saiu com código {result.returncode}.')
        return dict(text=read_bounded(report))

    def normalize(self, raw, root, tool):
        data = json.loads(raw['text'])
        findings = []
        for item in data.get('results') or []:
            extra = item.get('extra') or {}
            meta = extra.get('metadata') or {}
            cwe_src = meta.get('cwe', '')
            if isinstance(cwe_src, list):
                cwe_src = ' '.join(map(str, cwe_src))
            match = CWE.search(str(cwe_src))
            lines = extra.get('lines') or ''
            evidence = extra.get('message', '') if not lines or 'requires login' in lines else lines
            findings.append(external_finding(
                tool='semgrep', version=tool['version'], rule_id=_rule_id(item.get('check_id')),
                severity=SEVERITY.get(str(extra.get('severity', '')).upper(), 'medium'),
                title=str(extra.get('message', ''))[:200], file=_relative(item.get('path', ''), root),
                line=(item.get('start') or {}).get('line'), evidence=evidence, category='sast',
                cwe=match.group(0) if match else None))
        rule_errors = sum(1 for e in data.get('errors') or [] if str(e.get('level', '')).lower() == 'error')
        detail = f'Regras RepoShield embutidas ({_rule_count()} regras).'
        if rule_errors:
            detail += f' {rule_errors} erro(s) reportado(s) pelo Semgrep.'
        return dict(findings=findings, detail=detail)
