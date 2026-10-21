"""Importador SARIF genérico. Só lê JSON; nunca executa nada."""
import json
import os
import re
from urllib.parse import unquote

from .base import external_finding, severity_from

MAX_RESULTS = 20_000
SCHEMA_ERROR = 'SARIF inválido'


def _dict(value):
    return value if isinstance(value, dict) else {}


def _list(value):
    return value if isinstance(value, list) else []


def _dicts(value):
    return [item for item in _list(value) if isinstance(item, dict)]


def _strings(value):
    return [item for item in _list(value) if isinstance(item, str)]


def _cwe(tags):
    for tag in tags:
        found = re.search(r'(?i)(?:^|/)cwe-(\d{1,6})$', tag.strip())
        if found:
            return f'CWE-{int(found[1])}'
    return None


def _location(uri, root):
    """Caminho relativo ao projeto. Absoluto fora da raiz vira só o nome, prefixado por (externo)/."""
    path = unquote(uri).strip() if isinstance(uri, str) else ''
    if path.lower().startswith('file://'):
        path = path[7:]
    path = path.replace('\\', '/')
    if re.match(r'^/[A-Za-z]:/', path):
        path = path[1:]
    if not (path.startswith('/') or re.match(r'^[A-Za-z]:/', path)):
        if '..' in path.split('/'):
            return '(externo)/' + path.rsplit('/', 1)[-1]
        return re.sub(r'^(?:\./)+', '', path)
    if root is not None:
        base = os.path.normcase(os.path.normpath(str(root))).rstrip(os.sep) + os.sep
        if os.path.normcase(os.path.normpath(path)).startswith(base):
            return os.path.relpath(os.path.normpath(path), os.path.normpath(str(root))).replace('\\', '/')
    return '(externo)/' + path.rsplit('/', 1)[-1]


def _skip(result):
    """Ignora pass/notApplicable. Suprimidos na origem continuam como finding (ver disposition)."""
    return result.get('kind') in ('pass', 'notApplicable')


def import_sarif(text, *, default_tool='sarif', root=None, extra=None):
    """Converte SARIF em findings no formato de external_finding.

    extra(result) -> str, opcional: texto anexado à evidence (ex.: commit do gitleaks).
    """
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        raise ValueError(SCHEMA_ERROR) from None
    if not isinstance(data, dict) or not isinstance(data.get('runs'), list):
        raise ValueError(SCHEMA_ERROR)
    runs = data['runs']
    total = sum(len(_list(_dict(run).get('results'))) for run in runs)
    if total > MAX_RESULTS:
        raise ValueError(f'SARIF excede o limite de {MAX_RESULTS} results')

    findings = []
    for run in runs:
        run = _dict(run)
        driver = _dict(_dict(run.get('tool')).get('driver'))
        tool = re.sub(r'[^a-z0-9._-]', '', str(driver.get('name') or '').lower()) or default_tool
        version = str(driver.get('version') or driver.get('semanticVersion') or 'unknown')
        rules = [_dict(rule) for rule in _list(driver.get('rules'))]
        by_id = {rule['id']: rule for rule in rules if isinstance(rule.get('id'), str)}

        for result in _dicts(run.get('results')):
            if _skip(result):
                continue
            ref = result.get('ruleId') if isinstance(result.get('ruleId'), str) else None
            index = result.get('ruleIndex')
            by_index = isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(rules)
            rule = by_id.get(ref) or (rules[index] if by_index else {})
            rule_id = str(ref or rule.get('id') or 'unknown')

            props_rule, props_result = _dict(rule.get('properties')), _dict(result.get('properties'))
            score = props_rule.get('security-severity')
            if score is None:
                score = props_result.get('security-severity')
            level = result.get('level') or _dict(rule.get('defaultConfiguration')).get('level')
            tags = _strings(props_rule.get('tags')) + _strings(props_result.get('tags'))

            if 'gitleaks' in tool or 'secret' in rule_id.lower() or any('secret' in tag.lower() for tag in tags):
                category = 'secrets'
            elif ('osv' in tool or 'trivy' in tool) and re.search(r'(?i)cve-\d|ghsa-', rule_id):
                category = 'dependencies'
            else:
                category = 'sast'

            # No truncation here: external_finding redacts the whole text before cutting it.
            message = _dict(result.get('message')).get('text')
            evidence = message if isinstance(message, str) else ''
            if extra is not None:
                note = extra(result)
                if note:
                    evidence = f'{evidence} | {note}' if evidence else note

            physical = _dict(_dict(next(iter(_dicts(result.get('locations'))), {})).get('physicalLocation'))
            uri = _dict(physical.get('artifactLocation')).get('uri')
            line = _dict(physical.get('region')).get('startLine')

            title = _dict(rule.get('shortDescription')).get('text') or rule.get('name') or rule_id
            help_text = _dict(rule.get('help')).get('text')
            kwargs = {}
            if isinstance(help_text, str) and help_text.strip():
                kwargs['recommendation'] = help_text.strip()[:500]

            item = external_finding(
                tool=tool, version=version, rule_id=rule_id,
                severity=severity_from(level if isinstance(level, str) else None, score),
                title=str(title)[:200], file=_location(uri, root), line=line, evidence=evidence,
                category=category, cwe=_cwe(tags), **kwargs)
            # Suppressed in the source tool (any status but 'rejected'): kept, marked, and flagged so assurance.classify respects it.
            active = [s for s in _dicts(result.get('suppressions')) if s.get('status') != 'rejected']
            if active:
                just = active[0].get('justification')
                item.update(disposition='suppressed', source_suppressed=True, suppressed_by=dict(
                    justification=(just if isinstance(just, str) and just.strip() else 'Suprimido na ferramenta de origem')[:300],
                    author='ferramenta de origem', expires=None, match='sarif'))
            findings.append(item)
    return findings
