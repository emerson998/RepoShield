"""Bounded OSV lookup of exact npm lock versions. Never installs or runs project code."""
import json
import re
import urllib.request

_DETAILS = {}
_DETAIL_LIMIT = 300
_SEVERITY = {'CRITICAL': 'critical', 'HIGH': 'high', 'MODERATE': 'medium', 'MEDIUM': 'medium', 'LOW': 'low'}
# An advisory whose text describes a feature is not applicable when the lock has none of its packages.
CONDITIONS = [dict(package=r'^@angular/', text=r'(?i)\bSSR\b|server[- ]side render',
                   requires={'@angular/ssr', '@angular/platform-server', '@nguniversal/express-engine', '@nguniversal/common'},
                   note='Só se aplica com renderização no servidor (SSR), ausente neste lock.')]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _dicts(value):
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _fetch_detail(opener, advisory_id):
    if not re.fullmatch(r'[A-Za-z0-9._:-]{1,100}', advisory_id):
        return None
    try:
        with opener.open(urllib.request.Request(f'https://api.osv.dev/v1/vulns/{advisory_id}'), timeout=20) as response:
            raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            return None
        data = json.loads(raw)
    except (OSError, ValueError, TypeError, AttributeError):
        return None
    return data if isinstance(data, dict) else None


def _advisory(detail, name):
    if not isinstance(detail, dict):
        return dict(severity='unknown', cvss=None, aliases=[], fixed_in=[], summary='')
    database = detail.get('database_specific')
    raw = database.get('severity') if isinstance(database, dict) else None
    severity = _SEVERITY.get(raw.upper(), 'unknown') if isinstance(raw, str) else 'unknown'
    cvss = next((item['score'] for item in _dicts(detail.get('severity'))
                 if str(item.get('type', '')).startswith('CVSS') and isinstance(item.get('score'), str)), None)
    fixed = set()
    for affected in _dicts(detail.get('affected')):
        package = affected.get('package')
        if not isinstance(package, dict) or package.get('ecosystem') != 'npm' or package.get('name') != name:
            continue
        for rng in _dicts(affected.get('ranges')):
            for event in _dicts(rng.get('events')):
                if isinstance(event.get('fixed'), str):
                    fixed.add(event['fixed'])
    aliases = detail.get('aliases')
    summary = detail.get('summary')
    return dict(severity=severity, cvss=cvss,
                aliases=[a for a in aliases if isinstance(a, str)] if isinstance(aliases, list) else [],
                fixed_in=sorted(fixed),
                summary=summary[:200] if isinstance(summary, str) else '')


def _condition(package, detail, lock_names):
    if not isinstance(detail, dict): return None
    text = ' '.join(detail[key] for key in ('summary', 'details') if isinstance(detail.get(key), str))
    for rule in CONDITIONS:
        if re.search(rule['package'], package) and re.search(rule['text'], text) and not rule['requires'] & lock_names:
            return rule['note']
    return None


def check(root):
    result = dict(status='incomplete', packages=0, vulnerabilities=[], errors=[], warnings=[], skipped_local=0,
                  scope='Versões exatas do package-lock.json raiz (npm lock v2/v3), consultadas no OSV. '
                        'Dependências locais/workspace são ignoradas com aviso; a severidade vem do advisory OSV.')
    path = root / 'package-lock.json'
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 5_000_000:
            raise ValueError('Exige package-lock.json raiz, regular, com até 5 MB.')
        lock = json.loads(path.read_text())
        if lock.get('lockfileVersion') not in (2, 3) or not isinstance(lock.get('packages'), dict):
            raise ValueError('Somente package-lock v2/v3 é suportado nesta versão.')
        reach = {}
        for location, item in lock['packages'].items():
            if not location: continue
            if not isinstance(item, dict) or item.get('link') or 'node_modules/' not in location:
                result['skipped_local'] += 1
                continue
            name = item.get('name') or location.rsplit('node_modules/', 1)[1]
            version = item.get('version', '')
            if not isinstance(name, str) or not isinstance(version, str) or not re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?', version):
                raise ValueError('Dependência sem versão semântica exata; auditoria incompleta.')
            production = not (item.get('dev') is True or item.get('devOptional') is True)
            key = (name, version)
            reach[key] = 'production' if production or reach.get(key) == 'production' else 'dev_only'
        if result['skipped_local']:
            result['warnings'].append(f"{result['skipped_local']} dependência(s) local/workspace ignorada(s); não auditadas no OSV.")
        if not reach:
            # Nothing from the registry: there is nothing to query, so no OSV call is made.
            result['warnings'].append('Nenhuma dependência de registro npm no lock; apenas pacotes locais/workspace.')
            result['status'] = 'passed'
            return result
        if len(reach) > 1000:
            raise ValueError('Auditoria exige no máximo 1000 dependências únicas.')
        lock_names = {location.rsplit('node_modules/', 1)[-1] for location in lock['packages'] if location}
        packages = sorted(reach)
        result['packages'] = len(packages)
        opener = urllib.request.build_opener(NoRedirect())
        for offset in range(0, len(packages), 100):
            batch = packages[offset:offset+100]
            body = json.dumps({'queries': [{'package': {'name': name, 'ecosystem': 'npm'}, 'version': version} for name, version in batch]}).encode()
            request = urllib.request.Request('https://api.osv.dev/v1/querybatch', data=body, headers={'Content-Type': 'application/json'})
            with opener.open(request, timeout=20) as response:
                raw = response.read(2_000_001)
            if len(raw) > 2_000_000: raise ValueError('Resposta OSV excedeu o limite.')
            entries = json.loads(raw).get('results')
            if not isinstance(entries, list) or len(entries) != len(batch):
                raise ValueError('Resposta OSV incompleta.')
            for (name, version), entry in zip(batch, entries):
                if not isinstance(entry, dict) or set(entry) - {'vulns', 'next_page_token'} or not isinstance(entry.get('vulns', []), list):
                    raise ValueError('Resposta OSV inválida.')
                if entry.get('next_page_token'):
                    raise ValueError('Resposta OSV paginada; auditoria incompleta.')
                for vuln in entry.get('vulns', []):
                    if not isinstance(vuln, dict) or not isinstance(vuln.get('id'), str):
                        raise ValueError('Advisory OSV inválido.')
                    result['vulnerabilities'].append(dict(package=name, version=version, advisory=vuln['id'],
                                                          reachability=reach[(name, version)]))
        ids = list(dict.fromkeys(vuln['advisory'] for vuln in result['vulnerabilities']))
        # Only successful details are cached: the API is long-lived and a transient OSV
        # failure must be retried on the next scan.
        details, fetched, pending = {}, 0, 0
        for advisory_id in ids:
            if advisory_id in _DETAILS:
                details[advisory_id] = _DETAILS[advisory_id]
                continue
            if fetched >= _DETAIL_LIMIT:
                pending += 1
                continue
            fetched += 1
            details[advisory_id] = _fetch_detail(opener, advisory_id)
            if details[advisory_id] is not None:
                if len(_DETAILS) >= 5000: _DETAILS.clear()
                _DETAILS[advisory_id] = details[advisory_id]
        if pending:
            result['warnings'].append(f"{pending} advisory(ies) além do limite de {_DETAIL_LIMIT} consultas de detalhe; severidade desconhecida.")
        missing = [i for i in ids if i in details and details[i] is None]
        if missing:
            result['warnings'].append(f"{len(missing)} advisory(ies) sem detalhe OSV disponível; severidade desconhecida.")
        for vuln in result['vulnerabilities']:
            detail = details.get(vuln['advisory'])
            vuln.update(_advisory(detail, vuln['package']))
            # Unlisted workspaces may hold the SSR code, so the condition is not trusted then.
            condition = _condition(vuln['package'], detail, lock_names) if not result['skipped_local'] else None
            if condition:
                # Low/medium are not applicable without SSR; high, critical or unknown stay conditional for review.
                vuln['reachability'] = 'not_applicable' if vuln['severity'] in {'medium', 'low'} else 'conditional'
                vuln['condition'] = condition
        result['status'] = 'failed' if result['vulnerabilities'] else 'passed'
    except (OSError, ValueError, TypeError, AttributeError):
        result['errors'].append('Auditoria OSV incompleta: confira rede e package-lock raiz v2/v3; dependências locais não são suportadas.')
    return result
