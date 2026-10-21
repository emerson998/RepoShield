"""Bounded OSV lookup of exact npm lock versions. Never installs or runs project code."""
import json
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check(root):
    result = dict(status='incomplete', packages=0, vulnerabilities=[], errors=[],
                  scope='Versões exatas do package-lock.json raiz (npm lock v2/v3), consultadas no OSV.')
    path = root / 'package-lock.json'
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 5_000_000:
            raise ValueError('Exige package-lock.json raiz, regular, com até 5 MB.')
        lock = json.loads(path.read_text())
        if lock.get('lockfileVersion') not in (2, 3) or not isinstance(lock.get('packages'), dict):
            raise ValueError('Somente package-lock v2/v3 é suportado nesta versão.')
        packages = set()
        for location, item in lock['packages'].items():
            if not location: continue
            if not isinstance(item, dict) or item.get('link') or 'node_modules/' not in location:
                raise ValueError('Dependência local/workspace não resolvida; auditoria incompleta.')
            name = item.get('name') or location.rsplit('node_modules/', 1)[1]
            version = item.get('version', '')
            import re
            if not isinstance(name, str) or not isinstance(version, str) or not re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?', version):
                raise ValueError('Dependência sem versão semântica exata; auditoria incompleta.')
            packages.add((name, version))
        if not packages or len(packages) > 1000:
            raise ValueError('Auditoria exige entre 1 e 1000 dependências únicas.')
        packages = sorted(packages)
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
                    result['vulnerabilities'].append(dict(package=name, version=version, advisory=vuln['id']))
        result['status'] = 'failed' if result['vulnerabilities'] else 'passed'
    except (OSError, ValueError, TypeError, AttributeError):
        result['errors'].append('Auditoria OSV incompleta: confira rede e package-lock raiz v2/v3; dependências locais não são suportadas.')
    return result
