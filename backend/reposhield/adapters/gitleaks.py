"""Adaptador Gitleaks: segredos nos arquivos atuais e, se a config git for segura, no histórico. Somente leitura."""
import hashlib
import re

from .base import Adapter, ToolError, execute, git_history_safe, read_bounded
from .sarif import import_sarif

CWE = 'CWE-798'
# Regras padrão sempre; a config do próprio projeto (.gitleaks.toml) poderia desligar detecções.
DEFAULT_CONFIG = '[extend]\nuseDefault = true\n'
COMMIT = re.compile(r'[0-9a-fA-F]{7,64}')


def _commit(result):
    fingerprints = result.get('partialFingerprints')
    sha = fingerprints.get('commitSha') if isinstance(fingerprints, dict) else None
    return f'commit {sha[:12]}' if isinstance(sha, str) and COMMIT.fullmatch(sha) else ''


def _summary(stderr):
    from ..scanner import redact
    lines = [line.strip() for line in str(stderr or '').splitlines() if line.strip()]
    return redact(lines[-1] if lines else 'sem detalhe')[:300]


class Gitleaks(Adapter):
    name = 'gitleaks'
    binary = 'gitleaks'
    network = 'none'
    axis = 'secrets'
    version_args = ('version',)

    def run(self, root, workdir, tool, options):
        report = workdir / 'gitleaks.sarif'
        config = workdir / 'gitleaks.toml'
        config.write_text(DEFAULT_CONFIG, encoding='utf-8')
        # Arquivo vazio: o .gitleaksignore do projeto não pode esconder achados.
        empty_ignore = workdir / 'empty.gitleaksignore'
        empty_ignore.write_text('', encoding='utf-8')
        args = [tool['path'], 'detect', '--source', str(root), '--config', str(config),
                '--gitleaks-ignore-path', str(empty_ignore),
                '--report-format', 'sarif', '--report-path', str(report), '--redact', '--no-banner',
                '--exit-code', '0', '--log-level', 'error']
        if git_history_safe(root):
            detail = 'Arquivos e histórico git varridos.'
        else:
            args.append('--no-git')
            detail = 'Histórico git não varrido (sem .git ou config git com comandos); só arquivos atuais.'
        result = execute(args, timeout=600)
        if result.returncode != 0:
            raise ToolError('gitleaks terminou com erro: ' + _summary(result.stderr))
        return dict(sarif=read_bounded(report), detail=detail)

    def normalize(self, raw, root, tool):
        findings = import_sarif(raw['sarif'], default_tool='gitleaks', root=root, extra=_commit)
        for item in findings:
            item['category'] = 'secrets'
            item['cwe'] = CWE
            # Mesma fórmula de external_finding/scanner.finding: deduplica com RS001/RS403 na mesma linha.
            item['fingerprint'] = hashlib.sha256(f"{item['file']}:{item['line']}:{CWE}".encode()).hexdigest()[:16]
        return dict(findings=findings, detail=raw['detail'])
