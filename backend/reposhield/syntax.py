"""Small lexical helpers; preserve offsets, never evaluate repository code."""
import re

TOKENS = re.compile(r'@"(?:""|[^"])*"|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`|//[^\n]*|/\*.*?\*/', re.S)


def blank(value):
    return ''.join('\n' if c == '\n' else ' ' for c in value)


def clean(text, strings=False):
    return TOKENS.sub(lambda m: blank(m[0]) if strings or m[0].startswith(('//', '/*')) else m[0], text)


# The whole value must match: a prefix like "changeme-Pr0dSecret!9" is a real-looking secret.
PLACEHOLDER = re.compile(r'|'.join([
    r'<[^>]*>', r'\$\{[^}]*\}', r'\{\{[^}]*\}\}', r'%[A-Za-z_]+%', r'__\w+__', r'\*+', r'x{3,}', r'\.{3,}',
    r'(?:change[_-]?me|example|sample|placeholder|todo|dummy|redacted|\[redacted\]|secret|password|senha|test|none|null)[_-]?\d{0,4}',
    r'your[_-][a-z]+(?:[_-][a-z]+)*',
    r'(?:minha|sua)[_-]?senha',
]), re.I)


def placeholder(value):
    # Documentation values such as <senha>, ${VAR} or changeme are not secrets.
    value = (value or '').strip().strip('\'"').strip()
    return not value or PLACEHOLDER.fullmatch(value) is not None


def closing(masked, start, left='(', right=')'):
    depth = 0
    for i in range(start, len(masked)):
        if masked[i] == left: depth += 1
        elif masked[i] == right:
            depth -= 1
            if depth == 0: return i
    return None
