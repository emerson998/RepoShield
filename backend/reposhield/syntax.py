"""Small lexical helpers; preserve offsets, never evaluate repository code."""
import re

TOKENS = re.compile(r'@"(?:""|[^"])*"|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`|//[^\n]*|/\*.*?\*/', re.S)


def blank(value):
    return ''.join('\n' if c == '\n' else ' ' for c in value)


def clean(text, strings=False):
    return TOKENS.sub(lambda m: blank(m[0]) if strings or m[0].startswith(('//', '/*')) else m[0], text)


def closing(masked, start, left='(', right=')'):
    depth = 0
    for i in range(start, len(masked)):
        if masked[i] == left: depth += 1
        elif masked[i] == right:
            depth -= 1
            if depth == 0: return i
    return None
