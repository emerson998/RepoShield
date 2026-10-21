"""Web Storage sinks with local constant and token-expression hints."""
import re
from .syntax import clean, closing

SENSITIVE = re.compile(r'token|jwt|session', re.I)


def analyze(text, rel, make):
    source, mask = clean(text), clean(text, strings=True)
    constants = {}
    declaration = r'\b(?:const|let|var|readonly)\s+(\w+)\s*(?::\s*string)?\s*=\s*([\'"`])([^\n]*?)\2'
    for match in re.finditer(declaration, source):
        if mask[match.start():match.start()+5].strip():
            constants.setdefault(match[1], set()).add(match[3])
    findings = []
    for call in re.finditer(r'\b(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(', mask):
        end = closing(mask, call.end()-1)
        if end is None: continue
        start = call.end()
        # Find the first argument separator outside nested expressions.
        depth = 0
        comma = None
        for i in range(start, end):
            if mask[i] in '([{': depth += 1
            elif mask[i] in ')]}': depth -= 1
            elif mask[i] == ',' and depth == 0:
                comma = i; break
        if comma is None: continue
        key, value = source[start:comma].strip(), source[comma+1:end].strip()
        resolved = constants.get(key, set())
        literal = len(key) >= 2 and key[0] in "\"'`" and key[-1] == key[0]
        key_hint = SENSITIVE.search(key)
        value_hint = SENSITIVE.search(clean(value, strings=True))
        constant_hint = any(SENSITIVE.search(v) for v in resolved)
        if not (key_hint or value_hint or constant_hint): continue
        item = make('RS209', rel, text[:call.start()].count('\n')+1,
                    source[call.start():end+1].strip())
        item['storage_detection'] = 'literal_key' if literal and key_hint else 'local_constant' if constant_hint else 'identifier_or_value_hint'
        findings.append(item)
    return findings
