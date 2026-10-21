import json
from datetime import date, timedelta

import pytest

from reposhield.triage import (
    apply_baseline, apply_diff, apply_suppressions, assign_keys, changed_lines,
    diff_scope_note, load_baseline, load_suppressions, stable_key,
)

TODAY = date(2026, 10, 21)
FUTURE = (TODAY + timedelta(days=30)).isoformat()
JUST = 'Revisado com o time de segurança.'


def finding(**kw):
    base = dict(id='id1', fingerprint='fp1', rule='RS100', severity='high', title='t', file='src/a.py', line=10,
                evidence='token = "abc123"', category='secret', cwe='CWE-798', disposition=None)
    base.update(kw)
    return base


def supp(**kw):
    base = dict(justification=JUST, author='Emerson', expires=FUTURE)
    base.update(kw)
    return base


# stable_key / assign_keys

def test_stable_key_ignores_line_change():
    a = finding(line=10)
    b = finding(line=99)
    assert stable_key(a, 0) == stable_key(b, 0)


def test_stable_key_changes_when_text_changes():
    assert stable_key(finding(), 0) != stable_key(finding(evidence='outra coisa'), 0)


def test_occurrence_distinguishes_duplicates():
    items = [finding(line=10), finding(line=20), finding(line=30)]
    assign_keys(items)
    keys = [f['stable_key'] for f in items]
    assert len(set(keys)) == 3
    assert keys[0] == stable_key(finding(), 0)
    assert keys[1] == stable_key(finding(), 1)


def test_assign_keys_orders_by_file_and_line():
    items = [finding(line=20), finding(line=10)]
    assign_keys(items)
    assert items[1]['stable_key'] == stable_key(finding(), 0)
    assert items[0]['stable_key'] == stable_key(finding(), 1)


# supressões

def test_suppression_by_fingerprint():
    findings = [finding()]
    rules, errors = load_suppressions({'suppressions': [supp(fingerprint='fp1')]}, TODAY)
    assert errors == []
    warnings = apply_suppressions(findings, rules, TODAY)
    assert warnings == []
    assert findings[0]['disposition'] == 'suppressed'
    assert findings[0]['suppressed_by'] == dict(justification=JUST, author='Emerson', expires=FUTURE, match='fingerprint')


def test_suppression_by_rule_and_file():
    findings = [finding(), finding(file='src/b.py')]
    rules, errors = load_suppressions({'suppressions': [supp(rule='RS100', file='src/a.py')]}, TODAY)
    assert errors == []
    apply_suppressions(findings, rules, TODAY)
    assert findings[0]['disposition'] == 'suppressed'
    assert findings[1]['disposition'] is None


def test_suppression_without_suppressions_key():
    assert load_suppressions({}, TODAY) == ([], [])


def test_suppressions_wrong_type():
    rules, errors = load_suppressions({'suppressions': 'x'}, TODAY)
    assert rules == [] and len(errors) == 1


@pytest.mark.parametrize('item, texto', [
    (supp(fingerprint='fp1', justification='curta'), 'justification'),
    (supp(fingerprint='fp1', expires=(TODAY + timedelta(days=366)).isoformat()), '365 dias'),
    (supp(fingerprint='fp1', expires='21/10/2026'), 'AAAA-MM-DD'),
    (supp(fingerprint='fp1', expires='2026-13-40'), 'inválida'),
    (supp(fingerprint='fp1', author='  '), 'author'),
])
def test_invalid_suppressions_generate_errors(item, texto):
    rules, errors = load_suppressions({'suppressions': [item]}, TODAY)
    assert rules == []
    assert len(errors) == 1
    assert 'Supressão #1' in errors[0] and texto in errors[0]


def test_expired_suppression_does_not_suppress_and_warns():
    findings = [finding()]
    rules, _ = load_suppressions({'suppressions': [supp(fingerprint='fp1', expires='2026-10-01')]}, TODAY)
    warnings = apply_suppressions(findings, rules, TODAY)
    assert findings[0]['disposition'] is None
    assert warnings == ['Supressão #1 expirou em 2026-10-01; achado voltou a contar.']


def test_expired_suppression_without_match_warns_remove():
    rules, _ = load_suppressions({'suppressions': [supp(fingerprint='zzz', expires='2026-10-01')]}, TODAY)
    warnings = apply_suppressions([finding()], rules, TODAY)
    assert warnings == ['Supressão #1 expirada e sem achado correspondente; remova-a.']


def test_unmatched_suppression_warns():
    rules, _ = load_suppressions({'suppressions': [supp(fingerprint='zzz')]}, TODAY)
    warnings = apply_suppressions([finding()], rules, TODAY)
    assert warnings == ['Supressão #1 não corresponde a nenhum achado; remova-a.']


def test_critical_by_rule_and_file_without_line_is_not_suppressed():
    findings = [finding(severity='critical')]
    rules, _ = load_suppressions({'suppressions': [supp(rule='RS100', file='src/a.py')]}, TODAY)
    warnings = apply_suppressions(findings, rules, TODAY)
    assert findings[0]['disposition'] is None
    assert len(warnings) == 1 and 'critical' in warnings[0]


def test_critical_by_rule_file_and_line_is_suppressed():
    findings = [finding(severity='critical')]
    rules, _ = load_suppressions({'suppressions': [supp(rule='RS100', file='src/a.py', line=10)]}, TODAY)
    assert apply_suppressions(findings, rules, TODAY) == []
    assert findings[0]['disposition'] == 'suppressed'


# baseline

def report(*findings):
    return json.dumps({'findings': list(findings)})


def test_baseline_marks_existing_and_new():
    old = [finding(line=10)]
    keys = load_baseline(report(*old))
    current = [finding(line=12), finding(evidence='outro segredo', cwe='CWE-321')]
    assign_keys(current)
    counts = apply_baseline(current, keys)
    assert counts == dict(new=1, existing=1)
    assert current[0]['baseline'] == 'existing'
    assert current[0]['disposition'] == 'baseline'
    assert current[1]['baseline'] == 'new'


def test_baseline_keeps_suppressed_disposition():
    keys = {stable_key(finding(), 0)}
    current = [finding(disposition='suppressed')]
    assign_keys(current)
    apply_baseline(current, keys)
    assert current[0]['disposition'] == 'suppressed'


@pytest.mark.parametrize('texto', ['não é json', '[]', '{"x": 1}', '{"findings": "x"}'])
def test_invalid_baseline_raises(texto):
    with pytest.raises(ValueError, match='Linha de base inválida'):
        load_baseline(texto)


def test_baseline_size_limit():
    with pytest.raises(ValueError, match='20 MB'):
        load_baseline(' ' * (20 * 1024 * 1024 + 1))


# diff

DIFF = """diff --git a/src/a.py b/src/a.py
index 1..2 100644
--- a/src/a.py
+++ b/src/a.py
@@ -3,0 +4,2 @@ def f():
+x = 1
+y = 2
@@ -10 +12 @@
-old
+new
@@ -20,2 +22 @@
-a
-b
+c
@@ -30,3 +30,0 @@
-d
-e
-f
diff --git a/novo.py b/novo.py
new file mode 100644
--- /dev/null
+++ b/novo.py
@@ -0,0 +1,3 @@
+a
+b
+c
diff --git a/src/c.py b/src/c.py
--- a/src/c.py
+++ b/src/c.py
@@ -1,0 +2 @@
++ linha que começa com mais
"""


def fake_runner(returncode=0, stdout=DIFF):
    calls = []

    def runner(args):
        calls.append(args)
        if 'merge-base' in args:
            return returncode, 'a' * 40 + '\n'
        if 'ls-files' in args:
            return returncode, ''
        return returncode, stdout

    runner.calls = calls
    return runner


def test_changed_lines_parses_hunks_new_file_and_edge_counts():
    runner = fake_runner()
    result = changed_lines('/repo', 'main', runner)
    assert result['src/a.py'] == {4, 5, 12, 22}
    assert result['novo.py'] == {1, 2, 3}
    assert result['src/c.py'] == {2}
    assert 'src/a.py' in result


def test_changed_lines_uses_exact_args():
    runner = fake_runner(stdout='')
    changed_lines('/repo', 'main', runner)
    assert runner.calls[0] == ['git', '-c', 'core.fsmonitor=false', 'merge-base', 'main', 'HEAD']
    assert runner.calls[1] == ['git', '-c', 'core.fsmonitor=false', '-c', 'core.quotepath=false', '-c', 'diff.external=',
                               'diff', '--no-ext-diff', '--no-textconv', '--no-color', '--src-prefix=a/', '--dst-prefix=b/',
                               '--unified=0', '--diff-filter=ACMR', '--no-renames', 'a' * 40, '--']


def test_changed_lines_zero_count_gives_no_lines():
    result = changed_lines('/repo', 'main', fake_runner(stdout='+++ b/x.py\n@@ -5,2 +7,0 @@\n-a\n-b\n'))
    assert result == {'x.py': set()}


def test_changed_lines_git_failure_returns_none():
    assert changed_lines('/repo', 'main', fake_runner(returncode=128)) is None


@pytest.mark.parametrize('ref', ['--output=x', 'a;b', '-x', '', 'a b', 'x' * 201])
def test_invalid_base_ref_raises(ref):
    with pytest.raises(ValueError):
        changed_lines('/repo', ref, fake_runner())


def test_apply_diff_filters_by_file_and_line():
    changed = {'src/a.py': {4, 12}}
    findings = [
        finding(file='src/a.py', line=4),
        finding(file='src/a.py', line=5),
        finding(file='src/z.py', line=4),
        finding(file='runtime:/api', line=4),
        finding(file='(desconhecido)', line=4),
    ]
    kept = apply_diff(findings, changed)
    assert kept == [findings[0]]


def test_apply_diff_without_diff_raises():
    with pytest.raises(ValueError):
        apply_diff([finding()], None)


def test_diff_scope_note():
    assert diff_scope_note('main') == 'Somente linhas alteradas em relação a main.'


@pytest.mark.parametrize('changes', [
    {'evidence': 'token = "abc456"'},
    {'evidence': 'token = "ABC123"'},
    {'evidence': 'x' * 200 + 'different'},
    {'rule': 'RS999'},
    {'severity': 'critical'},
    {'reachability': 'production'},
])
def test_stable_key_preserves_security_relevant_changes(changes):
    original = finding(evidence='x' * 200) if changes.get('evidence', '').startswith('x') else finding()
    modified = dict(original, **changes)
    assert stable_key(original, 0) != stable_key(modified, 0)


def test_baseline_recalculates_legacy_keys():
    old = finding(stable_key='old-colliding-key')
    keys = load_baseline(report(old))
    assert keys == {stable_key(old, 0)}
    current = [finding(line=99), finding(evidence='token = "abc456"')]
    assign_keys(current)
    assert apply_baseline(current, keys) == {'existing': 1, 'new': 1}
