"""Correções de segurança: binário plantado, config git perigosa, diff com arquivos não rastreados e linha de base."""
import os
import shutil
import sys

import pytest

from reposhield.adapters import base
from reposhield.adapters.base import ToolError, execute, git_history_safe, resolve_binary
from reposhield.triage import ALL_LINES, apply_baseline, apply_diff, changed_lines


def make_exe(directory, name):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (name + '.exe' if os.name == 'nt' else name)
    path.write_text('x', encoding='utf-8')
    path.chmod(0o755)
    return path


def set_path(monkeypatch, *entries):
    monkeypatch.setenv('PATH', os.pathsep.join(str(e) for e in entries))


# ---------- resolve_binary ----------

def test_resolve_binary_finds_tool_outside_project(monkeypatch, tmp_path):
    tool = make_exe(tmp_path / 'system', 'rs_probe_ok')
    root = tmp_path / 'proj'
    root.mkdir()
    set_path(monkeypatch, tmp_path / 'system')
    found = resolve_binary('rs_probe_ok', root)
    assert found is not None and os.path.isabs(found)
    assert os.path.samefile(found, tool)


def test_resolve_binary_ignores_directory_inside_root(monkeypatch, tmp_path):
    root = tmp_path / 'proj'
    make_exe(root / 'bin', 'rs_planted')
    set_path(monkeypatch, root / 'bin')
    assert resolve_binary('rs_planted', root) is None
    # Sem root, o critério é só "absoluto e existente": o diretório passa.
    assert resolve_binary('rs_planted') is not None


def test_resolve_binary_ignores_directory_inside_cwd(monkeypatch, tmp_path):
    cwd = tmp_path / 'work'
    make_exe(cwd / 'bin', 'rs_cwd_planted')
    monkeypatch.chdir(cwd)
    set_path(monkeypatch, cwd / 'bin')
    assert resolve_binary('rs_cwd_planted', tmp_path / 'other') is None


def test_resolve_binary_ignores_relative_entries_and_dot(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    make_exe(tmp_path / 'relbin', 'rs_rel')
    make_exe(tmp_path, 'rs_dot')
    set_path(monkeypatch, 'relbin', '.')
    assert resolve_binary('rs_rel') is None
    assert resolve_binary('rs_dot') is None


def test_execute_missing_relative_binary_raises(tmp_path):
    with pytest.raises(ToolError, match='não encontrado em PATH seguro'):
        execute(['rs_definitely_missing_xyz'], cwd=tmp_path)


def test_execute_sets_no_default_current_directory(tmp_path):
    code = 'import os; print(os.environ.get("NoDefaultCurrentDirectoryInExePath"))'
    result = execute([sys.executable, '-c', code], cwd=tmp_path)
    assert result.stdout.strip() == '1'


# ---------- git_history_safe ----------

def _repo(tmp_path, config):
    root = tmp_path / 'proj'
    (root / '.git').mkdir(parents=True)
    (root / '.git' / 'config').write_text(config, encoding='utf-8')
    return root


def test_git_history_safe_same_line_textconv_is_unsafe(tmp_path):
    if shutil.which('git') is None:
        pytest.skip('git não instalado')
    root = _repo(tmp_path, '[diff "x"] textconv = ./evil\n')
    assert git_history_safe(root) is False


def test_git_history_safe_plain_config_is_safe_with_real_git(tmp_path):
    if shutil.which('git') is None:
        pytest.skip('git não instalado')
    root = _repo(tmp_path, '[core]\n\trepositoryformatversion = 0\n\tbare = false\n')
    assert git_history_safe(root) is True


def test_git_history_safe_config_worktree_is_unsafe(tmp_path):
    root = _repo(tmp_path, '[core]\n\tbare = false\n')
    (root / '.git' / 'config.worktree').write_text('[core]\n\tbare = false\n', encoding='utf-8')
    assert git_history_safe(root) is False


def test_git_history_safe_missing_git_binary_is_unsafe(monkeypatch, tmp_path):
    root = _repo(tmp_path, '[core]\n\tbare = false\n')
    monkeypatch.setattr(base, 'resolve_binary', lambda name, root=None: None)
    assert git_history_safe(root) is False


def test_git_history_safe_unsafe_keys_from_git_list(monkeypatch, tmp_path):
    root = _repo(tmp_path, '[core]\n\tbare = false\n')
    monkeypatch.setattr(base, 'resolve_binary', lambda name, root=None: '/fake/git')
    for key in ('diff.x.textconv', 'filter.lfs.clean', 'core.hookspath', 'includeif.gitdir:/a/.path',
                'alias.x.command', 'extensions.worktreeconfig'):
        monkeypatch.setattr(base, 'execute', lambda args, **kw: base.Result(0, f'{key}\nval\0', ''))
        assert git_history_safe(root) is False, key


def test_git_history_safe_git_error_is_unsafe(monkeypatch, tmp_path):
    root = _repo(tmp_path, '[core]\n\tbare = false\n')
    monkeypatch.setattr(base, 'resolve_binary', lambda name, root=None: '/fake/git')
    monkeypatch.setattr(base, 'execute', lambda args, **kw: base.Result(128, '', 'fatal'))
    assert git_history_safe(root) is False


# ---------- changed_lines ----------

SHA = 'b' * 40
TRACKED = ('diff --git a/src/a.py b/src/a.py\n--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +3 @@\n-x\n+y\n')


def _runner(diff=TRACKED, others='', mb_code=0, ls_code=0):
    def runner(args):
        if 'merge-base' in args:
            return mb_code, SHA + '\n'
        if 'ls-files' in args:
            return ls_code, others
        return 0, diff
    return runner


def test_changed_lines_untracked_file_covers_every_line():
    result = changed_lines('/repo', 'main', _runner(others='novo.py\0'))
    assert result['novo.py'] is ALL_LINES
    assert 999 in result['novo.py']
    assert result['src/a.py'] == {3}
    kept = apply_diff([dict(file='novo.py', line=500), dict(file='src/a.py', line=500)], result)
    assert [f['file'] for f in kept] == ['novo.py']


def test_changed_lines_merge_base_failure_is_none():
    assert changed_lines('/repo', 'main', _runner(mb_code=128)) is None


def test_changed_lines_invalid_merge_base_is_none():
    def runner(args):
        return 0, '--evil\n' if 'merge-base' in args else ''
    assert changed_lines('/repo', 'main', runner) is None


def test_changed_lines_ls_files_failure_is_none():
    assert changed_lines('/repo', 'main', _runner(ls_code=1)) is None


def test_changed_lines_quoted_octal_path_is_decoded():
    diff = '+++ "b/caf\\303\\251.py"\n@@ -0,0 +1 @@\n+x\n'
    assert changed_lines('/repo', 'main', _runner(diff=diff)) == {'café.py': {1}}


def test_changed_lines_quoted_escaped_quote_and_tab_path():
    diff = '+++ "b/a\\"x\\ty.py"\n@@ -0,0 +2 @@\n+x\n'
    assert changed_lines('/repo', 'main', _runner(diff=diff)) == {'a"x\ty.py': {2}}


# ---------- apply_baseline ----------

def test_baseline_does_not_downgrade_secret_disposition():
    findings = [
        dict(stable_key='k1', category='secrets', disposition='review_required', file='a', line=1),
        dict(stable_key='k2', category='secrets', disposition='suppressed', file='a', line=2),
        dict(stable_key='k3', category='sast', disposition='review_required', file='a', line=3),
    ]
    counts = apply_baseline(findings, {'k1', 'k2', 'k3'})
    assert findings[0]['baseline'] == 'existing'
    assert findings[0]['disposition'] == 'review_required'
    assert findings[1]['disposition'] == 'suppressed'
    assert findings[2]['disposition'] == 'baseline'
    assert counts == dict(new=0, existing=3)
