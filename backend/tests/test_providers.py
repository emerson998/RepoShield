from types import SimpleNamespace
import pytest
from reposhield.providers import review

def test_claude_isolated_and_no_shell(monkeypatch):
    monkeypatch.setattr('shutil.which',lambda _: '/bin/claude')
    def run(command,**kwargs):
        assert '--tools' in command and command[command.index('--tools')+1]==''
        assert 'shell' not in kwargs
        assert 'reposhield-review-' in kwargs['cwd']
        assert kwargs['timeout']==180
        return SimpleNamespace(returncode=0,stdout='Revisão de teste')
    monkeypatch.setattr('subprocess.run',run)
    assert review({'project':'test','findings':[],'limitations':[]},'claude')['text']=='Revisão de teste'

def test_missing_provider(monkeypatch):
    monkeypatch.setattr('shutil.which',lambda _:None)
    with pytest.raises(ValueError):review({},'codex')
