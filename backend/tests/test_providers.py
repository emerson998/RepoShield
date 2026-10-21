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


def test_provider_includes_performance_with_shared_finding_budget(monkeypatch):
    import json
    monkeypatch.setattr('shutil.which', lambda _: '/bin/claude')
    perf = {'rule': 'RP001', 'evidence': 'synthetic query'}
    def run(command, **kwargs):
        payload = json.loads(kwargs['input'].split('\n', 1)[1])
        assert len(payload['findings']) + len(payload['performance_findings']) <= 80
        assert payload['performance_findings'] == [perf]
        assert 'não confirme lentidão sem medição' in kwargs['input']
        return SimpleNamespace(returncode=0, stdout='Revisão de teste')
    monkeypatch.setattr('subprocess.run', run)
    review({'project': 'test', 'findings': [], 'limitations': [], 'performance': {'findings': [perf]}}, 'claude')
