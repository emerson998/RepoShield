import sys
import pytest
from reposhield.cli import main
from reposhield.scanner import scan,markdown

def test_default_command_writes_action_plan_and_does_not_rescan_it(tmp_path,monkeypatch):
    (tmp_path/'app.py').write_text('debug=True')
    monkeypatch.setattr(sys,'argv',['reposhield','scan',str(tmp_path)])
    main()
    report=tmp_path/'.reposhield'/'security-review.md'
    contents=report.read_text()
    assert 'Por que ajustar' in contents
    assert 'Como ajustar' in contents
    assert 'Como validar' in contents
    assert 'RS004' in contents
    assert scan(tmp_path)['coverage']['files']==1

def test_provider_failure_keeps_local_report(tmp_path,monkeypatch):
    (tmp_path/'app.py').write_text('debug=True')
    def fail(*args):raise ValueError('CLI indisponível')
    monkeypatch.setattr('reposhield.providers.review',fail)
    monkeypatch.setattr(sys,'argv',['reposhield','scan',str(tmp_path),'--provider','claude','--consent'])
    with pytest.raises(SystemExit) as e:main()
    assert e.value.code==2
    assert 'Revisão por IA incompleta' in (tmp_path/'.reposhield'/'security-review.md').read_text()

def test_stdout_and_ci_threshold_keep_report(tmp_path,monkeypatch,capsys):
    (tmp_path/'app.py').write_text('debug=True')
    monkeypatch.setattr(sys,'argv',['reposhield','scan',str(tmp_path),'--stdout'])
    main()
    assert 'Plano de ajustes' in capsys.readouterr().out
    assert not (tmp_path/'.reposhield').exists()
    monkeypatch.setattr(sys,'argv',['reposhield','scan',str(tmp_path),'--fail-on','medium'])
    with pytest.raises(SystemExit) as e:main()
    assert e.value.code==1
    assert (tmp_path/'.reposhield'/'security-review.md').exists()

def test_untrusted_evidence_cannot_inject_html(tmp_path):
    (tmp_path/'app.py').write_text('debug=True # <img src="https://evil.invalid">')
    output=markdown(scan(tmp_path))
    assert '<img' not in output
    assert '&lt;img' in output
