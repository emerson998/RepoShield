import json
import sys

import pytest

from reposhield import cli, performance
from reposhield.scanner import scan, markdown, sarif


def rules(code, name='Orders.cs'):
    return {f['rule'] for f in performance.analyze(code, name)}


def test_ef_n_plus_one_sync_in_async_and_unbounded():
    code = '''async Task Load() {
        foreach (var id in ids) {
            var orders = context.Orders.Where(o => o.Id == id).ToList();
        }
    }'''
    assert rules(code) == {'RP001', 'RP003', 'RP004'}


def test_ef_bounded_async_outside_loop():
    assert not rules('async Task Load() { var rows = await db.Orders.Where(x => x.Active).Take(50).ToListAsync(); }')


@pytest.mark.parametrize('materializer', ['ToList()', 'AsEnumerable()', 'ToArray()'])
def test_materialization_before_filter(materializer):
    assert 'RP002' in rules(f'var rows = db.Orders.{materializer}.Where(x => x.Active).ToList();')


def test_multiline_await_materialization_before_filter():
    assert 'RP002' in rules('var rows = (await db.Orders\n.ToListAsync())\n.Where(x => x.Active).ToList();')


def test_does_not_flag_ordinary_collection_or_comments():
    code = '''// db.Orders.ToList();
    var text = "db.Orders.ToList()";
    var rows = values.ToList();
    /* foreach (var id in ids) { db.Orders.ToList(); } */'''
    assert not rules(code)


def test_task_wait_only_recognizes_async_source():
    assert rules('var x = FetchAsync().Result;') == {'RP005'}
    assert not rules('var x = model.Result;')


def test_python_alias_blocking_io_and_nested_sync_function():
    code = '''import requests as http
from time import sleep as pause
async def load():
    http.get("https://example.invalid")
    pause(1)
    def local():
        http.get("https://example.invalid")
'''
    findings = performance.analyze(code, 'app.py')
    assert [f['line'] for f in findings if f['rule'] == 'RP010'] == [4, 5]


def test_python_loops_and_single_iteration_query():
    assert 'RP001' in rules('for id in ids:\n    cursor.execute(sql, (id,))', 'a.py')
    assert 'RP001' not in rules('for row in cursor.fetchall():\n    print(row)', 'a.py')
    assert 'RP011' in rules('async def load():\n    for id in ids:\n        await client.get(id)', 'a.py')


def test_python_async_client_not_flagged_as_blocking():
    assert 'RP010' not in rules('async def load():\n    return await client.get(url)', 'a.py')


def test_js_sequential_io_loop_comments_and_outside():
    assert rules('for (const id of ids) { await db.query(sql, [id]); }', 'a.ts') == {'RP011'}
    assert not rules('// for (const id of ids) { await fetch(url); }', 'a.ts')
    assert not rules('await fetch(url)', 'a.ts')


def test_sql_precision_and_boundaries():
    code = """-- SELECT * FROM comments;
SELECT count(*) FROM orders;
SELECT * FROM users WHERE LOWER(email) = 'x' AND name LIKE '%private' OFFSET 10000;
SELECT id FROM users LIMIT 30 OFFSET 9999;
"""
    found = performance.analyze(code, 'query.sql')
    assert {f['rule'] for f in found} == {'RP006', 'RP007', 'RP008', 'RP009'}
    assert all(f['line'] == 3 for f in found)
    assert 'private' not in json.dumps(found)


@pytest.mark.parametrize('name,code,line', [
    ('a.cs', '// SELECT * FROM x;\nvar sql = @"SELECT * FROM x";', 2),
    ('a.py', '# "SELECT * FROM x"\nsql = """SELECT * FROM x"""', 2),
    ('a.java', 'String sql = "SELECT * FROM x";', 1),
])
def test_sql_literal_locations(name, code, line):
    found = performance.analyze(code, name)
    assert [f['rule'] for f in found] == ['RP006']
    assert found[0]['line'] == line


def plan(tmp_path, node):
    path = tmp_path / 'plan.json'
    path.write_text(json.dumps([{'Plan': node}]))
    return path


def test_plan_records_actual_counters_without_copying_query_data(tmp_path):
    path = plan(tmp_path, {'Node Type': 'Seq Scan', 'Plan Rows': 20000, 'Actual Rows': 10,
                          'Actual Loops': 1500, 'Rows Removed by Filter': 50000,
                          'Filter': "password = 'do-not-export'", 'Relation Name': 'secret_table'})
    found, meta = performance.read_plan(path)
    assert {f['rule'] for f in found} == {'RP101', 'RP102', 'RP104'}
    assert meta == {'file': 'plan.json', 'nodes': 1, 'actual_metrics': True, 'status': 'imported'}
    assert 'do-not-export' not in json.dumps(found)
    assert 'secret_table' not in json.dumps(found)
    assert all(f['status'] == 'plan_observation' for f in found)


def test_seq_scan_without_discarded_rows_is_not_a_problem(tmp_path):
    assert not performance.read_plan(plan(tmp_path, {'Node Type': 'Seq Scan', 'Plan Rows': 100000}))[0]


def test_zero_actual_loops_are_not_cardinality_mismatch(tmp_path):
    assert not performance.read_plan(plan(tmp_path, {'Node Type': 'Index Scan', 'Plan Rows': 20000,
                                                      'Actual Rows': 0, 'Actual Loops': 0}))[0]


def test_plan_walks_children_and_reports_spill(tmp_path):
    found, meta = performance.read_plan(plan(tmp_path, {'Node Type': 'Sort', 'Sort Space Type': 'Disk',
        'Plans': [{'Node Type': 'Hash', 'Temp Written Blocks': 123}]}))
    assert [f['rule'] for f in found] == ['RP103', 'RP103']
    assert [f['plan_node'] for f in found] == [1, 2]
    assert meta['nodes'] == 2


@pytest.mark.parametrize('raw', ['{}', '[]', 'null', 'not json', '[{"Plan":{}}]',
                                  '[{"Plan":{"Node Type":"Sort","Plans":{}}}]',
                                  '[{"Plan":{"Node Type":"Seq Scan","Actual Rows":"invalid"}}]'])
def test_invalid_plans_fail_closed(tmp_path, raw):
    path = tmp_path / 'p.json'
    path.write_text(raw)
    with pytest.raises(ValueError): performance.read_plan(path)


def test_plan_limits_and_symlink(tmp_path, monkeypatch):
    path = plan(tmp_path, {'Node Type': 'Sort', 'Plans': [{'Node Type': 'Seq Scan'}]})
    monkeypatch.setattr(performance, 'MAX_PLAN_NODES', 1)
    with pytest.raises(ValueError, match='nós'): performance.read_plan(path)
    monkeypatch.setattr(performance, 'MAX_PLAN_BYTES', 1)
    with pytest.raises(ValueError, match='5 MB'): performance.read_plan(path)
    link = tmp_path / 'link.json'
    link.symlink_to(path)
    with pytest.raises(ValueError, match='simbólico'): performance.read_plan(link)


def test_scan_security_separation_exports_and_opt_out(tmp_path):
    (tmp_path / 'query.sql').write_text('SELECT * FROM orders;')
    enabled = scan(tmp_path)
    disabled = scan(tmp_path, performance_enabled=False)
    assert enabled['findings'] == disabled['findings']
    assert enabled['verdict'] == disabled['verdict']
    assert enabled['performance']['findings'][0]['rule'] == 'RP006'
    assert disabled['performance']['status'] == 'disabled'
    assert not disabled['performance']['findings']
    assert 'RP006' in markdown(enabled)
    exported = sarif(enabled)['runs'][0]
    assert not exported['results']
    assert exported['properties']['performance']['findings'][0]['rule'] == 'RP006'


def test_scan_respects_excludes_symlinks_and_limits(tmp_path):
    (tmp_path / '.reposhield.json').write_text(json.dumps({'exclude': ['ignored.sql']}))
    (tmp_path / 'ignored.sql').write_text('SELECT * FROM orders;')
    (tmp_path / 'oversize.sql').write_text(' ' * 300001)
    (tmp_path / 'link.sql').symlink_to(tmp_path / 'ignored.sql')
    result = scan(tmp_path)
    assert not result['performance']['findings']
    assert result['performance']['coverage']['partial']


def test_plan_error_is_separate_and_retains_static_report(tmp_path):
    path = tmp_path / 'invalid-plan.json'
    path.write_text('null')
    result = scan(tmp_path, query_plans=[path])
    assert result['performance']['status'] == 'partial'
    assert result['performance']['errors']
    assert result['errors'] == []


def test_performance_diff_filters_only_static_findings(tmp_path, monkeypatch):
    (tmp_path / 'query.sql').write_text('SELECT * FROM a;\nSELECT * FROM b;')
    from reposhield import scanner
    monkeypatch.setattr(scanner.adapter_base, 'git_history_safe', lambda root: True)
    monkeypatch.setattr(scanner.triage, 'changed_lines', lambda *args: {'query.sql': {2}})
    path = plan(tmp_path, {'Node Type': 'Sort', 'Sort Space Type': 'Disk'})
    report = scan(tmp_path, diff_base='main', query_plans=[path])
    found = report['performance']['findings']
    assert {f['rule'] for f in found} == {'RP006', 'RP103'}
    assert [f['line'] for f in found if f['rule'] == 'RP006'] == [2]


def test_cli_performance_gate_is_explicit_and_saves_report(tmp_path, monkeypatch):
    (tmp_path / 'query.sql').write_text('SELECT * FROM orders;')
    output = tmp_path / 'report.json'
    monkeypatch.setattr(sys, 'argv', ['reposhield', 'scan', str(tmp_path), '--format', 'json',
                                    '--output', str(output), '--performance-fail-on', 'low'])
    with pytest.raises(SystemExit) as exc: cli.main()
    assert exc.value.code == 1
    assert json.loads(output.read_text())['performance']['findings']


def test_cli_plan_error_exits_two_after_report(tmp_path, monkeypatch):
    output = tmp_path / 'report.json'
    monkeypatch.setattr(sys, 'argv', ['reposhield', 'scan', str(tmp_path), '--format', 'json',
                                    '--output', str(output), '--query-plan', str(tmp_path / 'missing.json')])
    with pytest.raises(SystemExit) as exc: cli.main()
    assert exc.value.code == 2
    assert json.loads(output.read_text())['performance']['errors']


def test_cli_cannot_disable_requested_performance_gate(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['reposhield', 'scan', str(tmp_path), '--no-performance', '--performance-fail-on', 'high'])
    with pytest.raises(SystemExit) as exc: cli.main()
    assert exc.value.code == 2


def test_huge_sql_offset_does_not_abort_security_scan(tmp_path):
    (tmp_path / 'q.sql').write_text('SELECT id FROM orders OFFSET ' + '9' * 5000)
    result = scan(tmp_path)
    assert [f['rule'] for f in result['performance']['findings']] == ['RP009']
