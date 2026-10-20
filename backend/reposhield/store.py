import json
import os
import sqlite3
from pathlib import Path

def connection():
    path=Path(os.environ.get('REPOSHIELD_DB',str(Path.home()/'.reposhield'/'history.db')))
    path.parent.mkdir(parents=True,exist_ok=True)
    conn=sqlite3.connect(path)
    conn.execute('CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
    return conn

def save(identifier, report):
    with connection() as conn:
        conn.execute('INSERT OR REPLACE INTO scans VALUES (?,?)',(identifier,json.dumps(report)))

def get(identifier):
    with connection() as conn:
        row=conn.execute('SELECT body FROM scans WHERE id=?',(identifier,)).fetchone()
    return json.loads(row[0]) if row else None

def history():
    with connection() as conn:
        rows=conn.execute('SELECT id, body FROM scans ORDER BY rowid DESC LIMIT 50').fetchall()
    return [dict(id=k,project=(r:=json.loads(v))['project'],created_at=r['created_at'],count=len(r['findings'])) for k,v in rows]
