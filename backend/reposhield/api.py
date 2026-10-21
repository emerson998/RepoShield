import os
import secrets
import threading
import uuid
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from .scanner import scan, sarif, markdown
from .providers import available, review
from . import store
from .assurance import evaluate

app=FastAPI(title='RepoShield',version='0.3.0',docs_url=None,redoc_url=None,openapi_url=None)
TOKEN=os.environ.get('REPOSHIELD_TOKEN') or secrets.token_urlsafe(32)
ROOT=Path(os.environ.get('REPOSHIELD_ROOT',os.getcwd())).expanduser().resolve()
lock=threading.Lock()
jobs={}
pool=ThreadPoolExecutor(max_workers=1)

def auth(request: Request, x_reposhield_token: str=Header(default='')):
    if request.headers.get('host','').split(':')[0] not in {'localhost','127.0.0.1','testserver'}:
        raise HTTPException(403,'Host inválido')
    origin=request.headers.get('origin')
    if origin and origin not in {'http://localhost:8765','http://127.0.0.1:8765','http://localhost:5173','http://127.0.0.1:5173'}:
        raise HTTPException(403,'Origem inválida')
    if not secrets.compare_digest(x_reposhield_token,TOKEN): raise HTTPException(401,'Token local inválido')

class ScanRequest(BaseModel):
    path: str=Field(min_length=1,max_length=2048)
    provider: str='none'
    consent: bool=False
    runtime: bool=False
    dependencies: bool=False

@app.get('/api/health')
def health(): return {'status':'ok'}

@app.get('/api/settings',dependencies=[Depends(auth)])
def settings(): return {'root':str(ROOT),'providers':available()}

@app.get('/api/scans',dependencies=[Depends(auth)])
def history(): return store.history()

def work(identifier,path,provider,runtime_enabled,dependencies_enabled=False):
    try:
        report=scan(path,runtime_enabled=runtime_enabled,dependencies_enabled=dependencies_enabled)
        if provider!='none':
            try: report['ai']=review(report,provider)
            except ValueError as exc: report['errors'].append(str(exc))
        report['verdict']=evaluate(report)
        store.save(identifier,report)
        with lock: jobs[identifier]={'status':'completed','report':report}
    except Exception as exc:
        with lock: jobs[identifier]={'status':'failed','error':str(exc)[:300]}

@app.post('/api/scans',dependencies=[Depends(auth)],status_code=202)
def create(req: ScanRequest):
    if req.provider not in {'none','claude','codex'}: raise HTTPException(422,'Provedor inválido')
    if req.provider!='none' and not req.consent: raise HTTPException(422,'Confirme o envio de achados ao provedor.')
    path=Path(req.path).expanduser()
    if not path.is_absolute(): path=ROOT/path
    path=path.resolve()
    if not path.is_relative_to(ROOT) or not path.is_dir(): raise HTTPException(400,'Use um diretório dentro da raiz permitida.')
    with lock:
        if any(j['status']=='running' for j in jobs.values()): raise HTTPException(409,'Já existe uma análise em execução.')
        identifier=uuid.uuid4().hex
        jobs.clear()
        jobs[identifier]={'status':'running'}
    pool.submit(work,identifier,path,req.provider,req.runtime,req.dependencies)
    return {'id':identifier,'status':'running'}

@app.get('/api/scans/{identifier}',dependencies=[Depends(auth)])
def result(identifier: str):
    with lock: job=jobs.get(identifier)
    if job: return job
    report=store.get(identifier)
    if report: return {'status':'completed','report':report}
    raise HTTPException(404,'Análise não encontrada')

@app.get('/api/scans/{identifier}/export',dependencies=[Depends(auth)])
def export(identifier: str,format: str='json'):
    import json
    report=store.get(identifier)
    if not report: raise HTTPException(404,'Análise não encontrada')
    if format not in {'json','sarif','markdown'}: raise HTTPException(422,'Formato inválido')
    body=markdown(report) if format=='markdown' else json.dumps(sarif(report) if format=='sarif' else report,ensure_ascii=False,indent=2)
    return Response(body,media_type='text/markdown' if format=='markdown' else 'application/json')

frontend=Path(__file__).resolve().parents[2]/'frontend'/'dist'
if frontend.is_dir(): app.mount('/',StaticFiles(directory=frontend,html=True),name='frontend')

