import argparse
import json
import os
import secrets
from pathlib import Path
from .scanner import scan,sarif,markdown

def main():
    parser=argparse.ArgumentParser(description='RepoShield • análise local de segurança')
    sub=parser.add_subparsers(dest='command',required=True)
    s=sub.add_parser('scan'); s.add_argument('path',nargs='?',default='.')
    s.add_argument('--provider',choices=['none','claude','codex'],default='none')
    s.add_argument('--consent',action='store_true',help='Autoriza envio dos achados redigidos ao provedor')
    s.add_argument('--format',choices=['json','sarif','markdown'],default='markdown')
    s.add_argument('--output',type=Path)
    s.add_argument('--fail-on',choices=['low','medium','high','critical'])
    serve=sub.add_parser('serve'); serve.add_argument('--root',default='.')
    args=parser.parse_args()
    if args.command=='serve':
        import uvicorn
        os.environ['REPOSHIELD_ROOT']=str(Path(args.root).resolve())
        os.environ.setdefault('REPOSHIELD_TOKEN',secrets.token_urlsafe(32))
        print('RepoShield: http://127.0.0.1:8765\nToken local: '+os.environ['REPOSHIELD_TOKEN'],flush=True)
        uvicorn.run('reposhield.api:app',host='127.0.0.1',port=8765)
        return
    if args.provider!='none' and not args.consent: parser.error('Use --consent para enviar os achados ao provedor.')
    try:
        report=scan(args.path)
        if args.provider!='none':
            from .providers import review
            report['ai']=review(report,args.provider)
        result=markdown(report) if args.format=='markdown' else json.dumps(sarif(report) if args.format=='sarif' else report,ensure_ascii=False,indent=2)
        if args.output: args.output.write_text(result,encoding='utf-8')
        else: print(result)
        levels={'low':0,'medium':1,'high':2,'critical':3}
        if args.fail_on and any(levels[f['severity']]>=levels[args.fail_on] for f in report['findings']): raise SystemExit(1)
        if report['coverage']['partial']: raise SystemExit(3)
    except (ValueError,OSError) as exc: parser.exit(2,f'Erro: {exc}\n')

if __name__=='__main__': main()
