import argparse
import json
import os
import secrets
import sys
from pathlib import Path
from .scanner import scan,sarif,markdown
from .assurance import evaluate

def main():
    parser=argparse.ArgumentParser(description='RepoShield • análise local de segurança')
    sub=parser.add_subparsers(dest='command',required=True)
    s=sub.add_parser('scan'); s.add_argument('path',nargs='?',default='.')
    s.add_argument('--provider',choices=['none','claude','codex'],default='none')
    s.add_argument('--consent',action='store_true',help='Autoriza envio dos achados redigidos ao provedor')
    s.add_argument('--format',choices=['json','sarif','markdown'],default='markdown')
    s.add_argument('--output',type=Path,help='Arquivo de saída; padrão: PROJETO/.reposhield/security-review.md')
    s.add_argument('--stdout',action='store_true',help='Imprime o relatório em vez de salvar automaticamente')
    s.add_argument('--runtime',action='store_true',help='Autoriza GETs da matriz runtime local configurada')
    s.add_argument('--dependencies',action='store_true',help='Autoriza envio de nomes/versões do package-lock raiz ao OSV; não instala pacotes')
    s.add_argument('--gate',action='store_true',help='Retorna 1 se reprovado e 3 se inconclusivo; 0 somente para aprovação no escopo')
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
    if args.stdout and args.output: parser.error('Escolha --stdout ou --output.')
    provider_failed=False
    try:
        print('Analisando o projeto…',file=sys.stderr)
        report=scan(args.path,runtime_enabled=args.runtime,dependencies_enabled=args.dependencies)
        if args.provider!='none':
            from .providers import review
            try: report['ai']=review(report,args.provider)
            except ValueError as exc:
                report['errors'].append('Revisão por IA incompleta: '+str(exc))
                provider_failed=True
        report['verdict']=evaluate(report)
        print(report['verdict']['label'],file=sys.stderr)
        result=markdown(report) if args.format=='markdown' else json.dumps(sarif(report) if args.format=='sarif' else report,ensure_ascii=False,indent=2)
        if args.stdout: print(result)
        else:
            suffix={'markdown':'md','json':'json','sarif':'sarif'}[args.format]
            destination=args.output or Path(args.path).expanduser().resolve()/'.reposhield'/('security-review.'+suffix)
            destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_text(result,encoding='utf-8')
            print('Relatório salvo: '+str(destination.resolve()),file=sys.stderr)
        if provider_failed: raise SystemExit(2)
        if args.gate and report['verdict']['status']=='rejected': raise SystemExit(1)
        levels={'low':0,'medium':1,'high':2,'critical':3}
        if args.fail_on and any(levels[f['severity']]>=levels[args.fail_on] for f in report['findings']): raise SystemExit(1)
        if args.gate and report['verdict']['status']!='passed_scoped':
            raise SystemExit(1 if report['verdict']['status']=='rejected' else 3)
        if report['coverage']['partial']: raise SystemExit(3)
    except (ValueError,OSError) as exc: parser.exit(2,f'Erro: {exc}\n')

if __name__=='__main__': main()

