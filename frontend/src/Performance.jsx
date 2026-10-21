import React,{useState} from 'react';

const priorities={high:'Alta',medium:'Média',low:'Baixa'};
const statuses={needs_measurement:'Hipótese · medir',plan_observation:'Observação de plano importado'};
export function Performance({report}){
 const [query,setQuery]=useState(''),[priority,setPriority]=useState('all');
 const perf=report.performance;
 if(!perf)return <section className="panel list-panel"><h2>Performance</h2><p>Execute uma nova análise para gerar os achados de performance.</p></section>;
 const findings=perf.findings.filter(f=>(priority==='all'||f.priority===priority)&&`${f.rule} ${f.file} ${f.title}`.toLowerCase().includes(query.toLowerCase()));
 return <section className="panel list-panel"><h2>Performance · queries e acesso a dados</h2><p>{perf.scope}</p><p>Estado: <strong>{perf.status}</strong> · {perf.coverage.files} arquivos · {perf.findings.length} indícios. {perf.coverage.partial?'Cobertura parcial.':''}</p><p>Esta análise tem prioridades próprias e não altera o veredito de segurança. Padrões no código precisam de medição; planos importados representam uma execução fornecida pelo usuário.</p>
 <div className="filters"><input aria-label="Buscar performance" value={query} onChange={e=>setQuery(e.target.value)} placeholder="Buscar regra, arquivo ou indício…"/><select aria-label="Prioridade de performance" value={priority} onChange={e=>setPriority(e.target.value)}><option value="all">Todas as prioridades</option>{Object.entries(priorities).map(([key,label])=><option key={key} value={key}>{label}</option>)}</select></div>
 <div className="control-grid">{findings.map(f=><article className="control" key={f.id}><span className={'severity '+f.priority}>{priorities[f.priority]}</span><h3>{f.rule} · {f.title}</h3><code>{f.file}:{f.line}{f.plan_node?` · nó ${f.plan_node}`:''}</code><small>{statuses[f.status]||f.status} · Confiança: {f.confidence}</small><pre>{f.evidence}</pre><h4>Impacto provável</h4><p>{f.impact}</p><h4>Como investigar e ajustar</h4><p>{f.recommendation}</p><details><summary>Como medir e validar</summary><p>{f.validation}</p></details></article>)}</div>
 {!findings.length&&<div className="empty">{!perf.enabled?'Análise de performance desativada.':'Nenhum indício neste filtro. Isso não comprova boa performance.'}</div>}
 {!!perf.plans?.length&&<><h3>Planos PostgreSQL importados</h3><ul>{perf.plans.map((p,i)=><li key={i}>{p.file}: {p.nodes} nós · {p.actual_metrics?'com métricas de execução':'somente estimativas'}</li>)}</ul></>}
 <h3>Limites</h3><ul>{perf.limitations.map(x=><li key={x}>{x}</li>)}</ul>{perf.errors.map((x,i)=><p className="error-text" key={i}>{x}</p>)}</section>;
}
