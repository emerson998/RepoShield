import React,{useState} from 'react';
const labels={findings:'Achados para investigar',indicator_only:'Indício encontrado · validar',manual_required:'Validação manual necessária'};
export function Checklist({report}){
 const [filter,setFilter]=useState('all');
 const controls=report.controls||[];
 return <section className="panel list-panel audit-panel"><h2>Checklist de segurança <span className="tag">{controls.length} CONTROLES</span></h2><p>Este checklist organiza a revisão. Nenhum estado significa que o controle foi aprovado.</p><label className="check-filter">Mostrar<select value={filter} onChange={e=>setFilter(e.target.value)}><option value="all">Todos os controles</option>{Object.entries(labels).map(([k,v])=><option key={k} value={k}>{v}</option>)}</select></label><div className="control-grid">{controls.filter(c=>filter==='all'||c.status===filter).map(c=><article className={'control '+c.status} key={c.id}><div className="control-top"><h3>{c.title}</h3><span>{c.findings?c.findings+' achados':labels[c.status]}</span></div><p>{c.validation}</p>{!!c.evidence.length&&<details><summary>{c.evidence.length} referências no código</summary>{c.evidence.map((e,i)=><code key={i}>{e.file}:{e.line}</code>)}</details>}<small>{c.assurance}</small></article>)}</div>{!controls.length&&<div className="empty">Esta análise foi criada com uma versão anterior. Execute uma nova análise para gerar o checklist.</div>}</section>
}
export function RuntimeResults({runtime}){if(!runtime)return null;return <section className="panel list-panel"><h2>Matriz de acesso · runtime</h2><p>{runtime.scope}</p><div className="table-scroll"><table><thead><tr><th>Caso / caminho</th><th>Identidade</th><th>Status esperado</th><th>Recebido</th><th>Contrato</th></tr></thead><tbody>{runtime.results.map(r=><tr key={r.case}><td>{r.case} · <code>{r.path}</code></td><td>{r.identity}</td><td>{r.expected.join(', ')}</td><td>{r.actual}</td><td className={r.matched?'matched':'mismatch'}>{r.matched?'Corresponde':'Divergente'}</td></tr>)}</tbody></table></div><p>Corresponder ao contrato de status não comprova isolamento de dados. Revise também corpo, propriedade e efeitos de cada operação.</p></section>}


export function Verdict({verdict}) {
 if(!verdict) return <section className="panel list-panel"><h2>Análise antiga · execute novamente para obter o veredito</h2></section>;
 return <section className={'panel list-panel verdict '+verdict.status} role="status"><h2>{verdict.label}</h2><p>{verdict.scope}</p><p>Contratos HTTP verificados: <strong>{verdict.checks_passed}/{verdict.checks_executed}</strong></p>{verdict.reasons.length>0&&<ul>{verdict.reasons.map(r=><li key={r}>{r}</li>)}</ul>}<details><summary>O que este veredito não certifica</summary><ul>{verdict.exclusions.map(r=><li key={r}>{r}</li>)}</ul></details></section>;
}

export function Dependencies({audit}) {
 if(!audit) return null;
 return <section className="panel list-panel"><h2>Dependências npm · OSV</h2><p>{audit.scope}</p><p>Estado: <strong>{audit.status}</strong> · {audit.packages} pacotes · {audit.vulnerabilities.length} correspondências</p>{audit.errors.map(e=><p key={e}>{e}</p>)}{audit.vulnerabilities.length>0&&<div className="table-scroll"><table><thead><tr><th>Pacote</th><th>Versão</th><th>Advisory</th></tr></thead><tbody>{audit.vulnerabilities.map((v,i)=><tr key={i}><td>{v.package}</td><td>{v.version}</td><td>{v.advisory}</td></tr>)}</tbody></table></div>}<p>Correspondência de versão exige avaliar alcance e atualização; não comprova explorabilidade.</p></section>;
}

export function Coverage({coverage}) {
 if(!coverage.by_extension) return null;
 return <section className="panel list-panel"><h2>Cobertura estática</h2><div className="table-scroll"><table><thead><tr><th>Extensão</th><th>Arquivos lidos</th></tr></thead><tbody>{Object.entries(coverage.by_extension).map(([ext,n])=><tr key={ext}><td>{ext}</td><td>{n}</td></tr>)}</tbody></table></div><p>Arquivos lidos não significam análise semântica completa.</p><ul>{Object.entries(coverage.skipped_reasons||{}).map(([reason,n])=><li key={reason}>{reason}: {n}</li>)}</ul><p>{coverage.excluded_directories||0} diretórios excluídos sem percorrer o conteúdo; seus arquivos não entram na contagem.</p>{Object.keys(coverage.unsupported_source||{}).length>0&&<p>Código sem analisador: {Object.entries(coverage.unsupported_source).map(([ext,n])=>`${ext}: ${n}`).join(', ')}. Esses arquivos não foram avaliados.</p>}</section>;
}
