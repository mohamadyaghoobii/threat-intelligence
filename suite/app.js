const names={overview:'Operations overview',unified:'Unified IOC',central:'Central TI',ua:'UA Intel',ip:'IP List'};
const icons=['▦','◇','⌗','◎','⊞'];
const feed=location.pathname.split('/')[1]||'overview';
const mode=new URLSearchParams(location.search).get('mode')==='live'?'live':'demo';
const $=s=>document.querySelector(s);
const esc=x=>String(x??'Unknown').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=s=>s?new Date(s).toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}):'—';
const href=f=>(f==='overview'?'/':'/'+f)+'?mode='+mode;
const badge=(s,ok)=>'<span class="badge '+(ok?'':'warn')+'">'+esc(s)+'</span>';
const status=r=>r.status==='active'&&Date.parse(r.expires)<=Date.now()?'expired':r.status;
function health(s){
 if(s.attempt.error)return 'Degraded';
 if(s.attempt.stage&&s.attempt.stage!=='published')return 'In progress';
 if(!s.manifest.version)return 'Unpublished';
 return Date.parse(s.manifest.expires)<=Date.now()?'Stale':'Current';
}
function summary(s){
 return s.attempt.error||({Stale:'Publication freshness window elapsed',Unpublished:'Awaiting first collection','In progress':'Latest recorded stage · '+s.attempt.stage,Current:'Within freshness window'})[health(s)];
}
let state,records=[],page=0;
function table(head,rows){return '<div class="panel"><table><thead><tr>'+head.map(h=>'<th>'+h+'</th>').join('')+'</tr></thead><tbody>'+rows.join('')+'</tbody></table>'+(!rows.length?'<div class="empty">No matching records.</div>':'')+'</div>'}
function cards(items){return '<div class="cards">'+items.map(([label,value])=>'<div class="card"><span class="eyebrow">'+label+'</span><b>'+esc(value)+'</b></div>').join('')+'</div>'}
function modal(title,html){$('article').innerHTML='<h2>'+esc(title)+'</h2>'+html;$('dialog').showModal()}
function compare(f){
 const m=state[f].manifest;
 modal(names[f]+' · Publication changes','<p class="mono">'+esc(m.previous||'Initial publication')+' → '+esc(m.version)+'</p>'+Object.entries(m.changes).map(([k,v])=>'<h3>'+k+' · '+v.length+'</h3><pre>'+esc(v.map(x=>x.join('   ')).join('\n')||'None')+'</pre>').join(''))
}
function overview(){
 const items=Object.entries(state);
 $('#body').innerHTML=cards([['MONITORED FEEDS',items.length],['CURRENT',items.filter(([,s])=>health(s)==='Current').length],['NEED ATTENTION',items.filter(([,s])=>health(s)!=='Current').length],['PUBLISHED OUTPUTS',items.reduce((n,[,s])=>n+(s.manifest.outputs||0),0)]])+'<h2>Feed health</h2>'+table(['INTELLIGENCE FEED','STATE','LAST ATTEMPT / PARSE','PUBLISHED / EXPIRES','INPUT → OUTPUT','PUBLICATION'],items.map(([f,s])=>{
 const m=s.manifest;
 return '<tr><td><a href="'+href(f)+'">'+names[f]+' ↗</a></td><td>'+badge(health(s),health(s)==='Current')+'<small>'+esc(summary(s))+'</small></td><td>'+fmt(s.attempt.started)+'<small>'+fmt(s.parsed)+'</small></td><td>'+fmt(m.published)+'<small>'+fmt(m.expires)+'</small></td><td>'+esc(m.inputs??'—')+' → '+esc(m.outputs??'—')+'</td><td>'+(m.version?'<button data-compare="'+f+'" title="'+esc(m.version)+'">'+m.version.slice(0,8)+' · Compare</button>':'—')+'</td></tr>'}))+ '<h2>Publication changes</h2>'+table(['FEED','ADDED','EXPIRED','REMOVED'],items.map(([f,s])=>'<tr><td>'+names[f]+'</td>'+['added','expired','removed'].map(k=>'<td>'+esc(s.manifest.changes?.[k]?.length??'—')+'</td>').join('')+'</tr>'))
}
const base=m=>'/exports/'+mode+'/'+feed+'/'+m.version+'/';
async function workspace(){
 const s=state[feed],m=s.manifest;
 $('#body').innerHTML=(health(s)!=='Current'?'<div class="alert">'+esc(health(s))+' · '+esc(summary(s))+'<br><small>Attempt '+fmt(s.attempt.started)+' · '+esc(s.attempt.inputs??0)+' input rows</small></div>':'');
 if(!m.version){$('#body').innerHTML+='<p>No published snapshot in this environment.</p>';return}
 records=await get(base(m)+'feed.json');
 $('#body').innerHTML+=cards([['OBSERVATIONS',m.inputs],['CANONICAL RECORDS',m.records],['PUBLISHED LOOKUP',m.outputs]])+'<div class="actions"><button data-compare="'+feed+'">Compare versions</button>'+[['lookup.csv','Download CSV'],['lookup.json','JSON'],['manifest.json','Manifest'],['compat.csv','Compatibility CSV']].map(([path,label])=>'<a class="action" download href="'+base(m)+path+'">'+label+' ↓</a>').join('')+'</div><p class="mono">Publication '+m.version.slice(0,12)+' · '+fmt(m.published)+' · expires '+fmt(m.expires)+'</p><h2>Indicator records</h2><div class="toolbar"><input id="q" aria-label="Search records" placeholder="Search a value or source…">'+select('type','All types',[...new Set(records.map(r=>r.type))])+select('source','All sources',[...new Set(records.flatMap(r=>r.observations.map(o=>o.source)))])+select('age','Any ingestion time',['24 hours','7 days'])+'</div><div id="rows"></div>';
 $('.toolbar').oninput=()=>{page=0;renderRows()};renderRows()
}
function select(id,label,options){return '<select id="'+id+'" aria-label="'+label+'"><option value="">'+label+'</option>'+options.sort().map(v=>'<option>'+esc(v)+'</option>').join('')+'</select>'}
function renderRows(){
 const q=$('#q').value.trim().toLowerCase(),age=$('#age').value,cut=age?Date.now()-(age==='24 hours'?1:7)*86400000:0;
 const matches=records.map((r,i)=>[r,i]).filter(([r])=>(!$('#type').value||r.type===$('#type').value)&&r.observations.some(o=>(!$('#source').value||o.source===$('#source').value)&&Date.parse(o.ingested)>=cut&&(r.value+' '+o.source+' '+(o.category||'')).toLowerCase().includes(q)));
 const start=page*40;
 $('#rows').innerHTML=table(['VALUE','TYPE','SOURCE EVIDENCE','DISPOSITION',''],matches.slice(start,start+40).map(([r,i])=>{
 const o=r.observations[0];return '<tr><td class="mono">'+esc(r.value)+'</td><td>'+esc(r.type)+(feed==='ua'?'<small>'+esc(o.category)+' · '+esc(o.match)+'</small>':'')+'</td><td>'+esc(o.source)+'<small>'+r.observations.length+' observation(s)</small></td><td>'+badge(status(r),status(r)==='active')+'</td><td><button data-index="'+i+'">Inspect</button></td></tr>'}))+'<div class="pager"><button id="prev" '+(page?'':'disabled')+'>Previous</button><small>'+matches.length+' matches · page '+(page+1)+'</small><button id="next" '+(start+40<matches.length?'':'disabled')+'>Next</button></div>';
 $('#prev').onclick=()=>{page--;renderRows()};$('#next').onclick=()=>{page++;renderRows()}
}
async function inspect(i){
 const r=records[i],obs=r.observations;
 modal(r.value,badge(status(r),status(r)==='active')+'<p>'+esc(status(r)==='expired'?'Validity window elapsed':r.reason)+' · expires '+fmt(r.expires)+'</p>'+(feed==='ua'?'<p>Signal for analyst review · '+new Set(obs.map(o=>o.upstream||o.source)).size+' distinct upstream(s)</p>':'')+'<h3>Source observations</h3>'+obs.map(o=>'<h4>'+esc(o.source)+'</h4><pre>'+esc(JSON.stringify(o,null,2))+'</pre>').join('')+'<h3>Disposition history</h3><pre>'+esc(JSON.stringify(r.history,null,2))+'</pre>'+(feed==='central'?'<h3>VirusTotal enrichment</h3><pre id="vt">Loading…</pre>':''));
 if(feed==='central'){const vt=$('#vt');try{vt.textContent=JSON.stringify(await get('/api/enrichment?mode='+mode+'&value='+encodeURIComponent(r.value)),null,2)}catch(e){vt.textContent=e.message}}
}
async function get(url){const r=await fetch(url);if(!r.ok)throw Error('Request failed · '+r.status);return r.json()}
$('#mode').value=mode;$('#mode').onchange=e=>location.search='?mode='+e.target.value;
$('#nav').innerHTML=Object.entries(names).map(([k,v],i)=>'<a class="'+(k===feed?'current':'')+'" href="'+href(k)+'"><strong>'+icons[i]+'</strong>'+v+'</a>').join('');
$('#title').textContent=$('#crumb').textContent=names[feed];
$('#sub').textContent=({overview:'Review collection health, publication freshness and changes across your feeds.',unified:'Trace normalized indicators to their original source observations.',central:'Inspect file hashes, provider observations and enrichment results.',ua:'Review crawler, bot and scanner signals alongside their matching rules.',ip:'Inspect network indicators, endpoint evidence and exclusion decisions.'})[feed];
$('#close').onclick=()=>$('dialog').close();
document.onclick=e=>{if(e.target.dataset.compare)compare(e.target.dataset.compare);if(e.target.dataset.index!==undefined)inspect(+e.target.dataset.index)};
(async()=>{try{state=await get('/api/state?mode='+mode);if(feed==='overview')overview();else await workspace()}catch(e){$('#body').textContent=e.message}})();
