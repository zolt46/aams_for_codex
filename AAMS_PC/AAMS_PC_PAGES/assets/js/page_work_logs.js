import { API_BASE } from './config.js';
import { requireAuth } from './work_utils.js';
import { toast } from './toast.js';

const auth=requireAuth();
if(!auth.is_admin){ location.replace('new_workcenter_apply.html'); throw new Error('admin only'); }

const etype=document.getElementById('etype');
const fromD=document.getElementById('fromD');
const toD=document.getElementById('toD');
const tbody=document.querySelector('#logT tbody');
let cache=[];

async function load(){
  const qs=new URLSearchParams(); const e=etype.value; if(e) qs.set('event_type',e);
  const res=await fetch(`${API_BASE}/api/executions?${qs.toString()}`); if(!res.ok){ toast('로그 조회 실패','error'); return; }
  let rows=await res.json();
  const fd=fromD.value?new Date(fromD.value):null, td=toD.value?new Date(toD.value):null;
  if(fd) rows=rows.filter(r=>new Date(r.executed_at)>=fd);
  if(td){ td.setDate(td.getDate()+1); rows=rows.filter(r=>new Date(r.executed_at)<td); }
  cache=rows; render(rows);
}
function render(rows){
  tbody.innerHTML='';
  rows.forEach(r=>{
    const fchg=(r.firearm_changes||[]).map(c=>`${c.firearm_number}: ${c.from_status}→${c.to_status}`).join('<br/>')||'-';
    const amv=(r.ammo_moves||[]).map(m=>`${m.ammo_name} ${m.delta} (= ${m.before_qty}→${m.after_qty})`).join('<br/>')||'-';
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${new Date(r.executed_at).toLocaleString()}</td><td>${r.event_type}</td><td>${r.executed_by_name||r.executed_by}</td><td>${fchg}</td><td>${amv}</td><td>${r.notes||''}</td>`;
    tbody.appendChild(tr);
  });
}
function exportCSV(rows){
  const head=['executed_at','event_type','executed_by','firearm_changes','ammo_moves','notes'];
  const lines=[head.join(',')].concat(rows.map(r=>{
    const f=(r.firearm_changes||[]).map(c=>`${c.firearm_number}:${c.from_status}->${c.to_status}`).join('|');
    const a=(r.ammo_moves||[]).map(m=>`${m.ammo_name}:${m.delta}(${m.before_qty}->${m.after_qty})`).join('|');
    return [r.executed_at,r.event_type,(r.executed_by_name||r.executed_by),JSON.stringify(f),JSON.stringify(a),JSON.stringify(r.notes||'')].join(',');
  }));
  const blob=new Blob([lines.join('\n')],{type:'text/csv'}); const url=URL.createObjectURL(blob); const a=document.createElement('a');
  a.href=url; a.download='executions.csv'; a.click(); URL.revokeObjectURL(url);
}
document.getElementById('reload').onclick=load;
document.getElementById('csv').onclick=()=>exportCSV(cache);
load();
