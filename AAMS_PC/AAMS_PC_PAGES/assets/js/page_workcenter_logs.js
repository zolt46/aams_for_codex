import { apiGet, safeDo } from './api.js';
import { downloadCSV } from './csv.js';

document.addEventListener('DOMContentLoaded', async ()=>{
  const tbody = document.getElementById('logs-body');
  const sDate = document.getElementById('start-date');
  const eDate = document.getElementById('end-date');
  const q     = document.getElementById('search-input');
  const btnSearch = document.getElementById('search-button');
  const btnCSV = document.getElementById('download-csv');

  let rows=[];
  async function load(){
    const qs = new URLSearchParams();
    if (sDate?.value) qs.set('start', new Date(sDate.value).toISOString());
    if (eDate?.value) qs.set('end',   new Date(eDate.value).toISOString());
    if (q?.value)     qs.set('q', q.value);
    rows = await safeDo(()=>apiGet('/api/workcenter/logs?'+qs.toString()));
    render();
  }
  function render(){
    tbody.innerHTML='';
    for (const r of rows){
      const tr=document.createElement('tr');
      tr.innerHTML = `
        <td>${r.id}</td><td>${r.event_type}</td><td>${r.actor_name??''}</td>
        <td>${r.target??''}</td><td>${r.message??''}</td>
        <td>${r.created_at?new Date(r.created_at).toISOString().slice(0,16).replace('T',' '):''}</td>`;
      tbody.appendChild(tr);
    }
  }
  btnSearch?.addEventListener('click', load);
  q?.addEventListener('keyup', e=>{ if(e.key==='Enter') load(); });
  btnCSV?.addEventListener('click', ()=>{
    const head = ['ID','이벤트','행위자','대상','메시지','시간'];
    const data = rows.map(r=>[r.id,r.event_type,r.actor_name||'',r.target||'',r.message||'',r.created_at||'']);
    downloadCSV(`AAMS_logs_${Date.now()}.csv`, [head, ...data]);
  });

  await load();
});
