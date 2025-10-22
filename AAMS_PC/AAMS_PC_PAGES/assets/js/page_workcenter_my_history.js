import { apiGet, apiPost, safeDo } from './api.js';

document.addEventListener('DOMContentLoaded', async ()=>{
  const tbody = document.getElementById('history-body');
  const btnRefresh = document.getElementById('refresh');
  let rows=[];

  async function load(){ rows = await safeDo(()=>apiGet('/api/workcenter/my_history')); render(); }
  function render(){
    tbody.innerHTML='';
    for (const r of rows){
      const canCancel = r.status==='대기';
      const tr=document.createElement('tr');
      tr.innerHTML = `
        <td>${r.id}</td><td>${r.request_type}</td><td>${r.weapon_name??''}</td>
        <td>${r.ammo_name??''}</td><td>${r.quantity??''}</td>
        <td>${r.status}</td>
        <td>${r.approver_name??''}</td>
        <td>${r.updated_at?new Date(r.updated_at).toISOString().slice(0,16).replace('T',' '):''}</td>
        <td>${canCancel?'<button class="cancel" data-id="'+r.id+'">취소</button>':''}</td>`;
      tbody.appendChild(tr);
    }
    tbody.querySelectorAll('button.cancel').forEach(b=>{
      b.addEventListener('click', async ()=>{
        const id=b.dataset.id;
        await safeDo(()=>apiPost(`/api/workcenter/my_history/${id}/cancel`,{}),'취소 완료');
        await load();
      });
    });
  }
  btnRefresh?.addEventListener('click', load);
  await load();
});
