import { apiGet, apiPost, safeDo } from './api.js';
import { addSelectHeader, mountSelectAll } from './table.js';
import { toast } from './toast.js';

document.addEventListener('DOMContentLoaded', async ()=>{
  const table = document.getElementById('approval-table');
  const tbody = document.getElementById('approval-body');
  const btnApprove = document.getElementById('bulk-approve');
  const btnReject  = document.getElementById('bulk-reject');
  const btnExecute = document.getElementById('bulk-execute');
  const selected = new Set();

  addSelectHeader(table);
  let rows=[];
  async function load(){ rows = await safeDo(()=>apiGet('/api/workcenter/approvals/pending')); render(); }

  function render(){
    tbody.innerHTML='';
    for(const r of rows){
      const tr=document.createElement('tr');
      tr.innerHTML = `
        <td><input type="checkbox" class="row-select" data-id="${r.id}"></td>
        <td>${r.requester_name}</td><td>${r.request_type}</td><td>${r.weapon_name??''}</td>
        <td>${r.ammo_name??''}</td><td>${r.quantity??''}</td><td>${r.status}</td>
        <td>${r.created_at?new Date(r.created_at).toISOString().slice(0,16).replace('T',' '):''}</td>`;
      tbody.appendChild(tr);
    }
    mountSelectAll(tbody, selected, ()=>{});
    tbody.querySelectorAll('input.row-select').forEach(cb=>{
      cb.addEventListener('change', ()=>{ cb.checked?selected.add(cb.dataset.id):selected.delete(cb.dataset.id); });
    });
  }

  async function bulk(path, okMsg){
    if (!selected.size) return toast('선택된 항목이 없습니다','error');
    const ids = [...selected];
    await safeDo(()=>apiPost(`/api/workcenter/approvals/${path}`, { ids }), okMsg);
    selected.clear(); await load();
  }

  btnApprove?.addEventListener('click', ()=>bulk('approve','승인 완료'));
  btnReject?.addEventListener('click',  ()=>bulk('reject','거부 완료'));
  btnExecute?.addEventListener('click', ()=>bulk('execute','집행 완료'));

  await load();
});
