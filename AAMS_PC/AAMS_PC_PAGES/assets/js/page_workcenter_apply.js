import { apiGet, apiPost, safeDo } from './api.js';
import { addSelectHeader } from './table.js';
import { openModal } from './modal.js';

document.addEventListener('DOMContentLoaded', async () => {
  const table = document.getElementById('apply-table');
  const tbody = document.getElementById('apply-table-body');
  const searchInput = document.getElementById('search-input');
  const statusFilter = document.getElementById('status-filter');
  const btnNew = document.getElementById('new-apply');
  const btnRefresh = document.getElementById('refresh');

  addSelectHeader(table);
  let fetched=[], view=[], sortCol=null, sortDir='asc';

  function formMarkup(d={}){
    return `
      <form id="apply-form" class="aams-form">
        <div class="grid-2">
          <label>신청 종류<select name="request_type">
            ${['불출','반납','정비','기타'].map(v=>`<option ${d.request_type===v?'selected':''}>${v}</option>`).join('')}
          </select></label>
          <label>무기<input name="weapon_name" value="${d.weapon_name??''}" required></label>
          <label>탄약<input name="ammo_name" value="${d.ammo_name??''}"></label>
          <label>수량<input type="number" name="quantity" value="${d.quantity??0}" min="0"></label>
          <label>시작<input type="datetime-local" name="start_time" value="${d.start_time?new Date(d.start_time).toISOString().slice(0,16):''}"></label>
          <label>종료<input type="datetime-local" name="end_time" value="${d.end_time?new Date(d.end_time).toISOString().slice(0,16):''}"></label>
        </div>
        <label>비고<input name="notes" value="${d.notes??''}"></label>
      </form>`;
  }

  async function load(){
    fetched = await safeDo(()=>apiGet('/api/workcenter/apply/list'));
    apply();
  }

  function apply(){
    const q = (searchInput?.value||'').toLowerCase();
    const st = statusFilter?.value||'';
    view = fetched.filter(r=>{
      const text = [r.request_type,r.weapon_name,r.ammo_name,r.requester_name,r.status,r.notes].map(v=>String(v??'').toLowerCase()).join(' ');
      return text.includes(q) && (!st || r.status===st);
    });
    if (sortCol!=null){
      const get=(r,i)=>[r.request_type,r.weapon_name,r.ammo_name,r.quantity,Date.parse(r.start_time)||0,Date.parse(r.end_time)||0,r.status,r.requester_name][i];
      view.sort((a,b)=>{
        const av=get(a,sortCol), bv=get(b,sortCol), num=(typeof av==='number'||typeof bv==='number');
        return sortDir==='asc' ? (num?av-bv:String(av).localeCompare(String(bv))) : (num?bv-av:String(bv).localeCompare(String(av)));
      });
    }
    render();
  }

  function render(){
    tbody.innerHTML='';
    for(const r of view){
      const tr=document.createElement('tr');
      tr.innerHTML = `
        <td><input type="checkbox" class="row-select" data-id="${r.id}"></td>
        <td>${r.request_type??''}</td>
        <td>${r.weapon_name??''}</td>
        <td>${r.ammo_name??''}</td>
        <td>${r.quantity??''}</td>
        <td>${r.start_time?new Date(r.start_time).toISOString().slice(0,16).replace('T',' '):''}</td>
        <td>${r.end_time?new Date(r.end_time).toISOString().slice(0,16).replace('T',' '):''}</td>
        <td>${r.status??''}</td>
        <td>${r.requester_name??''}</td>`;
      tr.addEventListener('dblclick', ()=> openEdit(r));
      tbody.appendChild(tr);
    }
  }

  function openEdit(r){
    openModal({
      title: r?.id ? '신청 수정' : '신청 작성',
      body: formMarkup(r),
      onSave: async ()=>{
        const fd=new FormData(document.getElementById('apply-form'));
        const payload=Object.fromEntries(fd.entries());
        if (r?.id) await safeDo(()=>apiPost(`/api/workcenter/apply/update/${r.id}`, payload),'수정 완료');
        else       await safeDo(()=>apiPost('/api/workcenter/apply/create', payload),'신청 완료');
        await load();
      }
    });
  }

  btnNew?.addEventListener('click', ()=>openEdit(null));
  btnRefresh?.addEventListener('click', load);
  searchInput?.addEventListener('keyup', e=>{ if(e.key==='Enter') apply(); });
  statusFilter?.addEventListener('change', apply);

  table.querySelectorAll('thead th[data-column-index]').forEach(th=>{
    th.addEventListener('click',()=>{
      const idx=parseInt(th.dataset.columnIndex,10); if (isNaN(idx)) return;
      sortCol=idx; sortDir = sortDir==='asc'?'desc':'asc'; apply();
      table.querySelectorAll('.sort-icon').forEach(i=>i.textContent='');
      th.querySelector('.sort-icon').textContent = sortDir==='asc'?'▲':'▼';
    });
  });

  await load();
});
