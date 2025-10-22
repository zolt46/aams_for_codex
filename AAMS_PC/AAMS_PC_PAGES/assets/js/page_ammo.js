import { apiGet, apiPost, apiPut, apiDel, safeDo } from './api.js';
import { addSelectHeader, mountSelectAll, statusBadge } from './table.js';
import { openModal } from './modal.js';

document.addEventListener('DOMContentLoaded', async () => {
  const table = document.getElementById('ammo-table');
  const tbody = document.getElementById('ammo-table-body');
  const searchInput = document.getElementById('search-input');
  const statusFilter = document.getElementById('status-filter');
  const searchButton = document.getElementById('search-button');
  const btnNew = document.getElementById('new-ammo');

  let fetched = [], view = [], sortCol=null, sortDir='asc';
  const selectedIds = new Set();

  addSelectHeader(table);

  function ammoForm(r={}){
    return `
      <form id="ammo-form" class="aams-form">
        <div class="grid-2">
          <label>탄약명<input name="ammo_name" value="${r.ammo_name??''}" required></label>
          <label>카테고리<input name="ammo_category" value="${r.ammo_category??''}"></label>
          <label>수량<input type="number" name="quantity" value="${r.quantity??0}" min="0"></label>
          <label>보관함<input name="storage_locker" value="${r.storage_locker??''}"></label>
          <label>상태<select name="status">
            ${['불입','불출'].map(v=>`<option ${r.status===v?'selected':''}>${v}</option>`).join('')}
          </select></label>
          <label>비고<input name="notes" value="${r.notes??''}"></label>
        </div>
      </form>`;
  }

  async function load(){
    fetched = await apiGet('/api/ammunition');
    apply();
  }

  function apply(){
    const q = (searchInput.value||'').toLowerCase();
    const st = statusFilter.value;
    view = fetched.filter(r=>{
      const text = [r.ammo_name, r.ammo_category, r.storage_locker, r.status, r.notes, r.quantity]
        .map(v=>String(v??'').toLowerCase()).join(' ');
      const ok = !st || r.status===st;
      return text.includes(q) && ok;
    });
    if (sortCol!=null){
      view.sort((a,b)=>{
        const get = (r,i)=>[r.ammo_name,r.ammo_category,Number(r.quantity)||0,r.storage_locker,r.status,Date.parse(r.last_change)||0,r.notes][i];
        const av=get(a,sortCol), bv=get(b,sortCol);
        const num = (typeof av==='number'||typeof bv==='number');
        return sortDir==='asc' ? (num?av-bv:String(av).localeCompare(String(bv))) : (num?bv-av:String(bv).localeCompare(String(av)));
      });
    }
    render(); counts();
  }

  function counts(){
    document.getElementById('total-ammo-rows').textContent = String(view.length);
    document.getElementById('category-count').textContent  = String(new Set(view.map(r=>r.ammo_category)).size);
    document.getElementById('outgoing-count').textContent  = String(view.filter(r=>r.status==='불출').length);
  }

  function render(){
    tbody.innerHTML='';
    for(const r of view){
      const tr=document.createElement('tr');
      const tdSel=document.createElement('td');
      const cb=document.createElement('input'); cb.type='checkbox'; cb.className='row-select'; cb.dataset.id=String(r.id);
      cb.addEventListener('change',()=>{ cb.checked?selectedIds.add(cb.dataset.id):selectedIds.delete(cb.dataset.id); });
      tdSel.appendChild(cb); tr.appendChild(tdSel);

      const cols=[r.ammo_name,r.ammo_category,r.quantity,r.storage_locker,r.status,r.last_change,r.notes];
      cols.forEach((val,i)=>{
        const td=document.createElement('td');
        if (i===4) statusBadge(td,String(val));
        else if (i===5) td.textContent = r.last_change ? new Date(r.last_change).toISOString().slice(0,16).replace('T',' ') : '';
        else td.textContent = String(val ?? '');
        tr.appendChild(td);
      });
      tr.addEventListener('dblclick',()=>openEdit(r));
      tbody.appendChild(tr);
    }
    mountSelectAll(tbody, selectedIds);
  }

  function openEdit(r){
    openModal({
      title: r?.id ? '탄약 수정' : '탄약 등록',
      body: ammoForm(r),
      onSave: async ()=>{
        const fd=new FormData(document.getElementById('ammo-form'));
        const payload=Object.fromEntries(fd.entries());
        payload.quantity = Number(payload.quantity||0);
        if (r?.id) await safeDo(()=>apiPut(`/api/ammunition/${r.id}`, payload),'수정 완료');
        else       await safeDo(()=>apiPost('/api/ammunition', payload),'등록 완료');
        await load();
      }
    });
  }

  table.querySelectorAll('thead th[data-column-index]').forEach(th=>{
    th.addEventListener('click',()=>{
      const idx=parseInt(th.dataset.columnIndex,10);
      if (isNaN(idx)) return;
      sortCol=idx; sortDir = sortDir==='asc'?'desc':'asc'; apply();
      table.querySelectorAll('.sort-icon').forEach(i=>i.textContent='');
      th.querySelector('.sort-icon').textContent = sortDir==='asc'?'▲':'▼';
    });
  });

  searchButton.addEventListener('click', apply);
  searchInput.addEventListener('keyup', e=>{ if(e.key==='Enter') apply(); });
  statusFilter.addEventListener('change', apply);
  btnNew?.addEventListener('click', ()=>openEdit(null));

  await load();
});
