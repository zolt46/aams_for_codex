import { apiGet, apiPost, apiPut, apiDel, safeDo } from './api.js';
import { addSelectHeader, mountSelectAll, statusBadge } from './table.js';
import { openModal } from './modal.js';

document.addEventListener('DOMContentLoaded', () => {
  const table = document.getElementById('firearm-table');
  const tbody = document.getElementById('firearm-table-body');
  const searchInput = document.getElementById('search-input');
  const statusFilter = document.getElementById('status-filter');
  const typeFilter = document.getElementById('type-filter');
  const searchBtn = document.getElementById('search-button');
  const btnNew = document.getElementById('new-firearm');
  const btnDel = document.getElementById('bulk-delete');

  const selectedIds = new Set();
  let fetched = [], view = [], sortCol = null, sortDir = 'asc';

  addSelectHeader(table);

  function firearmForm(record={}){
    return `
      <form id="firearm-form" class="aams-form">
        <div class="grid-2">
          <label>무기명<input name="weapon_name" value="${record.weapon_name??''}" required></label>
          <label>유형<select name="weapon_type">
            ${['소총','권총','기관총','기타'].map(v=>`<option ${record.weapon_type===v?'selected':''}>${v}</option>`).join('')}
          </select></label>
          <label>시리얼<input name="serial_number" value="${record.serial_number??''}"></label>
          <label>보관위치<input name="storage_location" value="${record.storage_location??''}"></label>
          <label>상태<select name="status">
            ${['불입','불출','정비중'].map(v=>`<option ${record.status===v?'selected':''}>${v}</option>`).join('')}
          </select></label>
          <label>비고<input name="notes" value="${record.notes??''}"></label>
        </div>
      </form>`;
  }

  async function load(){
    fetched = await apiGet('/api/firearms');
    apply();
  }

  function apply(){
    const q = (searchInput?.value || '').toLowerCase();
    const st = statusFilter?.value || '';
    const tp = typeFilter?.value || '';

    view = fetched.filter(r => {
      const text = [r.weapon_name, r.weapon_type, r.serial_number, r.storage_location, r.status, r.notes]
        .map(v => String(v ?? '').toLowerCase()).join(' ');
      const okStatus = !st || r.status === st;
      const okType   = !tp || r.weapon_type === tp;
      return text.includes(q) && okStatus && okType;
    });

    if (sortCol != null) {
      const get = (r, i) => [r.weapon_name,r.weapon_type,r.serial_number,r.storage_location,r.status,Date.parse(r.last_change)||0,r.notes][i];
      view.sort((a,b) => {
        const av=get(a,sortCol), bv=get(b,sortCol);
        const num=(typeof av==='number'||typeof bv==='number');
        return sortDir==='asc' ? (num?av-bv:String(av).localeCompare(String(bv))) : (num?bv-av:String(bv).localeCompare(String(av)));
      });
    }

    render(); summary();
  }

  function summary(){
    document.getElementById('total-firearm-rows').textContent = String(view.length);
    document.getElementById('outgoing-count').textContent     = String(view.filter(r=>r.status==='불출').length);
  }

  function render(){
    tbody.innerHTML = '';
    for (const r of view) {
      const tr = document.createElement('tr');

      const tdSel = document.createElement('td');
      const cb = document.createElement('input'); cb.type='checkbox'; cb.className='row-select'; cb.dataset.id=String(r.id);
      cb.addEventListener('change', () => { cb.checked ? selectedIds.add(cb.dataset.id) : selectedIds.delete(cb.dataset.id); });
      tdSel.appendChild(cb); tr.appendChild(tdSel);

      const cells = [r.weapon_name, r.weapon_type, r.serial_number, r.storage_location, r.status, r.last_change, r.notes];
      cells.forEach((val, i) => {
        const td = document.createElement('td');
        if (i === 4) statusBadge(td, String(val));
        else if (i === 5) td.textContent = r.last_change ? new Date(r.last_change).toISOString().slice(0,16).replace('T',' ') : '';
        else td.textContent = String(val ?? '');
        tr.appendChild(td);
      });

      tr.addEventListener('dblclick', () => openEdit(r));
      tbody.appendChild(tr);
    }

    mountSelectAll(tbody, selectedIds, ()=>{});
  }

  function openEdit(r){
    openModal({
      title: r?.id ? '총기 수정' : '총기 등록',
      body: firearmForm(r),
      onSave: async () => {
        const fd = new FormData(document.getElementById('firearm-form'));
        const payload = Object.fromEntries(fd.entries());
        if (r?.id) await safeDo(()=>apiPut(`/api/firearms/${r.id}`, payload),'수정 완료');
        else       await safeDo(()=>apiPost('/api/firearms', payload),'등록 완료');
        await load();
      }
    });
  }

  table.querySelectorAll('thead th[data-column-index]').forEach(th => {
    th.addEventListener('click', () => {
      const idx = parseInt(th.dataset.columnIndex, 10);
      if (Number.isNaN(idx)) return;
      sortCol = idx; sortDir = (sortDir === 'asc') ? 'desc' : 'asc';
      apply();
      table.querySelectorAll('.sort-icon').forEach(i => i.textContent = '');
      const icon = th.querySelector('.sort-icon');
      if (icon) icon.textContent = sortDir === 'asc' ? '▲' : '▼';
    });
  });

  searchBtn?.addEventListener('click', apply);
  searchInput?.addEventListener('keyup', e => { if (e.key === 'Enter') apply(); });
  statusFilter?.addEventListener('change', apply);
  typeFilter?.addEventListener('change', apply);
  btnNew?.addEventListener('click', ()=>openEdit(null));
  btnDel?.addEventListener('click', async ()=>{
    if (!selectedIds.size) return;
    await safeDo(()=>apiDel(`/api/firearms?ids=${encodeURIComponent([...selectedIds].join(','))}`),'삭제 완료');
    selectedIds.clear(); await load();
  });

  load();
});
