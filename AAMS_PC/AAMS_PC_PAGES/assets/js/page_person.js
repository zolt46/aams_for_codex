import { apiGet, apiPost, apiPut, apiDel, safeDo } from './api.js';
import { addSelectHeader, mountSelectAll, statusBadge } from './table.js';
import { openModal } from './modal.js';

document.addEventListener('DOMContentLoaded', async () => {
  const table = document.getElementById('person-table');
  const tbody = document.getElementById('person-table-body');
  const searchInput = document.getElementById('search-input');
  const adminFilter = document.getElementById('admin-filter');
  const unitFilter  = document.getElementById('unit-filter');
  const searchBtn   = document.getElementById('search-button');
  const btnNew      = document.getElementById('new-person');
  const btnDel      = document.getElementById('bulk-delete');

  const selectedIds = new Set();
  let fetched = [], view = [], sortCol = null, sortDir = 'asc';

  addSelectHeader(table);

  function personForm(p={}){
    return `
      <form id="person-form" class="aams-form">
        <div class="grid-2">
          <label>이름<input name="name" value="${p.name??''}" required></label>
          <label>계급<input name="rank" value="${p.rank??''}"></label>
          <label>군번<input name="service_number" value="${p.service_number??''}"></label>
          <label>소속<input name="unit" value="${p.unit??''}"></label>
          <label>직책<input name="position" value="${p.position??''}"></label>
          <label>시스템 아이디<input name="system_id" value="${p.system_id??''}"></label>
          <label>비밀번호<input type="password" name="password" placeholder="${p.id?'(변경시만 입력)':''}"></label>
          <label>관리자<select name="is_admin">
            <option value="false" ${!p.is_admin?'selected':''}>허용안함</option>
            <option value="true"  ${p.is_admin?'selected':''}>허용</option>
          </select></label>
        </div>
        <label>비고<input name="notes" value="${p.notes??''}"></label>
      </form>`;
  }

  async function load(){
    fetched = await apiGet('/api/personnel');
    const units = [...new Set(fetched.map(x=>x.unit).filter(Boolean))];
    unitFilter.innerHTML = `<option value="">-- 소속 --</option>` + units.map(u=>`<option>${u}</option>`).join('');
    apply();
  }

  function apply(){
    const q  = (searchInput?.value || '').toLowerCase();
    const af = adminFilter?.value || '';
    const uf = unitFilter?.value || '';

    view = fetched.filter(p => {
      const text = [p.name,p.rank,p.service_number,p.unit,p.position,p.system_id,p.notes].map(v=>String(v??'').toLowerCase()).join(' ');
      const okAdmin = !af || (af==='허용' ? !!p.is_admin : !p.is_admin);
      const okUnit  = !uf || p.unit === uf;
      return text.includes(q) && okAdmin && okUnit;
    });

    if (sortCol != null) {
      const get = (r, i) => [r.name,r.rank,r.service_number,r.unit,r.position,(r.is_admin?'허용':'허용안함'),Date.parse(r.last_login)||0,r.system_id][i];
      view.sort((a,b) => {
        const av = get(a, sortCol), bv = get(b, sortCol);
        const num = (typeof av === 'number' || typeof bv === 'number');
        return sortDir === 'asc' ? (num?av-bv:String(av).localeCompare(String(bv))) : (num?bv-av:String(bv).localeCompare(String(av)));
      });
    }

    render(); summary();
  }

  function summary(){
    document.getElementById('total-person-rows').textContent = String(view.length);
    document.getElementById('admin-count').textContent = String(view.filter(p=>!!p.is_admin).length);
  }

  function render(){
    tbody.innerHTML='';
    for (const p of view){
      const tr=document.createElement('tr');

      const tdSel=document.createElement('td');
      const cb=document.createElement('input'); cb.type='checkbox'; cb.className='row-select'; cb.dataset.id=String(p.id);
      cb.addEventListener('change', ()=>{ cb.checked?selectedIds.add(cb.dataset.id):selectedIds.delete(cb.dataset.id); });
      tdSel.appendChild(cb); tr.appendChild(tdSel);

      const adminText = p.is_admin ? '허용' : '허용안함';
      const cells = [p.name,p.rank,p.service_number,p.unit,p.position,adminText,p.last_login,p.system_id];
      cells.forEach((val,i)=>{
        const td=document.createElement('td');
        if (i===5) statusBadge(td,String(val));
        else if (i===6) td.textContent = p.last_login ? new Date(p.last_login).toISOString().slice(0,16).replace('T',' ') : '';
        else td.textContent = String(val ?? '');
        tr.appendChild(td);
      });

      tr.addEventListener('dblclick', ()=>openEdit(p));
      tbody.appendChild(tr);
    }
    mountSelectAll(tbody, selectedIds, ()=>{});
  }

  function openEdit(p){
    openModal({
      title: p?.id ? '인원 수정' : '인원 등록',
      body: personForm(p),
      onSave: async ()=>{
        const fd = new FormData(document.getElementById('person-form'));
        const payload = Object.fromEntries(fd.entries());
        payload.is_admin = (payload.is_admin === 'true');
        if (!payload.password) delete payload.password;
        if (p?.id) await safeDo(()=>apiPut(`/api/personnel/${p.id}`, payload),'수정 완료');
        else       await safeDo(()=>apiPost('/api/personnel', payload),'등록 완료');
        await load();
      }
    });
  }

  table.querySelectorAll('thead th[data-column-index]').forEach(th=>{
    th.addEventListener('click', ()=>{
      const idx = parseInt(th.dataset.columnIndex,10);
      if (Number.isNaN(idx)) return;
      sortCol = idx; sortDir = (sortDir === 'asc') ? 'desc' : 'asc';
      apply();
      table.querySelectorAll('.sort-icon').forEach(i => i.textContent = '');
      const icon = th.querySelector('.sort-icon'); if (icon) icon.textContent = sortDir==='asc'?'▲':'▼';
    });
  });

  searchBtn?.addEventListener('click', apply);
  searchInput?.addEventListener('keyup', e=>{ if (e.key==='Enter') apply(); });
  adminFilter?.addEventListener('change', apply);
  unitFilter?.addEventListener('change', apply);
  btnNew?.addEventListener('click', ()=>openEdit(null));
  btnDel?.addEventListener('click', async ()=>{
    if (!selectedIds.size) return;
    await safeDo(()=>apiDel(`/api/personnel?ids=${encodeURIComponent([...selectedIds].join(','))}`),'삭제 완료');
    selectedIds.clear(); await load();
  });

  await load();
});
