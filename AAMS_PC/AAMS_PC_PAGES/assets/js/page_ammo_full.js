import { API_BASE } from './config.js';
import { toast } from './toast.js';

const table = document.getElementById('ammo-table');
const tbody = document.getElementById('ammo-table-body');

const qInput = document.getElementById('search-input');
const catSel = document.getElementById('category-filter');
const qBtn   = document.getElementById('search-button');

const btnAdd    = document.getElementById('btn-add');
const btnEdit   = document.getElementById('btn-edit');
const btnSave   = document.getElementById('btn-save');
const btnCancel = document.getElementById('btn-cancel');
const btnDel    = document.getElementById('btn-del');
const selInfo   = document.getElementById('selected-count');

let rows=[], view=[], selected=new Set();
let sortCol=null, sortDir='asc', editMode=null, editingId=null;

const fmt = (iso) => (iso ? new Date(iso).toISOString().slice(0,16).replace('T',' ') : '');

function updateSummary(){
  document.getElementById('total-ammo-count').textContent = String(view.length);
  const cats=[...new Set(view.map(r=>(r.ammo_category ? r.ammo_category : null)).filter(Boolean))].length;
  document.getElementById('category-count').textContent = String(cats);
  // 불출 중(가용 < 재고) 단순 추정
  const out=view.filter(r=>{
    const avail = (typeof r.available === 'number') ? r.available
                 : (typeof r.quantity === 'number') ? r.quantity : null;
    const qty   = (typeof r.quantity === 'number') ? r.quantity : null;
    return avail !== null && qty !== null && avail < qty;
  }).length;
  document.getElementById('dispatching-count').textContent = String(out);
}

function updateSelectedInfo(){
  selInfo.textContent=`선택: ${selected.size}`;
  const all=tbody.querySelectorAll('input.row-select');
  const sa=document.getElementById('select-all');
  if(sa){
    sa.checked = !!all.length && selected.size===all.length;
    sa.indeterminate = selected.size>0 && selected.size<all.length;
  }
}

function addSelectHeader(){
  const tr=table.querySelector('thead tr');
  if(!tr || tr.firstElementChild.classList?.contains('select-col')) return;
  const th=document.createElement('th');
  th.classList.add('select-col');
  th.style.width='44px';
  th.innerHTML=`<input type="checkbox" id="select-all"/>`;
  tr.insertBefore(th, tr.firstElementChild);
  tr.querySelector('#select-all').addEventListener('change', e=>{
    selected.clear();
    tbody.querySelectorAll('input.row-select').forEach(cb=>{
      cb.checked = e.target.checked;
      if(e.target.checked) selected.add(cb.dataset.id);
    });
    updateSelectedInfo();
  });
}

function safe(val, fallback=''){
  return (val === null || val === undefined) ? fallback : val;
}

function toCells(r){
  const qty = safe(r.quantity, '');
  const avail = (r.available === null || r.available === undefined)
    ? safe(r.quantity, '')
    : r.available;
  return [
    safe(r.ammo_name, ''), safe(r.ammo_category, ''), safe(r.caliber, ''),
    qty, avail, safe(r.storage_locker, ''), fmt(r.last_change), safe(r.notes,'')
  ];
}

function render(){
  tbody.innerHTML='';
  for(const r of view){
    const tr=document.createElement('tr');

    // 선택 체크박스
    const tdSel=document.createElement('td');
    const cb=document.createElement('input');
    cb.type='checkbox';
    cb.className='row-select';
    cb.dataset.id=String(r.id);
    cb.addEventListener('change', ()=>{
      if(cb.checked) selected.add(cb.dataset.id);
      else selected.delete(cb.dataset.id);
      updateSelectedInfo();
    });
    tdSel.appendChild(cb);
    tr.appendChild(tdSel);

    // 데이터 셀
    const cells=toCells(r);
    cells.forEach(v=>{
      const td=document.createElement('td');
      td.textContent=String(v);
      tr.appendChild(td);
    });

    tbody.appendChild(tr);
  }
  updateSelectedInfo();
}

function apply(){
  const q=(qInput.value||'').toLowerCase();
  const cat=catSel.value;

  view = rows.filter(r=>{
    const hay=[r.ammo_name,r.ammo_category,r.caliber,r.storage_locker,r.notes]
      .map(x=>String(x==null ? '' : x).toLowerCase()).join(' ');
    if(q && !hay.includes(q)) return false;
    if(cat && r.ammo_category!==cat) return false;
    return true;
  });

  if(sortCol!=null){
    const get=(r,i)=>{
      const qty   = (typeof r.quantity === 'number') ? r.quantity : 0;
      const avail = (r.available == null) ? qty : r.available;
      const last  = Date.parse(r.last_change) || 0;
      const cols  = [r.ammo_name,r.ammo_category,r.caliber,qty,avail,r.storage_locker,last,r.notes];
      return cols[i];
    };
    view.sort((a,b)=>{
      const av=get(a,sortCol), bv=get(b,sortCol);
      return (sortDir==='asc')
        ? (av>bv?1:(av<bv?-1:0))
        : (av>bv?-1:(av<bv?1:0));
    });
  }
  render();
  updateSummary();
}

function bindSort(){
  table.querySelectorAll('thead th[data-column-index]').forEach(th=>{
    th.addEventListener('click', ()=>{
      const idx=parseInt(th.dataset.columnIndex,10);
      if(isNaN(idx)) return;
      sortCol=idx;
      sortDir = (sortDir==='asc') ? 'desc' : 'asc';
      apply();
      table.querySelectorAll('.sort-icon').forEach(i=>i.textContent='');
      th.querySelector('.sort-icon').textContent = (sortDir==='asc') ? '▲' : '▼';
    });
  });
}

function ensureNoEdit(){
  if(editMode){
    toast('편집 중입니다. 저장/취소 후 진행하세요','error');
    return false;
  }
  return true;
}

const input = (v='')=>{
  const i=document.createElement('input');
  i.value=(v==null ? '' : v);
  i.style.width='100%';
  return i;
};
function numInput(v){
  const i=document.createElement('input');
  i.type='number'; i.min='0'; i.step='1';
  i.value = (typeof v === 'number') ? v : 0;
  i.style.width='100%';
  return i;
}

function buildEditRow(data={}, isNew=false){
  const tr=document.createElement('tr');

  const tdSel=document.createElement('td');
  const dis=document.createElement('input');
  dis.type='checkbox'; dis.disabled=true;
  tdSel.appendChild(dis);
  tr.appendChild(tdSel);

  const inName = input(data.ammo_name);
  const inCat  = input(data.ammo_category);
  const inCal  = input(data.caliber);
  const inQty  = numInput((typeof data.quantity==='number') ? data.quantity : 0);
  const inLoc  = input(data.storage_locker);
  const last   = fmt(data.last_change) || '';
  const inNote = input(data.notes);

  // 렌더 순서에 맞춰 셀 추가(가용은 서버 계산이므로 편집 X)
  const avail = (data.available == null)
    ? (typeof data.quantity==='number' ? data.quantity : '')
    : data.available;

  const seq = [
    [inName], [inCat], [inCal], [inQty],
    [document.createTextNode(String(avail))],
    [inLoc], [last], [inNote]
  ];

  seq.forEach((els,idx)=>{
    const td=document.createElement('td');
    if(idx===6) td.textContent = last;
    else els.forEach(el=>td.appendChild(el));
    tr.appendChild(td);
  });

  tr._refs={ inName,inCat,inCal,inQty,inLoc,inNote };
  tr._isNew=isNew;
  tr._id = data.id || null;
  return tr;
}

function getEditingRow(){
  return Array.from(tbody.children).find(tr=>tr._refs);
}

function collectPayload(tr){
  const { inName,inCat,inCal,inQty,inLoc,inNote } = tr._refs;
  const qtyVal = parseInt((inQty.value||'0'),10);

  const payload={
    ammo_name: (inName.value||'').trim(),
    ammo_category: (inCat.value||'').trim(),
    caliber: (inCal.value||'').trim(),
    quantity: isNaN(qtyVal) ? 0 : qtyVal,
    storage_locker: (inLoc.value||'').trim(),
    notes: (inNote.value||'').trim(),
  };

  if(!payload.ammo_name) throw new Error('품명은 필수입니다');
  if(payload.quantity < 0 || !Number.isInteger(payload.quantity)) throw new Error('재고 수량은 0 이상의 정수여야 합니다');
  return payload;
}

// === Events ===
btnAdd?.addEventListener('click', ()=>{
  if(!ensureNoEdit()) return;
  editMode='add'; editingId=null;
  const tr=buildEditRow({}, true);
  tbody.insertBefore(tr, tbody.firstChild);
  selected.clear(); updateSelectedInfo();
});

btnEdit?.addEventListener('click', ()=>{
  if(!ensureNoEdit()) return;
  if(selected.size!==1){ toast('수정할 행을 하나만 선택하세요','error'); return; }
  editMode='edit'; editingId=[...selected][0];
  const data=rows.find(r=>String(r.id)===String(editingId));
  if(!data){ toast('선택한 항목을 찾을 수 없습니다','error'); editMode=null; return; }
  const idx=view.findIndex(r=>String(r.id)===String(editingId));
  render();
  const tr=buildEditRow(data,false);
  tbody.replaceChild(tr, tbody.children[idx]);
});

btnSave?.addEventListener('click', async ()=>{
  if(!editMode){ toast('저장할 변경이 없습니다','error'); return; }
  const tr=getEditingRow(); if(!tr){ editMode=null; editingId=null; return; }
  try{
    const payload=collectPayload(tr);
    let res;
    if(editMode==='add'){
      res=await fetch(`${API_BASE}/api/ammunition`,{
        method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)
      });
    }else{
      res=await fetch(`${API_BASE}/api/ammunition/${editingId}`,{
        method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)
      });
    }
    if(!res.ok){
      const t=await res.text(); throw new Error(`저장 실패: ${res.status} ${t}`);
    }
    toast('저장 완료','success');
    editMode=null; editingId=null;
    await load();
  }catch(e){
    console.error(e);
    toast(e.message||'저장 중 오류','error');
  }
});

btnCancel?.addEventListener('click', ()=>{
  const tr=getEditingRow();
  if(tr && tr.parentNode) tr.parentNode.removeChild(tr);
  editMode=null; editingId=null;
  selected.clear(); updateSelectedInfo();
  render();
});

btnDel?.addEventListener('click', async ()=>{
  if(selected.size<1){ toast('삭제할 행을 선택하세요','error'); return; }
  if(!confirm(`선택한 ${selected.size}건을 삭제하시겠습니까?`)) return;
  try{
    for(const id of [...selected]){
      const res=await fetch(`${API_BASE}/api/ammunition/${id}`,{ method:'DELETE' });
      if(!res.ok) throw new Error(`삭제 실패(${id}): ${res.status}`);
    }
    toast('삭제 완료','success');
    selected.clear();
    await load();
  }catch(e){
    console.error(e);
    toast(e.message||'삭제 중 오류','error');
  }
});

qBtn?.addEventListener('click', apply);
qInput?.addEventListener('keyup', (e)=>{ if(e.key==='Enter') apply(); });
catSel?.addEventListener('change', apply);

async function fetchAmmo(){
  const r=await fetch(`${API_BASE}/api/ammunition?limit=5000`);
  if(!r.ok) throw new Error('목록 실패');
  rows=await r.json();

  // 카테고리 필터 옵션
  const cats=[...new Set(rows.map(x=>x.ammo_category).filter(Boolean))].sort();
  catSel.innerHTML = '<option value="">-- 카테고리 --</option>' + cats.map(c=>`<option value="${c}">${c}</option>`).join('');

  view=[...rows];
  apply();
  bindSort();
}

async function load(){
  addSelectHeader();
  await fetchAmmo();
}

load().catch(e=>{
  console.error(e);
  toast('데이터 로딩 실패','error');
});
