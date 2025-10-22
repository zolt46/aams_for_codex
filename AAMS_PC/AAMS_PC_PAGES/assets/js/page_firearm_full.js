import { API_BASE } from './config.js';
import { toast } from './toast.js';

const table = document.getElementById('firearm-table');
const tbody = document.getElementById('firearms-table-body');
const searchInput  = document.getElementById('search-input');
const statusFilter = document.getElementById('status-filter');
const searchBtn    = document.getElementById('search-button');

const btnAdd    = document.getElementById('btn-add');
const btnEdit   = document.getElementById('btn-edit');
const btnSave   = document.getElementById('btn-save');
const btnCancel = document.getElementById('btn-cancel');
const btnDel    = document.getElementById('btn-del');
const selInfo   = document.getElementById('selected-count');

let owners = [];       // [{id,name,rank,unit,position,military_id}]
let rows   = [];       // 서버 데이터(조인됨)
let view   = [];       // 필터/정렬 적용본
let selected = new Set();
let sortCol = null, sortDir = 'asc';
let editMode = null; // 'add' | 'edit' | null
let editingId = null;

function fmt(iso){ if(!iso) return ''; try{ return new Date(iso).toISOString().slice(0,16).replace('T',' ');}catch{ return String(iso)} }
function statusBadge(td, value){
  const s=document.createElement('span'); s.className='status-badge '+(value==='불출'?'불출':'불입');
  s.textContent=value||''; td.appendChild(s);
}
function updateSelectedInfo(){
  selInfo.textContent = `선택: ${selected.size}`;
  const all = tbody.querySelectorAll('input.row-select');
  const sa = document.getElementById('select-all');
  if (sa){
    sa.checked = !!all.length && selected.size===all.length;
    sa.indeterminate = selected.size>0 && selected.size<all.length;
  }
}

function addSelectHeader(){
  const tr = table.querySelector('thead tr');
  if (!tr || tr.firstElementChild.classList?.contains('select-col')) return;
  const th = document.createElement('th'); th.classList.add('select-col'); th.style.width='44px';
  th.innerHTML = `<input type="checkbox" id="select-all"/>`;
  tr.insertBefore(th, tr.firstElementChild);
  tr.querySelector('#select-all').addEventListener('change', e=>{
    selected.clear();
    tbody.querySelectorAll('input.row-select').forEach(cb=>{
      cb.checked = e.target.checked;
      if (e.target.checked) selected.add(cb.dataset.id);
    });
    updateSelectedInfo();
  });
}

function toCells(r){
  return [
    r.owner_name||'', r.owner_rank||'', r.owner_military_id||'', r.owner_unit||'', r.owner_position||'',
    r.firearm_type||'', r.firearm_number||'', r.storage_locker||'', r.status||'', fmt(r.last_change), r.notes||''
  ];
}

function render(){
  tbody.innerHTML='';
  for (const r of view){
    const tr = document.createElement('tr');

    const tdSel=document.createElement('td');
    const cb=document.createElement('input'); cb.type='checkbox'; cb.className='row-select'; cb.dataset.id=String(r.id);
    cb.addEventListener('change', ()=>{ cb.checked?selected.add(cb.dataset.id):selected.delete(cb.dataset.id); updateSelectedInfo(); });
    tdSel.appendChild(cb); tr.appendChild(tdSel);

    const cells = toCells(r);
    cells.forEach((v,i)=>{
      const td=document.createElement('td');
      if (i===8) statusBadge(td,String(v)); else td.textContent=String(v);
      tr.appendChild(td);
    });

    tbody.appendChild(tr);
  }
  updateSelectedInfo();
}

function apply(){
  const q = (searchInput.value||'').toLowerCase();
  const st = statusFilter.value;
  view = rows.filter(r=>{
    const text = [r.owner_name,r.owner_rank,r.owner_military_id,r.owner_unit,r.owner_position,r.firearm_type,r.firearm_number,r.storage_locker,r.notes]
      .map(v=>String(v??'').toLowerCase()).join(' ');
    return text.includes(q) && (!st || r.status===st);
  });
  if (sortCol!=null){
    const get=(r,i)=>[
      r.owner_name,r.owner_rank,r.owner_military_id,r.owner_unit,r.owner_position,
      r.firearm_type,r.firearm_number,r.storage_locker,r.status,Date.parse(r.last_change)||0,r.notes
    ][i];
    view.sort((a,b)=>{
      const av=get(a,sortCol), bv=get(b,sortCol), num=(typeof av==='number'||typeof bv==='number');
      return sortDir==='asc' ? (num?av-bv:String(av).localeCompare(String(bv))) : (num?bv-av:String(bv).localeCompare(String(av)));
    });
  }
  render(); counts();
}

function counts(){
  document.getElementById('total-firearms-count').textContent = String(view.length);
  document.getElementById('dispatch-count').textContent = String(view.filter(r=>r.status==='불출').length);
  document.getElementById('returned-count').textContent = String(view.filter(r=>r.status==='불입').length);
}

function bindSort(){
  table.querySelectorAll('thead th[data-column-index]').forEach(th=>{
    th.addEventListener('click', ()=>{
      const idx = parseInt(th.dataset.columnIndex,10); if (isNaN(idx)) return;
      sortCol=idx; sortDir = sortDir==='asc'?'desc':'asc'; apply();
      table.querySelectorAll('.sort-icon').forEach(i=>i.textContent='');
      th.querySelector('.sort-icon').textContent = sortDir==='asc'?'▲':'▼';
    });
  });
}

function ensureNoEdit(){ if (editMode){ toast('편집 중입니다. 저장/취소 후 진행하세요','error'); return false; } return true; }
function ownerSelect(selectedId=null){
  const s=document.createElement('select'); s.style.width='100%';
  s.innerHTML = '<option value="">-- 소유자 선택 --</option>' + owners.map(o=>
    `<option value="${o.id}">${o.name} (${o.rank}, ${o.unit}, ${o.position}, ${o.military_id})</option>`
  ).join('');
  if (selectedId) s.value = String(selectedId);
  return s;
}
function input(v=''){ const i=document.createElement('input'); i.value=v??''; i.style.width='100%'; return i; }
function selectStatus(v='불입'){ const s=document.createElement('select'); s.innerHTML='<option value="불입">불입</option><option value="불출">불출</option>'; s.value=v||'불입'; return s; }

function buildEditRow(data={}, isNew=false){
  const tr=document.createElement('tr');

  const tdSel=document.createElement('td'); const dis=document.createElement('input'); dis.type='checkbox'; dis.disabled=true; tdSel.appendChild(dis); tr.appendChild(tdSel);

  const tdOwner=document.createElement('td'); const selOwner=ownerSelect(data.owner_id||null); tdOwner.appendChild(selOwner); tr.appendChild(tdOwner);
  const tdRank=document.createElement('td'); tdRank.textContent=data.owner_rank||''; tr.appendChild(tdRank);
  const tdMil =document.createElement('td'); tdMil.textContent =data.owner_military_id||''; tr.appendChild(tdMil);
  const tdUnit=document.createElement('td'); tdUnit.textContent=data.owner_unit||''; tr.appendChild(tdUnit);
  const tdPos =document.createElement('td'); tdPos.textContent =data.owner_position||''; tr.appendChild(tdPos);

  const tdType=document.createElement('td'); const inType=input(data.firearm_type); tdType.appendChild(inType); tr.appendChild(tdType);
  const tdNum =document.createElement('td'); const inNum =input(data.firearm_number); tdNum.appendChild(inNum); tr.appendChild(tdNum);
  const tdLoc =document.createElement('td'); const inLoc =input(data.storage_locker); tdLoc.appendChild(inLoc); tr.appendChild(tdLoc);
  const tdSta =document.createElement('td'); const selSta=selectStatus(data.status||'불입'); tdSta.appendChild(selSta); tr.appendChild(tdSta);
  const tdChg =document.createElement('td'); tdChg.textContent = data.last_change?fmt(data.last_change):''; tr.appendChild(tdChg);
  const tdNote=document.createElement('td'); const inNote=input(data.notes); tdNote.appendChild(inNote); tr.appendChild(tdNote);

  selOwner.addEventListener('change', ()=>{
    const o=owners.find(x=>String(x.id)===selOwner.value);
    tdRank.textContent=o?.rank||''; tdMil.textContent=o?.military_id||''; tdUnit.textContent=o?.unit||''; tdPos.textContent=o?.position||'';
  });

  tr._refs = { selOwner, inType, inNum, inLoc, selSta, inNote };
  tr._isNew=isNew; tr._id=data.id||null;
  return tr;
}

function getEditingRow(){ return Array.from(tbody.children).find(tr=>tr._refs); }

function collectPayload(tr){
  const { selOwner, inType, inNum, inLoc, selSta, inNote } = tr._refs;
  const payload = {
    owner_id: selOwner.value ? Number(selOwner.value) : null,
    firearm_type: (inType.value||'').trim(),
    firearm_number: (inNum.value||'').trim(),
    storage_locker: (inLoc.value||'').trim(),
    status: selSta.value,
    notes: (inNote.value||'').trim(),
  };
  const req = ['owner_id','firearm_type','firearm_number','storage_locker','status'];
  for (const k of req){ if (!payload[k]) throw new Error(`필수값 누락: ${k}`); }
  return payload;
}

// === events ===
btnAdd?.addEventListener('click', ()=>{
  if (!ensureNoEdit()) return;
  editMode='add'; editingId=null;
  const tr=buildEditRow({}, true);
  tbody.insertBefore(tr, tbody.firstChild);
  selected.clear(); updateSelectedInfo();
});

btnEdit?.addEventListener('click', ()=>{
  if (!ensureNoEdit()) return;
  if (selected.size!==1){ toast('수정할 행을 하나만 선택하세요','error'); return; }
  editMode='edit'; editingId=[...selected][0];
  const data = rows.find(r=>String(r.id)===String(editingId));
  if (!data){ toast('선택한 항목을 찾을 수 없습니다','error'); editMode=null; return; }
  // 현재 view에서 위치 찾아 교체
  const idx = view.findIndex(r=>String(r.id)===String(editingId));
  render();
  const tr = buildEditRow(data,false);
  tbody.replaceChild(tr, tbody.children[idx]);
});

btnSave?.addEventListener('click', async ()=>{
  if (!editMode){ toast('저장할 변경이 없습니다','error'); return; }
  const tr = getEditingRow(); if (!tr){ editMode=null; editingId=null; return; }
  try{
    const payload = collectPayload(tr);
    let res;
    if (editMode==='add'){
      res = await fetch(`${API_BASE}/api/firearms`, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload) });
    }else{
      res = await fetch(`${API_BASE}/api/firearms/${editingId}`, { method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload) });
    }
    if (!res.ok){ const t=await res.text(); throw new Error(`저장 실패: ${res.status} ${t}`); }
    toast('저장 완료','success');
    editMode=null; editingId=null;
    await load(); // 재조회
  }catch(e){ console.error(e); toast(e.message||'저장 중 오류','error'); }
});

btnCancel?.addEventListener('click', ()=>{
  const tr = getEditingRow();
  if (tr && tr.parentNode) tr.parentNode.removeChild(tr);
  editMode=null; editingId=null;
  selected.clear(); updateSelectedInfo();
  render();
});

btnDel?.addEventListener('click', async ()=>{
  if (selected.size<1){ toast('삭제할 행을 선택하세요','error'); return; }
  if (!confirm(`선택한 ${selected.size}건을 삭제하시겠습니까?`)) return;
  try{
    for (const id of [...selected]){
      const res = await fetch(`${API_BASE}/api/firearms/${id}`, { method:'DELETE' });
      if (!res.ok){
        const txt = await res.text();
        if (res.status===409){
          toast('참조 이력으로 삭제 불가: 먼저 관련 신청/이력을 정리하세요','error');
        }else{
          throw new Error(`삭제 실패 (${id}): ${res.status} ${txt}`);
        }
      }
    }
    toast('삭제 완료','success');
    selected.clear(); await load();
  }catch(e){ console.error(e); toast(e.message||'삭제 중 오류','error'); }
});

searchBtn?.addEventListener('click', apply);
searchInput?.addEventListener('keyup', e=>{ if (e.key==='Enter') apply(); });
statusFilter?.addEventListener('change', apply);

// === data ===
async function fetchOwners(){
  const r = await fetch(`${API_BASE}/api/personnel`); if (!r.ok) throw new Error('소유자 목록 실패');
  owners = await r.json();
  owners = owners.map(o=>({ id:o.id, name:o.name, rank:o.rank, unit:o.unit, position:o.position, military_id:o.military_id }));
}
async function fetchFirearms(){
  const r = await fetch(`${API_BASE}/api/firearms_full`); if (!r.ok) throw new Error(`총기 목록 실패: ${r.status}`);
  rows = await r.json(); view=[...rows]; render(); counts();
}
async function load(){
  await fetchOwners();
  await fetchFirearms();
  bindSort();
}

(function init(){
  addSelectHeader();
  load().catch(e=>{ console.error(e); toast('데이터 로딩 실패','error'); });
})();
