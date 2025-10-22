import { API_BASE } from './config.js';
import { toast } from './toast.js';

const table = document.getElementById('person-table');
const tbody = document.getElementById('person-table-body');

const qInput   = document.getElementById('search-input');
const unitSel  = document.getElementById('unit-filter');
const adminSel = document.getElementById('admin-filter');
const qBtn     = document.getElementById('search-button');

const btnAdd    = document.getElementById('btn-add');
const btnEdit   = document.getElementById('btn-edit');
const btnSave   = document.getElementById('btn-save');
const btnCancel = document.getElementById('btn-cancel');
const btnDel    = document.getElementById('btn-del');
const selInfo   = document.getElementById('selected-count');

let rows=[], view=[], selected=new Set();
let sortCol=null, sortDir='asc', editMode=null, editingId=null;

/* ---------- helpers ---------- */
const MASK = '****';
const fmtDate = (iso)=> iso ? (new Date(iso).toISOString().slice(0,10)) : '';
const safe = (v, f='') => (v==null ? f : v);
const adminText = (v)=> v ? '허용' : '허용 안함';

function updateCounts(){
  const total = view.length;
  const allowed = view.filter(r=>r.is_admin).length;
  const denied  = total - allowed;
  document.getElementById('total-personnel-count').textContent = String(total);
  document.getElementById('admin-allowed-count').textContent = String(allowed);
  document.getElementById('admin-not-allowed-count').textContent = String(denied);
}

function updateSelectedInfo(){
  selInfo.textContent=`선택: ${selected.size}`;
  const all=tbody.querySelectorAll('input.row-select'); const sa=document.getElementById('select-all');
  if(sa){ sa.checked=!!all.length && selected.size===all.length; sa.indeterminate = selected.size>0 && selected.size<all.length; }
}

function addSelectHeader(){
  const tr=table.querySelector('thead tr');
  if(!tr || tr.firstElementChild.classList?.contains('select-col')) return;
  const th=document.createElement('th'); th.classList.add('select-col'); th.style.width='44px';
  th.innerHTML=`<input type="checkbox" id="select-all"/>`;
  tr.insertBefore(th, tr.firstElementChild);
  tr.querySelector('#select-all').addEventListener('change', e=>{
    selected.clear();
    tbody.querySelectorAll('input.row-select').forEach(cb=>{
      cb.checked = e.target.checked; if(e.target.checked) selected.add(cb.dataset.id);
    });
    updateSelectedInfo();
  });
}

/* ---------- render ---------- */
function toCells(r){
  return [
    safe(r.name), safe(r.rank), safe(r.military_id), safe(r.unit),
    safe(r.position), safe(r.user_id), MASK, adminText(!!r.is_admin),
    safe(r.contact), fmtDate(r.last_modified||r.last_login), safe(r.notes),
  ];
}

function render(){
  tbody.innerHTML='';
  for(const r of view){
    const tr=document.createElement('tr');

    // 선택 체크박스
    const tdSel=document.createElement('td');
    const cb=document.createElement('input'); cb.type='checkbox'; cb.className='row-select'; cb.dataset.id=String(r.id);
    cb.addEventListener('change', ()=>{ cb.checked?selected.add(cb.dataset.id):selected.delete(cb.dataset.id); updateSelectedInfo(); });
    tdSel.appendChild(cb); tr.appendChild(tdSel);

    // 데이터 셀
    const cells=toCells(r);
    cells.forEach((v,i)=>{
      const td=document.createElement('td');
      if(i===7){ // 관리자 배지
        const span=document.createElement('span');
        const isAllow = (v==='허용');
        span.className = `status-badge ${isAllow?'status-allow':'status-deny'}`;
        span.textContent = isAllow ? '허용' : '허용 안함';
        td.appendChild(span);
      }else{
        td.textContent = String(v);
      }
      tr.appendChild(td);
    });

    tbody.appendChild(tr);
  }
  updateSelectedInfo();
}

function apply(){
  const q=(qInput.value||'').toLowerCase();
  const unit=unitSel.value; const adm=adminSel.value;

  view = rows.filter(r=>{
    const hay=[r.name,r.rank,r.military_id,r.unit,r.position,r.user_id,r.contact,r.notes]
      .map(x=>String(x??'').toLowerCase()).join(' ');
    if(q && !hay.includes(q)) return false;
    if(unit && r.unit!==unit) return false;
    if(adm==='Y' && !r.is_admin) return false;
    if(adm==='N' &&  r.is_admin) return false;
    return true;
  });

  if(sortCol!=null){
    const get=(r,i)=>[
      r.name,r.rank,r.military_id,r.unit,r.position,r.user_id, '', adminText(!!r.is_admin),
      r.contact, (Date.parse(r.last_modified||r.last_login)||0), r.notes
    ][i];
    view.sort((a,b)=>{
      const av=get(a,sortCol), bv=get(b,sortCol);
      return sortDir==='asc' ? (av>bv?1:av<bv?-1:0) : (av>bv?-1:av<bv?1:0);
    });
  }

  render(); updateCounts();
}

function bindSort(){
  table.querySelectorAll('thead th[data-column-index]').forEach(th=>{
    th.addEventListener('click', ()=>{
      const idx=parseInt(th.dataset.columnIndex,10); if(isNaN(idx)) return;
      sortCol=idx; sortDir = sortDir==='asc'?'desc':'asc'; apply();
      table.querySelectorAll('.sort-icon').forEach(i=>i.textContent='');
      th.querySelector('.sort-icon').textContent = sortDir==='asc'?'▲':'▼';
    });
  });
}

/* ---------- edit helpers ---------- */
function ensureNoEdit(){ if(editMode){ toast('편집 중입니다. 저장/취소 후 진행하세요','error'); return false; } return true; }
const input = (v='')=>{ const i=document.createElement('input'); i.value=v??''; i.style.width='100%'; return i; };
function selectAdmin(v){ const s=document.createElement('select'); s.innerHTML='<option value="Y">허용</option><option value="N">허용 안함</option>'; s.value=v?'Y':'N'; return s; }

function buildEditRow(data={}, isNew=false){
  const tr=document.createElement('tr');
  const tdSel=document.createElement('td'); const dis=document.createElement('input'); dis.type='checkbox'; dis.disabled=true; tdSel.appendChild(dis); tr.appendChild(tdSel);

  const inName=input(data.name), inRank=input(data.rank), inMil=input(data.military_id),
        inUnit=input(data.unit), inPos=input(data.position), inUid=input(data.user_id),
        inPwd=input(''), selAdm=selectAdmin(!!data.is_admin),
        inTel=input(data.contact), inNote=input(data.notes);
  const modTxt = fmtDate(data.last_modified||data.last_login)||'';

  // 열 순서에 맞춰 추가
  [inName,inRank,inMil,inUnit,inPos,inUid,inPwd,selAdm,inTel,modTxt,inNote].forEach((el,idx)=>{
    const td=document.createElement('td');
    if(idx===7){ td.appendChild(el); }           // 관리자 select
    else if(idx===9){ td.textContent = modTxt; } // 최근 변동일 텍스트
    else td.appendChild(el);
    tr.appendChild(td);
  });

  tr._refs={inName,inRank,inMil,inUnit,inPos,inUid,inPwd,selAdm,inTel,inNote};
  tr._isNew=isNew; tr._id=data.id||null;
  return tr;
}

function getEditingRow(){ return Array.from(tbody.children).find(tr=>tr._refs); }

function collectPayload(tr){
  const { inName,inRank,inMil,inUnit,inPos,selAdm,inUid,inPwd,inTel,inNote } = tr._refs;
  const p={
    name:(inName.value||'').trim(),
    rank:(inRank.value||'').trim(),
    military_id:(inMil.value||'').trim(),
    unit:(inUnit.value||'').trim(),
    position:(inPos.value||'').trim(),
    is_admin: selAdm.value==='Y',
    user_id:(inUid.value||'').trim(),
    contact:(inTel.value||'').trim(),
    notes:(inNote.value||'').trim(),
  };
  const req=['name','military_id','unit','user_id'];
  for(const k of req){ if(!p[k]) throw new Error(`필수값 누락: ${k}`); }
  const pwd=(inPwd.value||'').trim();
  if(tr._isNew){ if(!pwd) throw new Error('초기 비밀번호를 입력하세요'); p.password_hash=pwd; }
  else{ if(pwd) p.password_hash=pwd; }
  return p;
}

/* ---------- CRUD buttons ---------- */
btnAdd?.addEventListener('click', ()=>{
  if(!ensureNoEdit()) return;
  editMode='add'; editingId=null;
  const tr=buildEditRow({}, true);
  tbody.insertBefore(tr, tbody.firstChild);
  selected.clear(); updateSelectedInfo();
});

btnEdit?.addEventListener('click', async ()=>{
  if(!ensureNoEdit()) return;
  if(selected.size!==1){ toast('수정할 행을 하나만 선택하세요','error'); return; }
  editMode='edit'; editingId=[...selected][0];
  // 단건 상세(비밀번호 해시 등 필요 시)
  let detail=null;
  try{
    const res=await fetch(`${API_BASE}/api/personnel/${editingId}`);
    detail = res.ok ? (await res.json()) : rows.find(r=>String(r.id)===String(editingId));
  }catch{ detail = rows.find(r=>String(r.id)===String(editingId)); }
  const idx=view.findIndex(r=>String(r.id)===String(editingId));
  render();
  const tr=buildEditRow(detail||{}, false);
  tbody.replaceChild(tr, tbody.children[idx]);
});

btnSave?.addEventListener('click', async ()=>{
  if(!editMode){ toast('저장할 변경이 없습니다','error'); return; }
  const tr=getEditingRow(); if(!tr){ editMode=null; editingId=null; return; }
  try{
    const payload=collectPayload(tr);
    let res;
    if(editMode==='add'){
      res=await fetch(`${API_BASE}/api/personnel`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    }else{
      res=await fetch(`${API_BASE}/api/personnel/${editingId}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    }
    if(!res.ok){ const t=await res.text(); throw new Error(`저장 실패: ${res.status} ${t}`); }
    toast('저장 완료','success'); editMode=null; editingId=null; await load();
  }catch(e){ console.error(e); toast(e.message||'저장 중 오류','error'); }
});

btnCancel?.addEventListener('click', ()=>{
  const tr=getEditingRow(); if(tr && tr.parentNode) tr.parentNode.removeChild(tr);
  editMode=null; editingId=null; selected.clear(); updateSelectedInfo(); render();
});

btnDel?.addEventListener('click', async ()=>{
  if(selected.size<1){ toast('삭제할 행을 선택하세요','error'); return; }
  if(!confirm(`선택한 ${selected.size}건을 삭제하시겠습니까?`)) return;
  try{
    for(const id of [...selected]){
      const res=await fetch(`${API_BASE}/api/personnel/${id}`,{method:'DELETE'});
      if(!res.ok){
        if(res.status===409){
          const msg = await res.text().catch(()=>null);
          toast(msg || '참조 이력으로 삭제 불가(배정/신청 등)', 'error');
          continue;
        }
        throw new Error(`삭제 실패(${id}): ${res.status}`);
      }
    }
    toast('삭제 완료','success'); selected.clear(); await load();
  }catch(e){ console.error(e); toast(e.message||'삭제 중 오류','error'); }
});

/* ---------- sort/filter ---------- */
qBtn?.addEventListener('click', apply);
qInput?.addEventListener('keyup', e=>{ if(e.key==='Enter') apply(); });
unitSel?.addEventListener('change', apply);
adminSel?.addEventListener('change', apply);

/* ---------- loader (정규화 포함) ---------- */
async function fetchCore(url){
  const r=await fetch(url); if(!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  let d=await r.json();
  if(Array.isArray(d)) return d;
  for(const k of ['rows','data','items','personnel','list','result']) if(Array.isArray(d?.[k])) return d[k];
  return (d && typeof d==='object') ? [d] : [];
}
function normalize(p,i=0){
  const id = p.id ?? p.person_id ?? p.user_id ?? (i+1);
  const name = p.name ?? p.full_name ?? p.username ?? p.display_name ?? '';
  const rank = p.rank ?? p.grade ?? '';
  const military_id = p.military_id ?? p.service_no ?? p.soldier_id ?? '';
  const unit = p.unit ?? p.company ?? p.department ?? '';
  const position = p.position ?? p.role_name ?? p.duty ?? '';
  const is_admin =
    typeof p.is_admin === 'boolean' ? p.is_admin :
    typeof p.is_admin === 'number'  ? !!p.is_admin :
    typeof p.role     === 'string'  ? p.role.toUpperCase()==='ADMIN' :
    typeof p.role     === 'number'  ? p.role===1 : false;
  const user_id = p.user_id ?? p.login ?? p.username ?? p.email ?? '';
  const contact = p.contact ?? p.phone ?? p.tel ?? '';
  const last_modified = p.last_modified ?? p.updated_at ?? p.last_seen ?? p.last_login ?? null;
  const notes = p.notes ?? p.memo ?? '';
  return { id,name,rank,military_id,unit,position,is_admin,user_id,contact,last_modified,notes, last_login:p.last_login };
}
async function fetchPersonnel(){
  const endpoints=[
    `${API_BASE}/api/personnel`,
    `${API_BASE}/api/personnel/all`,
    `${API_BASE}/api/users`,
    `${API_BASE}/api/persons`
  ];
  let arr=null;
  for(const u of endpoints){ try{ const a=await fetchCore(u); if(a.length){ arr=a; break; } }catch{} }
  if(!arr) throw new Error('인원 목록 조회 실패');
  rows=arr.map(normalize);
  // 유닛 필터
  const units=[...new Set(rows.map(x=>x.unit).filter(Boolean))].sort();
  unitSel.innerHTML='<option value="">-- 소속 --</option>'+units.map(u=>`<option value="${u}">${u}</option>`).join('');
  view=[...rows]; apply(); bindSort();
}
async function load(){ addSelectHeader(); await fetchPersonnel(); }
load().catch(e=>{ console.error(e); toast('데이터 로딩 실패: '+(e.message||e),'error'); });
