import { API_BASE } from './config.js';
import { requireAuth, kType, kStatus, statusClass, fmt, csvEscape } from './work_utils.js';
import { toast } from './toast.js';

const auth = requireAuth();
const els = {
  fStatus: document.getElementById('fStatus'),
  fType: document.getElementById('fType'),
  from: document.getElementById('from'),
  to: document.getElementById('to'),
  q: document.getElementById('q'),
  tableBody: document.querySelector('#t tbody'),
  checkAll: document.getElementById('checkAll'),
  cancelSel: document.getElementById('cancelSel'),
  deleteSel: document.getElementById('deleteSel'),
};
let rows=[];

async function load(){
  const url = auth.is_admin
    ? `${API_BASE}/api/requests`                         // 관리자: 전체
    : `${API_BASE}/api/requests?requester_id=${auth.id}`; // 사용자: 본인만
  const res = await fetch(url);
  if(!res.ok){ toast('목록 조회 실패','error'); return; }
  const all=await res.json();

  // 관리자: SUBMITTED(대기)는 감춤 → 재오픈 시 승인함으로만 이동
  // 사용자: 모든 상태 보이기(취소 가능하게)
  rows = auth.is_admin ? all.filter(r => r.status !== 'SUBMITTED') : all;
  render();
}

function render(){
  els.tableBody.innerHTML='';
  rows.forEach(r=>{
    const tr=document.createElement('tr');
    tr.dataset.id=r.id; tr.dataset.status=r.status;
    tr.innerHTML=`
      <td><input type="checkbox" class="rowchk"/></td>
      <td>#${r.id}</td>
      <td><span class="badge b-type">${kType(r.request_type)}</span></td>
      <td>${r.requester_name || r.requester_id}</td>
      <td>${fmt(r.scheduled_at)}</td>
      <td><span class="badge ${statusClass(r.status)}">${kStatus(r.status)}</span></td>
      <td id="dec-${r.id}"><span class="badge b-submitted">-</span></td>
      <td id="sum-${r.id}" class="muted">읽는 중…</td>
      <td>${r.purpose||'-'}</td>
      <td>${r.location||'-'}</td>
      <td class="actions">
      ${auth.is_admin ? `
          <button class="btn secondary" data-ex="${r.id}" ${(r.status==='APPROVED' && r.status!=='CANCELLED')?'':'disabled'}>집행</button>
          <button class="btn warn" data-rp="${r.id}" ${['APPROVED','REJECTED'].includes(r.status)?'':'disabled'}>취소(재오픈)</button>
        ` : ``}
      ${r.status==='CANCELLED' ? '' :
        ((!auth.is_admin && (r.status==='SUBMITTED' || r.status==='REJECTED'))
          ? `<button class="btn warn" data-uc="${r.id}">취소</button>` : ``)}
        <button class="btn ghost" data-id="${r.id}">상세</button>
      </td>`;
    els.tableBody.appendChild(tr);
    enrichRow(r.id);
  });

  // 기존 상세 버튼 핸들러 유지
  els.tableBody.querySelectorAll('button[data-id]').forEach(b=>b.onclick=()=>toggleDetail(parseInt(b.dataset.id,10), b));
  // ✅ 행 클릭으로도 상세 토글
  els.tableBody.addEventListener('click', (e)=>{
    const cell = e.target.closest('td,th'); if(!cell) return;
    const tr   = e.target.closest('tr'); if(!tr || !tr.dataset.id) return;

    // 예외: 체크박스나 액션 버튼 영역 클릭은 무시
    if (e.target.closest('input[type="checkbox"]')) return;
    if (cell.classList.contains('actions') || e.target.closest('.actions')) return;
    if (e.target.tagName === 'BUTTON') return;

    toggleDetail(parseInt(tr.dataset.id, 10), tr);
  });
  els.tableBody.querySelectorAll('button[data-ex]').forEach(b=>b.onclick=()=>rowAct(parseInt(b.dataset.ex,10),'execute'));
  els.tableBody.querySelectorAll('button[data-rp]').forEach(b=>b.onclick=()=>rowAct(parseInt(b.dataset.rp,10),'reopen'));
  els.tableBody.querySelectorAll('button[data-uc]').forEach(b=>b.onclick=()=>userCancel(parseInt(b.dataset.uc,10)));
  els.tableBody.querySelectorAll('.rowchk').forEach(chk=>chk.addEventListener('change', syncBulk));
  els.checkAll.checked=false; syncBulk();
}

async function userCancel(id){
  if(!confirm('이 신청을 취소하시겠습니까?')) return;
  // 백엔드가 /cancel 엔드포인트를 제공한다고 가정
  // (만약 서버에서 /withdraw, /close 등 다른 경로를 쓰면 여기만 바꿔주세요)
  const res = await fetch(`${API_BASE}/api/requests/${id}/cancel`, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ actor_id: Number(auth.id) })
  });
  if(!res.ok){
    let msg='취소 실패';
    try{ const j=await res.json(); if(j?.error) msg = `취소 실패: ${j.error}`; }catch{}
    toast(msg,'error'); return;
  }
  toast('신청 취소 완료','success');
  document.querySelectorAll('tr.expand-row').forEach(n=>n.remove()); // 상세 닫기
  load();
}

async function rowAct(id, action){
  const url = action==='execute'
    ? `${API_BASE}/api/requests/${id}/execute`
    : `${API_BASE}/api/requests/${id}/reopen`;
  const body = action==='execute' ? { executed_by: auth.id } : { actor_id: auth.id };
  const res = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
  if(!res.ok){ toast((action==='execute'?'집행':'재오픈')+' 실패','error'); return; }
  toast((action==='execute'?'집행':'재오픈')+' 완료','success');
  document.querySelectorAll('tr.expand-row').forEach(n=>n.remove()); // 상세 닫기
  load();
}

async function enrichRow(id){
  try{
    const res=await fetch(`${API_BASE}/api/requests/${id}`); if(!res.ok) return;
    const d=await res.json(); const items=d.items||[], approvals=d.approvals||[];
    const gunNos=items.filter(i=>i.item_type==='FIREARM').map(i=>i.firearm_number).filter(Boolean);
    const gunsPart = gunNos.length?`총기 ${gunNos.slice(0,2).join(', ')}${gunNos.length>2?` 외 ${gunNos.length-2}정`:''}`:'총기 0건';
    const ammoLines=items.filter(i=>i.item_type==='AMMO').length;
    const ammoQty=items.filter(i=>i.item_type==='AMMO').reduce((s,i)=>s+(i.quantity||0),0);
    const ammoPart=ammoLines?`탄약 ${ammoLines}건(수량 ${ammoQty})`:'탄약 0건';
    const sumCell=document.getElementById(`sum-${id}`); if(sumCell) sumCell.textContent=`${gunsPart} · ${ammoPart}`;
    if(approvals.length){
      const last=approvals[approvals.length-1]; const ok=last.decision==='APPROVE';
      const dec=document.getElementById(`dec-${id}`); if(dec) dec.innerHTML=`<span class="badge ${ok?'b-approved':'b-rejected'}">${ok?'승인':'거부'}</span><span class="muted"> · ${fmt(last.decided_at)}</span>`;
    }
  }catch{}
}


async function toggleDetail(id, btn){
  const tr = btn.closest('tr') || document.querySelector(`tbody tr[data-id="${id}"]`);
  const existing = tr.parentElement.querySelector(`tr.expand-row[data-for="${id}"]`);
  if (existing) { existing.remove(); return; }
  tr.parentElement.querySelectorAll('tr.expand-row').forEach(n => n.remove());

  const res = await fetch(`${API_BASE}/api/requests/${id}`);
  if (!res.ok){ toast('상세 조회 실패','error'); return; }
  const d = await res.json();
  const r = d.request || d;
  const items = d.items || [];
  const approvals = d.approvals || [];
  const execs = d.executions || [];

  const wrap = document.createElement('tr');
  wrap.className = 'expand-row';
  wrap.dataset.for = String(id);

  const td = document.createElement('td');
  td.colSpan = tr.children.length; // ✅ 테이블 열 수에 맞춰 자동

  td.innerHTML = `
    <div class="expand">
      <div class="grid" style="margin-bottom:8px">
        <div class="chip">요청 ID #${r.id}</div><div class="chip">상태 ${kStatus(r.status)}</div><div class="chip">유형 ${kType(r.request_type)}</div>
        <div class="chip">신청자 ${r.requester_name||r.requester_id}</div><div class="chip">예정 ${fmt(r.scheduled_at)}</div><div class="chip">생성 ${fmt(r.created_at)}</div>
        <div class="chip">수정 ${fmt(r.updated_at)}</div><div class="chip">목적 ${r.purpose||'-'}</div><div class="chip">장소 ${r.location||'-'}</div>
        ${r.notes?`<div class="chip" style="grid-column:1/-1">비고 ${r.notes}</div>`:''}
      </div>
      <div class="grid">
        <div>
          <div class="muted" style="margin-bottom:6px">항목 상세</div>
          ${items.length?`
            <table style="width:100%;border-collapse:separate;border-spacing:0 6px">
              <thead><tr><th>종류</th><th>식별</th><th>수량</th></tr></thead>
              <tbody>
                ${items.map(it=> it.item_type==='FIREARM'
                    ? `<tr><td>총기</td><td>${it.firearm_number||it.firearm_id} (${it.firearm_type||''})</td><td>-</td></tr>`
                    : `<tr><td>탄약</td><td>${it.ammo_name||it.ammo_id} (${it.ammo_category||''})</td><td>${it.quantity||0}</td></tr>`
                ).join('')}
              </tbody>
            </table>` : '<span class="muted">항목 없음</span>'}
        </div>
        <div>
          <div class="muted" style="margin-bottom:6px">승인/거부 이력</div>
          <div class="chip-list">
            ${approvals.length
              ? approvals.map(a=>{ const ok=a.decision==='APPROVE';
                  return `<div class="chip" style="${ok?'background:#17301d':'background:#301717'}">${ok?'승인':'거부'} · ${fmt(a.decided_at)} · ${a.approver_name||a.approver_id}${a.reason?` · 사유:${a.reason}`:''}</div>`;
                }).join('')
              : '<span class="muted">결정 없음(제출됨)</span>'}
          </div>
      </div>
            ${execs && execs.length ? `
      <div style="margin-top:10px">
        <div class="muted" style="margin-bottom:6px">집행 로그</div>
        <div class="chip-list">${execs.map(e=>`<div class="chip">[${e.event_type}] ${fmt(e.executed_at)} · by ${e.executed_by_name||e.executed_by}</div>`).join('')}</div>
      </div>` : '' }
      <div class="timeline" style="margin-top:8px"></div>
    </div>`;

  wrap.appendChild(td);
  tr.after(wrap);

  try{
    const treq = await fetch(`${API_BASE}/api/requests/${id}/timeline`);
    if(treq.ok){
      const tl = await treq.json();
      const host = td.querySelector('.timeline');
      if (host) {
        host.classList.add('chip-list');
        host.innerHTML = tl.map(ev => `
          <span class="chip">${fmt(ev.event_time)} · ${ev.event_type}${ev.notes?` · ${ev.notes}`:''}</span>
        `).join('');
      }
    }
  }catch{}
}

function selectedTrs(){ return [...els.tableBody.querySelectorAll('.rowchk')].filter(c=>c.checked).map(c=>c.closest('tr')); }
function syncBulk(){
  const sel=selectedTrs(); const any=sel.length>0;
  els.cancelSel.disabled = true; // 선택 재오픈 비활성(사용자 '내 이력'에선 안 씀)
  els.deleteSel.disabled = true; // 선택 삭제 전면 폐기
  els.checkAll.indeterminate = any && ![...els.tableBody.querySelectorAll('.rowchk')].every(c=>c.checked);
}
els.checkAll.addEventListener('change', ()=>{ const on=els.checkAll.checked; els.tableBody.querySelectorAll('.rowchk').forEach(c=>c.checked=on); syncBulk(); });

document.getElementById('reload').onclick=load;
[els.fStatus,els.fType,els.from,els.to].forEach(el=>el.addEventListener('change', load));
els.q.addEventListener('input',()=>{ clearTimeout(window.__qTimer); window.__qTimer=setTimeout(load,200); });

document.getElementById('cancelSel').onclick=async()=>{
  const sel=selectedTrs(); if(sel.length===0) return;
  if(!confirm(`선택 ${sel.length}건을 '재오픈(다시 제출)' 하시겠습니까?`)) return;
  let ok=0, fail=0;
  for(const tr of sel){
    const id=tr.dataset.id;
    const res=await fetch(`${API_BASE}/api/requests/${id}/reopen`,{
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({actor_id:auth.id})
    });
    res.ok?ok++:fail++;
  }
  toast(`재오픈 완료: ${ok} / 실패: ${fail}`, fail?'error':'success'); load();
};
document.getElementById('deleteSel').onclick=async()=>{
  const sel=selectedTrs(); if(sel.length===0) return;
  if(!confirm(`선택 ${sel.length}건을 삭제하시겠습니까? (거부 상태만)`)) return;
  let ok=0, fail=0;
  for(const tr of sel){
    const id=tr.dataset.id, st=tr.dataset.status; if(st!=='REJECTED'){ fail++; continue; }
    const res=await fetch(`${API_BASE}/api/requests/${id}`,{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({actor_id:auth.id})});
    res.ok?ok++:fail++;
  }
  toast(`삭제 완료: ${ok} / 실패: ${fail}`, fail?'error':'success'); load();
};

document.getElementById('exportCsv').onclick=()=>{
  const header=['ID','유형','예정','진행','목적','장소'];
  const lines=[header.join(',')].concat(rows.map(r=>[`#${r.id}`,kType(r.request_type),fmt(r.scheduled_at),kStatus(r.status),r.purpose||'',r.location||''].map(csvEscape).join(',')));
  const blob=new Blob([lines.join('\n')],{type:'text/csv;charset=utf-8;'}); const url=URL.createObjectURL(blob); const a=document.createElement('a');
  a.href=url; a.download='my_history.csv'; a.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
};

load();
