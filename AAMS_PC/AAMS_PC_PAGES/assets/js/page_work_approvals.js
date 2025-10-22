import { API_BASE } from './config.js';
import { requireAuth, kType, kStatus, statusClass, fmt, csvEscape } from './work_utils.js';
import { toast } from './toast.js';

const auth = requireAuth();
if(!auth.is_admin){ location.replace('new_workcenter_apply.html'); throw new Error('admin only'); }

const els={
  fStatus: document.getElementById('fStatus'),
  fType: document.getElementById('fType'),
  from: document.getElementById('from'),
  to: document.getElementById('to'),
  q: document.getElementById('q'),
  tableBody: document.querySelector('#t tbody'),
  checkAll: document.getElementById('checkAll'),
  bulkApprove: document.getElementById('bulkApprove'),
  bulkReject: document.getElementById('bulkReject'),

};
let rows=[];

async function load(){
  const qs=new URLSearchParams();
  // 타입은 서버 필터 사용 가능
  if(els.fType.value) qs.set('type',els.fType.value);
  // 🔁 상태는 "항상 전체"를 받아서 클라에서 필터 (SUBMITTED 선택시 APPROVED도 함께 보기 위함)
  const res=await fetch(`${API_BASE}/api/requests${qs.toString()?`?${qs}`:''}`);
  if(!res.ok){ toast('요청 목록 실패','error'); return; }
  const all=await res.json();

  const q=(els.q.value||'').toLowerCase();
  const from=els.from.value?new Date(els.from.value+'T00:00:00'):null; const to=els.to.value?new Date(els.to.value+'T23:59:59'):null;
  rows = all.filter(r=>{
    const t=r.scheduled_at?new Date(r.scheduled_at):null;
    if(from && (!t||t<from)) return false;
    if(to && (!t||t>to)) return false;
    const hay=[r.requester_name||'',r.purpose||'',r.location||'',r.notes||''].join(' ').toLowerCase();
    return !q || hay.includes(q);
  })
  // ✅ 요구사항: 승인함은 본래 "대기(SUBMITTED)만" 보여야 함
  .filter(r=>{
    const fs = (els.fStatus.value||'').trim();
    if(!fs) return true; // 전체
    if(fs==='SUBMITTED') return r.status==='SUBMITTED';
    return r.status===fs;
  })
  .sort((a,b)=>b.id-a.id);

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
      <td>${r.requester_name||r.requester_id}</td>
      <td>${fmt(r.scheduled_at)}</td>
      <td><span class="badge ${statusClass(r.status)}">${kStatus(r.status)}</span></td>
      <td id="dec-${r.id}"><span class="badge b-submitted">-</span></td>
      <td id="sum-${r.id}" class="muted">읽는 중…</td>
      <td>${(r.purpose||'-')} / ${(r.location||'-')}</td>

      <td class="actions">
        <button class="btn ok"   data-ap="${r.id}" ${r.status!=='SUBMITTED'?'disabled':''}>승인</button>
        <button class="btn warn" data-rj="${r.id}" ${r.status!=='SUBMITTED'?'disabled':''}>거부</button>
        <button class="btn ghost" data-id="${r.id}">상세</button>
      </td>`;
    els.tableBody.appendChild(tr);
    enrichRow(r.id);
  });
  els.tableBody.querySelectorAll('[data-ap]').forEach(b=>b.onclick=()=>actOne(b.dataset.ap,'approve'));
  els.tableBody.querySelectorAll('[data-rj]').forEach(b=>b.onclick=()=>actOne(b.dataset.rj,'reject'));
  
  els.tableBody.querySelectorAll('[data-id]').forEach(b=>b.onclick=(e)=>{ e.preventDefault(); e.stopPropagation(); toggleDetail(parseInt(b.dataset.id,10), b); });
  els.tableBody.querySelectorAll('.rowchk').forEach(c=>c.addEventListener('change', syncBulk));
  // 집행/재오픈 버튼 제거
  els.checkAll.checked=false; syncBulk();
}

async function enrichRow(id){
  try{
    const res=await fetch(`${API_BASE}/api/requests/${id}`); if(!res.ok) return;
    const d=await res.json(); const items=d.items||[], approvals=d.approvals||[];
    const gunNos=items.filter(i=>i.item_type==='FIREARM').map(i=>i.firearm_number).filter(Boolean);
    const gunsPart= gunNos.length?`총기 ${gunNos.slice(0,2).join(', ')}${gunNos.length>2?` 외 ${gunNos.length-2}정`:''}`:'총기 0건';
    const ammoLines=items.filter(i=>i.item_type==='AMMO').length;
    const ammoQty=items.filter(i=>i.item_type==='AMMO').reduce((s,i)=>s+(i.quantity||0),0);
    const ammoPart= ammoLines?`탄약 ${ammoLines}건(수량 ${ammoQty})`:'탄약 0건';
    const sum=document.getElementById(`sum-${id}`); if(sum) sum.textContent=`${gunsPart} · ${ammoPart}`;
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
  td.colSpan = tr.children.length; // 테이블 컬럼 수에 자동 맞춤 (열 변동에도 안전)

  // 먼저 상세 본문을 그린다
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

  // ★ 이제 타임라인을 가져와서 .timeline에 넣는다 (본문 렌더 후!)
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


function selTrs(){ return [...document.querySelectorAll('#t tbody .rowchk')].filter(c=>c.checked).map(c=>c.closest('tr')); }
function syncBulk(){
  const sel=selTrs(); const count=sel.length;
  els.bulkApprove.disabled = count===0 || sel.some(tr=>tr.dataset.status!=='SUBMITTED');
  els.bulkReject .disabled = count===0 || sel.some(tr=>tr.dataset.status!=='SUBMITTED');
  // bulkExecute 제거
  els.checkAll.indeterminate = count>0 && ![...document.querySelectorAll('#t tbody .rowchk')].every(c=>c.checked);
}
els.checkAll.addEventListener('change', ()=>{ const on=els.checkAll.checked; document.querySelectorAll('#t tbody .rowchk').forEach(c=>c.checked=on); syncBulk(); });

async function actOne(id, action){
  const urlMap = {
    approve: `/api/requests/${id}/approve`,
    reject:  `/api/requests/${id}/reject`,
    execute: `/api/requests/${id}/execute`,
    reopen:  `/api/requests/${id}/reopen`,
  };
  const body = { approver_id: auth.id, executed_by: auth.id, actor_id: auth.id };
  const res = await fetch(`${API_BASE}${urlMap[action]}`, {
    method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)
  });
  if(!res.ok){ toast(action+' 실패','error'); return; }
  toast(action+' 완료','success');
  document.querySelectorAll('tr.expand-row').forEach(n=>n.remove()); // 상세 닫기
  await load();
}

document.getElementById('bulkApprove').onclick=async()=>{
  const sel=selTrs(); if(sel.length===0) return;
  if(!confirm(`선택 ${sel.length}건 승인?`)) return;
  let ok=0,fail=0; for(const tr of sel){ const id=tr.dataset.id; const r=await fetch(`${API_BASE}/api/requests/${id}/approve`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({approver_id:auth.id})}); r.ok?ok++:fail++; }
  toast(`승인 완료:${ok} 실패:${fail}`, fail?'error':'success'); load();
};
document.getElementById('bulkReject').onclick=async()=>{
  const sel=selTrs(); if(sel.length===0) return;
  const reason=prompt('거부 사유(선택)')||''; if(!confirm(`선택 ${sel.length}건 거부?`)) return;
  let ok=0,fail=0; for(const tr of sel){ const id=tr.dataset.id; const r=await fetch(`${API_BASE}/api/requests/${id}/reject`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({approver_id:auth.id,reason})}); r.ok?ok++:fail++; }
  toast(`거부 완료:${ok} 실패:${fail}`, fail?'error':'success'); load();
};

// bulkExecute 제거
// document.getElementById('bulkExecute').onclick=async()=>{
//   const sel=selTrs(); if(sel.length===0) return;
//   if(!confirm(`선택 ${sel.length}건 집행?`)) return;
//   let ok=0,fail=0; for(const tr of sel){ const id=tr.dataset.id; const r=await fetch(`${API_BASE}/api/requests/${id}/execute`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({executed_by:auth.id})}); r.ok?ok++:fail++; }
//   toast(`집행 완료:${ok} 실패:${fail}`, fail?'error':'success'); load();
// };

document.getElementById('exportCsv').onclick=()=>{
  const header=['ID','유형','신청자','예정','진행','목적','장소'];
  const lines=[header.join(',')].concat(rows.map(r=>[`#${r.id}`,kType(r.request_type),r.requester_name||r.requester_id,fmt(r.scheduled_at),kStatus(r.status),r.purpose||'',r.location||''].map(csvEscape).join(',')));
  const blob=new Blob([lines.join('\n')],{type:'text/csv;charset=utf-8;'}); const url=URL.createObjectURL(blob); const a=document.createElement('a');
  a.href=url; a.download='approvals.csv'; a.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
};

document.getElementById('reload').onclick=load;
[els.fStatus,els.fType,els.from,els.to].forEach(el=>el.addEventListener('change', load));
els.q.addEventListener('input',()=>{ clearTimeout(window.__qTimer); window.__qTimer=setTimeout(load,200); });

load();
