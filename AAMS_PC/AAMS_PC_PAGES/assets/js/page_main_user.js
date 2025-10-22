import { apiGet } from './api.js';
import { toast } from './toast.js';


const KST_FULL = new Intl.DateTimeFormat('ko-KR',{ timeZone:'Asia/Seoul', dateStyle:'medium', timeStyle:'short' });
const KST_DATE = new Intl.DateTimeFormat('ko-KR',{ timeZone:'Asia/Seoul', dateStyle:'medium' });
import { fmt, fmtDate } from './work_utils.js';
const kType = t => t==='DISPATCH' ? '불출' : (t==='RETURN' ? '불입' : t);
const kStatus = s => ({SUBMITTED:'제출',APPROVED:'승인됨',REJECTED:'거부됨',EXECUTED:'집행됨',CANCELLED:'취소됨'}[s]||s);
const statusClass = s => ({SUBMITTED:'b-submitted',APPROVED:'b-approved',REJECTED:'b-rejected',EXECUTED:'b-executed',CANCELLED:'b-cancelled'}[s]||'b-submitted');
(async function main(){
  try{
    const auth = JSON.parse(sessionStorage.getItem('auth') || '{}');
    const myId = auth?.id;

    // 0) 내 정보 채우기 (세션 정보 우선, 부족하면 단건 조회)
    fillMeCard(auth);
    try {
      if (!auth?.unit || !auth?.position || !auth?.rank) {
        const me = await apiGet(`/api/personnel/${encodeURIComponent(myId)}`);
        fillMeCard({ ...auth, ...me });
      }
    } catch(e) { /* optional */ }

    // 1) 내 요청 가져와서 상태별 집계 + 프리뷰 선정
    const myReqs = await safeGetMyRequests(myId);
    const stats = countByStatus(myReqs);
    setText('nSubmitted', stats.SUBMITTED);
    setText('nApproved' , stats.APPROVED);
    setText('nRejected' , stats.REJECTED);
    setText('nExecuted' , stats.EXECUTED);
    setText('nCancelled', stats.CANCELLED);
    renderReqPreview(myReqs, { limit: 3 }); // ← 대시보드 내 카드형 프리뷰

    // 2) 내 총기 요약
    await loadMyGuns(myId);

     // 신청 퀵: 버튼 이동/프리셋
    wireQuickApply();

  }catch(e){ console.warn(e); /* 대시보드 요약 실패해도 나머지 렌더는 진행 */ }

})();



// --- helpers (대시보드용) ---
function setText(id, v){ const el=document.getElementById(id); if(el) el.textContent=(v ?? '-'); }
function setHtml(id, v){ const el=document.getElementById(id); if(el) el.innerHTML=(v ?? '-'); }

function countByStatus(rows){
  const acc = { SUBMITTED:0, APPROVED:0, REJECTED:0, EXECUTED:0, CANCELLED:0 };
  (rows||[]).forEach(r => { if(acc[r.status]!=null) acc[r.status]++; });
  return acc;
}

async function safeGetMyRequests(myId){
  try{
    return await apiGet(`/api/requests?requester_id=${encodeURIComponent(myId)}`);
  }catch{
    const all = await apiGet('/api/requests');
    return Array.isArray(all) ? all.filter(r=>r.requester_id===myId) : [];
  }
}

function fillMeCard(me){
  setText('meName', me?.rank ? `${me.rank} ${me.name||''}`.trim() : (me?.name||'-'));
  setText('meUnit', me?.unit || '-');
  setText('meRole', me?.position ? ` ${me.position}` : '');
  setText('meUserId', me?.military_id ? `군번: ${me.military_id} · ID: ${me.user_id||'-'}` : ` ${me?.user_id||'-'}`);
}

async function loadMyGuns(myId){
  try{
    // 서버: owner_id 지원 (/api/firearms?owner_id=) :contentReference[oaicite:4]{index=4}
    const guns = await apiGet(`/api/firearms?owner_id=${encodeURIComponent(myId)}&limit=100`);
    const n = Array.isArray(guns) ? guns.length : 0;
    setText('gunsCount', `${n}정`);
    if(!n){
      setText('gunsStatus','보유 총기 없음');
      document.getElementById('gunsList').innerHTML='';
      return;
    }
    // 상태 통계
    const by = guns.reduce((a,g)=>{ a[g.status]= (a[g.status]||0)+1; return a; },{});
    setText('gunsStatus', Object.entries(by).map(([k,v])=>`${k} ${v}`).join(' · '));
    // 상위 3줄 렌더 + reserved 뱃지(서버 reserved 제공) :contentReference[oaicite:5]{index=5}
    const ul = document.getElementById('gunsList');
    ul.innerHTML = '';
    guns.slice(0,3).forEach(g=>{
      const li = document.createElement('li');
      li.style.padding = '2px 0';
      li.innerHTML = `${g.firearm_number} (${g.firearm_type||'-'}) · ${g.status}${g.reserved?` <span class="badge" style="margin-left:6px">대기/예약</span>`:''}`;
      ul.appendChild(li);
    });
    if(n>3){
      const li = document.createElement('li');
      li.className='muted';
      li.style.padding='2px 0';
      li.textContent = `그 외 ${n-3}정`;
      ul.appendChild(li);
    }
  }catch(e){
    setText('gunsCount','-'); setText('gunsStatus','불러오기 실패');
    document.getElementById('gunsList').innerHTML='';
  }
}



async function quickSummary(id){
  const d = await apiGet(`/api/requests/${id}`);
  const items = d.items || [];
  const guns = items.filter(i=>i.item_type==='FIREARM').map(i=>i.firearm_number).filter(Boolean);
  const ammoLines = items.filter(i=>i.item_type==='AMMO').length;
  const ammoQty   = items.filter(i=>i.item_type==='AMMO').reduce((s,i)=>s+(i.quantity||0),0);
  const gPart = guns.length ? `총기 ${guns.slice(0,2).join(', ')}${guns.length>2?` 외 ${guns.length-2}정`:''}` : '총기 0건';
  const aPart = ammoLines ? `탄약 ${ammoLines}건(수량 ${ammoQty})` : '탄약 0건';
  return `${gPart} · ${aPart}`;
}


// 신청 프리뷰(최신 1~3건) 카드 렌더 — 최신순으로만 자르기
async function renderReqPreview(myReqs, {limit=3}={}){
  const host = document.getElementById('reqPreviewList'); if(!host) return;
  host.innerHTML = '';

  if(!Array.isArray(myReqs) || myReqs.length===0){
    host.innerHTML = `<li class="empty">신청 내역이 없습니다</li>`;
    return;
  }

  // 화면폭 좁을땐 자동 1건
  const isNarrow = window.matchMedia('(max-width: 860px)').matches;
  if (isNarrow) limit = Math.min(limit, 1);

  // 🔑 최신순 기준: updated_at > created_at > scheduled_at
  const ts = r => new Date(r.updated_at || r.created_at || r.scheduled_at || 0).getTime();
  const pick = [...myReqs].sort((a,b)=> ts(b) - ts(a)).slice(0, limit);

  for (const r of pick){
    let sum='-';
    try{ sum = await quickSummary(r.id); }catch{}
    const li = document.createElement('li');
    li.className = 'req-card';
    const icon = (r.request_type==='DISPATCH') ? '📤' : '📥';

    // 표시 날짜는: 예정(scheduled_at) 있으면 그걸, 아니면 최신 기준이 된 updated_at/created_at 중 하나
    const shownTime = r.scheduled_at || r.updated_at || r.created_at;

    li.innerHTML = `
      <div class="req-icon">${icon}</div>
      <div class="req-main">
        <div class="req-top">
          <span class="big">#${r.id}</span>
          <span class="badge b-type">${kType(r.request_type)}</span>
          <span class="badge ${statusClass(r.status)}">${kStatus(r.status)}</span>
        </div>
        <div class="req-mid">${fmtDate(shownTime)}</div>
        <div class="req-sub" title="${sum}">${sum}</div>
      </div>
      <div class="req-link"><a class="muted" href="new_workcenter_my_history.html">상세</a></div>
    `;
    host.appendChild(li);
  }
}



function wireQuickApply(){
  const go = (type, extra={})=>{
    // 새 신청 페이지로 이동: 유형/목적 프리셋 + 내 총기 자동 추가 지시
    // autofill=opposite_firearm → 현재 상태의 '반대 상태' 총기를 자동 추가
    //   DISPATCH(불출)일 때  현 상태 '불입' 총기 자동 추가
    //   RETURN(불입)일 때   현 상태 '불출' 총기 자동 추가
    const q = new URLSearchParams({ type, ...extra, autofill:'opposite_firearm', max:'3' }).toString();
    location.href = `new_workcenter_apply.html?${q}`;
  };
  const d = document.getElementById('qaDispatch');
  const r = document.getElementById('qaReturn');
  const u = document.getElementById('qaDuty');
  const ur = document.getElementById('qaDutyReturn');
  if (d) d.onclick = ()=>go('DISPATCH');                    // 불출 신청
  if (r) r.onclick = ()=>go('RETURN');                      // 불입 신청
  if (u) u.onclick = ()=>go('DISPATCH', { purpose:'근무' }); // 근무 + 불출
  if (ur) ur.onclick = ()=>go('RETURN',   { purpose:'근무' }); // 근무 + 불입

}