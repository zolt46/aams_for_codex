// AAMS - Admin Dashboard Summary (KPI cards + chips)
// - .dashboard-summary 내부를 KPI 카드/칩 UI로 재구성
// - health/db 우선, 실패시 목록 길이로 폴백
// - 대기 건은 서버 상태와 일치하도록 SUBMITTED로 집계

import { apiGet } from './api.js';
import { toast } from './toast.js';
import { onLockdownChange, getLockdownState } from './lockdown.js';

const CSS_ID = 'dash-summary-style-v2';

function injectStyle(){
  if (document.getElementById(CSS_ID)) return;
  const style = document.createElement('style');
  style.id = CSS_ID;
  style.textContent = `
  .dash-wrap{ display:grid; grid-template-columns:repeat(12,minmax(0,1fr)); gap:10px; justify-items:stretch; }
  .kpi-card{ grid-column:span 4/span 4; background:var(--sidebar-bg); border:1px solid var(--border-color); border-radius:12px; padding:12px; display:flex; align-items:center; justify-content:space-between; }
  .kpi-card .label{ font-size:.9rem; opacity:.85; display:flex; align-items:center; gap:.4rem }
  .kpi-card .value{ font-size:1.8rem; font-weight:800 }
  .kpi-card .sub{ font-size:.8rem; opacity:.75; margin-top:2px }
  .kpi-card .icon{ font-size:1.2rem }
  .chips{ grid-column:1/-1; display:flex; flex-wrap:wrap; gap:8px; justify-content:center; }
  .chip{ display:inline-flex; align-items:center; gap:.4rem; padding:6px 10px; border-radius:999px; background:#1b231e; border:1px solid var(--border-color); font-size:.9rem }
  .chip.ok{ background:#18261b; color:#9be29f; }
  .chip.warn{ background:#2b2516; color:#ffd78a; }
  .chip.err{ background:#2b1b1b; color:#ff9b9b; }
  @media (max-width: 900px){ .kpi-card{ grid-column:span 12/span 12; } }
  `;
  document.head.appendChild(style);
}

function fmt(n){ try { return Number(n).toLocaleString('ko-KR'); } catch { return n; } }
function setText(id, v){ const el=document.getElementById(id); if(el) el.textContent=v; }

function renderSummary(container, data){
  injectStyle();
  const {
    person=0, firearm=0, ammo=0,
    admins=0, inDepot=0, deployed=0, maint=0,
    totalAmmoQty=0, lowAmmo=0, pending=0
  } = data || {};

  container.innerHTML = `
    <div class="dash-wrap">
      <div class="kpi-card">
        <div>
          <div class="label"><span class="icon">👤</span>인원</div>
          <div class="sub">관리자 ${fmt(admins)}명</div>
        </div>
        <div class="value">${fmt(person)}</div>
      </div>

      <div class="kpi-card">
        <div>
          <div class="label"><span class="icon">🔫</span>총기</div>
          <div class="sub">불입 ${fmt(inDepot)} · 불출 ${fmt(deployed)} · 정비 ${fmt(maint)}</div>
        </div>
        <div class="value">${fmt(firearm)}</div>
      </div>

      <div class="kpi-card">
        <div>
          <div class="label"><span class="icon">🎯</span>탄약 품목</div>
          <div class="sub">총 재고량 ${fmt(totalAmmoQty)}</div>
        </div>
        <div class="value">${fmt(ammo)}</div>
      </div>

      <div class="chips">
        <span class="chip ${pending>0?'warn':'ok'}">⏳ 대기 승인 ${fmt(pending)}</span>
        <span class="chip ${deployed>0?'warn':'ok'}">🚚 불출 ${fmt(deployed)}</span>
        <span class="chip ${maint>0?'warn':'ok'}">🛠 정비 ${fmt(maint)}</span>
        <span class="chip ${lowAmmo>0?'warn':'ok'}">⚠️ 저수량(≤20) ${fmt(lowAmmo)}</span>
      </div>
    </div>
  `;
}

(async function main(){
  setupLockdownOverlay();
  try{
    const wrap = document.querySelector('.dashboard-summary');
    if(!wrap) return;

    // 데이터 병렬 수집
    const [health, personnel, firearms, ammo, submitted] = await Promise.all([
      apiGet('/health/db').catch(()=>null),
      apiGet('/api/personnel').catch(()=>[]),
      apiGet('/api/firearms').catch(()=>[]),
      apiGet('/api/ammunition').catch(()=>[]),
      apiGet('/api/requests?status=SUBMITTED').catch(()=>[]), // 대기 = SUBMITTED
    ]);

    // 기존 한줄 숫자(있다면)도 갱신해 호환 유지
    const pTotal = Array.isArray(personnel)? personnel.length : 0;
    const fTotal = health?.firearms_total ?? (Array.isArray(firearms)? firearms.length : 0);
    const aTotal = health?.ammo_total ?? (Array.isArray(ammo)? ammo.length : 0);
    setText('dash-person', pTotal);
    setText('dash-firearm', fTotal);
    setText('dash-ammo', aTotal);

    // 추가 지표 계산
    let admins=0, inDepot=0, deployed=0, maint=0, totalAmmoQty=0, lowAmmo=0;
    if(Array.isArray(personnel)){
      admins = personnel.filter(p=>p.is_admin).length;
    }
    if(Array.isArray(firearms)){
      const byStatus = firearms.reduce((m,r)=>{ m[r.status]=(m[r.status]||0)+1; return m; },{});
      inDepot = byStatus['불입']||0;
      deployed = byStatus['불출']||0;
      maint = byStatus['정비중']||0;
    }
    if(Array.isArray(ammo)){
      totalAmmoQty = ammo.reduce((s,r)=> s + (Number(r.quantity)||0), 0);
      lowAmmo = ammo.filter(r=> (Number(r.quantity)||0) <= 20).length;
    }
    const pending = Array.isArray(submitted)? submitted.length : 0;

    // 카드/칩 UI 렌더
    renderSummary(wrap, {
      person: pTotal, firearm: fTotal, ammo: aTotal,
      admins, inDepot, deployed, maint, totalAmmoQty, lowAmmo, pending
    });

  }catch(e){
    console.error(e);
    toast('대시보드 요약 로딩 실패','error');
  }
})();

function setupLockdownOverlay(){
  const overlay = document.getElementById('lockdown-overlay');
  if (!overlay) return;
  const issuedAtEl = document.getElementById('lockdownIssuedAt');
  const issuedByEl = document.getElementById('lockdownIssuedBy');
  const reasonEl = document.getElementById('lockdownReason');

  const render = (state) => {
    if (!state?.active) {
      overlay.hidden = true;
      return;
    }
    overlay.hidden = false;
    if (issuedAtEl) {
      issuedAtEl.textContent = state.triggeredAt
        ? new Date(state.triggeredAt).toLocaleString('ko-KR')
        : '-';
    }
    if (issuedByEl) {
      const actor = state.triggeredBy;
      if (actor?.name) {
        const rank = actor.rank ? `${actor.rank} ` : '';
        issuedByEl.textContent = `${rank}${actor.name}`.trim();
      } else {
        issuedByEl.textContent = '-';
      }
    }
    if (reasonEl) {
      const message = state.message || null;
      const reason = state.reason || null;
      const label = message ? message : (reason ? `사유: ${reason}` : '사유: 긴급 대응');
      reasonEl.textContent = label;
    }
  };

  onLockdownChange(render);
  render(getLockdownState());
}