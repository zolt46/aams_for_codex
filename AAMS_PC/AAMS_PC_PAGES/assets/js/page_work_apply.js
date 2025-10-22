// AAMS - Work Apply (user request page) - robust version
// - 근무/경계 + 불출(DISPATCH) 시 5.56mm 공포탄 자동 '발행' 미리보기
// - 근무/경계 + 불입(RETURN)  시 5.56mm 공포탄 자동 '반납' 미리보기
// - 일반 사용자는 AMMO 직접 신청 제한(관리자 전용)
// - 문법 호환성 문제 유발하는 구문(옵셔널 체이닝 좌변 할당 등) 배제

import { API_BASE } from './config.js';
import { localDatetimeToISOZ } from './work_utils.js';
import { requireAuth } from './work_utils.js';
import { toast } from './toast.js';

// ---- DOM ----
const auth = requireAuth();

const reqType     = document.getElementById('request_type');
const scheduledAt = document.getElementById('scheduled_at');
const purpose     = document.getElementById('purpose');
const locationEl  = document.getElementById('location');
const notesEl     = document.getElementById('notes');

const itemType   = document.getElementById('item_type');   // 'FIREARM' | 'AMMO'
const itemSearch = document.getElementById('item_search');
const taList     = document.getElementById('taList');      // typeahead dropdown
const ammoQty    = document.getElementById('ammo_qty');

const addItemBtn = document.getElementById('addItemBtn');
const submitBtn  = document.getElementById('submitBtn');

// ---- State ----
const state = { items: [] };
let picked = null;       // 최근 검색에서 사용자가 선택한 레코드
let autoAmmoFlag = false; // 자동 추가 중복 방지

const purposeEl = document.querySelector('#purpose, [name="purpose"], .purpose-input');
if (purposeEl) {
  purposeEl.addEventListener('input', () => {autoPreviewDisabled = false;  maybeAttachAutoAmmoPreview(state); });
  purposeEl.addEventListener('change', () => { autoPreviewDisabled = false; maybeAttachAutoAmmoPreview(state); });
}

let autoPreviewDisabled = false; // 사용자가 프리뷰를 지우면, 상태/목적 바뀔 때까지 재생성 금지

// ---- Helpers ----
function setDisabled(el, v) { if (el) el.disabled = !!v; }
function setPlaceholder(el, s){ if (el) el.placeholder = s; }
function getVal(el){ return el ? el.value : ''; }
function setVal(el, v){ if (el) el.value = v; }
function show(el, on){ if (el) el.style.display = on ? 'block' : 'none'; }
function fmtNum(n){ var x = Number(n); return Number.isFinite(x) ? x.toLocaleString('ko-KR') : String(n); }


// item 테이블 렌더
function renderItems(){
  const tb = document.querySelector('#itemsTable tbody'); if(!tb) return;
  tb.innerHTML = '';
  state.items.forEach((it, idx) => {
    const tr = document.createElement('tr');

    const tdType = document.createElement('td');
    tdType.className = 'badge';
    tdType.textContent = (it.type === 'FIREARM') ? '총기' : '탄약';

    const tdLabel = document.createElement('td');
    tdLabel.textContent = it.ident || '-';

    const tdQty = document.createElement('td');
    tdQty.textContent = (it.type === 'AMMO') ? String(it.qty || 0) : '-';

    const tdAct = document.createElement('td');
    tdAct.className = 'actions';

    const isLockedAutoAmmo = false;
    // 또는 🔒을 살릴 거면 ↓
    // const isLockedAutoAmmo = (!auth.is_admin) && it.type==='AMMO' && (it._auto || it._auto_return);
    if (isLockedAutoAmmo) {
      const lock = document.createElement('span');
      lock.textContent = '🔒';
      lock.title = '자동 지정 탄약은 삭제할 수 없습니다';
      tdAct.appendChild(lock);
    } else {
      const btn = document.createElement('button');
      btn.textContent = '삭제';
      btn.dataset.i = String(idx);
      btn.onclick = () => {
        const removed = state.items[idx];
        state.items.splice(idx, 1);

        // ✅ 프리뷰를 사용자가 지웠다면, 즉시 재생성 금지
        if (removed && removed._preview) {
          autoPreviewDisabled = true;
        }

        renderItems();

        // ✅ 총기가 하나도 안 남았으면 프리뷰 싹 정리 + 차단 플래그 해제
        const anyFirearm = state.items.some(it => it.type === 'FIREARM');
        if (!anyFirearm) {
          for (let i = state.items.length - 1; i >= 0; i--){
            if (state.items[i]._preview) state.items.splice(i,1);
          }
          autoPreviewDisabled = false;
          renderItems();
          return;
        }

        // ✅ 총기는 남아 있으면 프리뷰 재평가 (차단 플래그가 true면 재생성 안 함)

        maybeAttachAutoAmmoPreview(state);
      };

      tdAct.appendChild(btn);
    }

    tr.appendChild(tdType);
    tr.appendChild(tdLabel);
    tr.appendChild(tdQty);
    tr.appendChild(tdAct);
    tb.appendChild(tr);
  });
}

// --- 퀵 가드 프리셋 적용 & 내 총기 자동 추가 ---
function applyPresetFromQuery(){
  const qs = new URLSearchParams(location.search);

  // 1) 유형/목적 프리셋
  const t = (qs.get('type')||'').toUpperCase();
  if (t === 'DISPATCH' || t === 'RETURN'){
    if (reqType) {
      reqType.value = t;
      reqType.dispatchEvent(new Event('change'));
    }
  }
  const p = qs.get('purpose');
  if (p && purpose) {
    purpose.value = p;
    // 목적 바꾸면 자동탄약 프리뷰 허용 + 재평가
    autoPreviewDisabled = false;
    purpose.dispatchEvent(new Event('change'));
  }

  // 2) 내 총기 자동 추가: opposite_firearm
  const af = qs.get('autofill');
  if (af === 'opposite_firearm') {
    const targetStatus = (reqType && reqType.value === 'DISPATCH') ? '불입' : '불출';
    const max = Math.max(1, Math.min(parseInt(qs.get('max')||'3',10) || 3, 10));
    autoAddMyFirearms(targetStatus, max);
  }
}

async function autoAddMyFirearms(targetStatus, max){
  try{
    const url = `${API_BASE}/api/firearms?owner_id=${encodeURIComponent(auth.id)}&status=${encodeURIComponent(targetStatus)}&limit=${max}`;
    const res = await fetch(url);
    const guns = await res.json();

    if (!Array.isArray(guns) || guns.length === 0) {
      toast(`자동 추가할 ${targetStatus} 상태 총기가 없습니다`, 'info');
      return;
    }

    let added = 0;
    for (const g of guns) {
      if (added >= max) break;
      if (g.reserved) continue; // 대기/예약 제외
      if (state.items.some(it => it.type==='FIREARM' && it.id===g.id)) continue; // 중복 방지
      state.items.push({
        type: 'FIREARM',
        id: g.id,
        ident: `${g.firearm_number || g.id} (${g.firearm_type || ''})`
      });
      added++;
    }
    if (added > 0) {
      renderItems();
      // 근무/경계 프리셋이면 공포탄 프리뷰 바로 반영
      autoPreviewDisabled = false;
      maybeAttachAutoAmmoPreview(state);
    }
  } catch (e) {
    toast('내 총기 자동 추가 실패', 'error');
  }
}



// itemType 변경 시 UI 상태 반영
function syncQtyInput(){
  const isAmmo = (getVal(itemType) === 'AMMO');
  setDisabled(ammoQty, !isAmmo);
  setPlaceholder(ammoQty, isAmmo ? '탄약 수량' : '탄약 선택 시에만 입력');
}
syncQtyInput();

// 일반 사용자는 탄약 직접 신청 제한
if (!auth.is_admin) {
  if (itemType) {
    itemType.value = 'FIREARM';
    const opts = itemType.options || [];
    for (let i = 0; i < opts.length; i++){
      if (opts[i].value === 'AMMO') {
        opts[i].disabled = true;
        opts[i].textContent = '탄약 (관리자 전용)';
      }
    }
  }
  setDisabled(ammoQty, true);
  setPlaceholder(ammoQty, '관리자 전용');
}

// 이벤트 바인딩
if (itemType) {
  itemType.addEventListener('change', function(){
    setVal(itemSearch, '');
    picked = null;
    show(taList, false);
    syncQtyInput();
  });
}
if (purpose) {
  purpose.addEventListener('input', () => {
    autoPreviewDisabled = false;        // ✅ 목적 바뀌면 프리뷰 허용
    maybeAttachAutoAmmoPreview(state);
  });
  purpose.addEventListener('change', () => {
    autoPreviewDisabled = false;
    maybeAttachAutoAmmoPreview(state);
  });
}
if (reqType) {
  reqType.addEventListener('change', () => {
    autoPreviewDisabled = false;        // ✅ 유형 바뀌면 프리뷰 허용
    picked = null; searchNow();
  });
}


// 검색어 입력 → Typeahead
if (itemSearch) {
  itemSearch.addEventListener('input', function(){
    const q = getVal(itemSearch).trim();
    if (!q) {
      picked = null;
      show(taList, false);
      return;
    }
    searchNow();
  });
}

// 안전한 하이라이트
function escapeRegExp(s){
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
function hi(text, q){
  var t = String(text || '');
  var re = new RegExp('(' + escapeRegExp(q) + ')', 'ig');
  return t.replace(re, '<mark>$1</mark>');
}

// 검색 실행
async function searchNow(){
  if (!itemSearch || !itemType || !taList) return;
  const q = getVal(itemSearch).trim();
  if (!q) {
    show(taList, false);
    picked = null;
    return;
  }
  show(taList, true);
  taList.innerHTML = '<div class="typeahead-empty">검색 중…</div>';

  try {
    const type = getVal(itemType);
    var url;
    if (type === 'FIREARM') {
      url = API_BASE + '/api/firearms?q=' + encodeURIComponent(q) + '&limit=12&requester_id=' + encodeURIComponent(auth.id);
      // 불출이면 현 상태 '불입'인 총기만, 불입이면 현 상태 '불출'인 총기만
      var statusFilter = (getVal(reqType) === 'DISPATCH') ? '불입' : '불출';
      url += '&status=' + encodeURIComponent(statusFilter);
    } else {
      url = API_BASE + '/api/ammunition?q=' + encodeURIComponent(q) + '&limit=12';
    }

    const res = await fetch(url);
    const rows = await res.json();

    if (!Array.isArray(rows) || rows.length === 0) {
      taList.innerHTML = '<div class="typeahead-empty">결과 없음</div>';
      return;
    }

    taList.innerHTML = '';
    for (let i = 0; i < rows.length; i++){
      const r = rows[i];
      const el = document.createElement('div');
      el.className = 'typeahead-item';

      // 기존 FIREARM 분기 내 el.innerHTML / el.onclick 교체
      if (getVal(itemType) === 'FIREARM') {
        const num  = r.firearm_number || '';
        const kind = r.firearm_type || '';
        const isReserved = !!r.reserved; // 서버가 이제 리스트에도 내려줌
        el.innerHTML = '<strong>' + hi(num, q) + '</strong> <span>' + kind + '</span>'
                    + (isReserved ? ' <span class="badge b-reserved">대기/예약</span>' : '');
        el.onclick = function(){
          if (isReserved) { toast('대기/예약 중인 총기는 집행 완료 전까지 신청할 수 없습니다.','error'); return; }
          picked = { type: 'FIREARM', id: r.id, label: (num + ' (' + kind + ')'), _reserved:false };
          setVal(itemSearch, num);
          show(taList, false);
          // 총기 아이템을 선택 완료한 직후
          autoPreviewDisabled = false; 
          maybeAttachAutoAmmoPreview(state);   // ← 프리뷰 붙이기/제거
        };
      }
      else {
        const name = r.ammo_name || '';
        const cat  = r.ammo_category || '';
        // available 필드는 서버 /api/ammunition 에서 제공
        const avail = (typeof r.available === 'number') ? r.available : (r.quantity || 0);
        el.innerHTML = '<strong>' + hi(name, q) + '</strong> <span>' + cat + '</span>';
        el.onclick = function(){
          picked = { type: 'AMMO', id: r.id, label: name, available: avail };
          setVal(itemSearch, name);
          show(taList, false);
           
          
        };
      }

      taList.appendChild(el);
    }
  } catch (e) {
    taList.innerHTML = '<div class="typeahead-empty">검색 실패</div>';
  }
}

// 항목 추가
if (addItemBtn) {
  addItemBtn.onclick = async function(){
    const type = getVal(itemType);
    if (type === 'AMMO' && !auth.is_admin) {
      alert('일반 사용자는 탄약을 신청할 수 없습니다');
      return;
    }
    if (!picked || picked.type !== type) {
      alert('검색 결과에서 항목을 선택하세요');
      return;
    }

    let qty = 1;
    if (type === 'AMMO') {
      qty = parseInt(getVal(ammoQty) || '0', 10);
      if (!Number.isInteger(qty) || qty <= 0) {
        alert('탄약 수량을 입력');
        return;
      }
      // 불출 신청 시 가용재고 초과 제한
      if (getVal(reqType) === 'DISPATCH' && typeof picked.available === 'number' && qty > picked.available) {
        alert('재고 부족 (가용: ' + picked.available + ')');
        return;
      }
    }

    // 중복 방지
    for (let i = 0; i < state.items.length; i++){
      const it = state.items[i];
      if (it.type === type && it.id === picked.id) {
        alert('이미 추가된 항목입니다');
        return;
      }
    }

    if (type === 'FIREARM' && picked && picked._reserved) {
      toast('대기/예약 중인 총기는 집행 완료 전까지 신청 불가','error'); return;
    }

    state.items.push({
      type: type,
      id: picked.id,
      ident: picked.label,
      qty: (type === 'AMMO' ? qty : undefined)
    });

    picked = null;
    setVal(itemSearch, '');
    setVal(ammoQty, '');
    renderItems(); 

    // 총기 추가 이후 자동 탄약 미리보기
    if (type === 'FIREARM') {
      autoPreviewDisabled = false; maybeAttachAutoAmmoPreview(state);
    }
  };
}

// 자동 탄약 미리보기 (프론트 표시)
// - 서버 자동추가 보완용(사용자에게도 즉시 보이도록)
// async function ensureAutoAmmoPreview(){
//   const t = getVal(reqType);
//   const isDispatch = (t === 'DISPATCH');
//   const isReturn   = (t === 'RETURN' || t === 'INCOMING');
//   const pv = (purpose && typeof purpose.value === 'string') ? purpose.value.trim() : '';
//   const wantAuto   = (isDispatch || isReturn) && /근무|경계/.test(pv);

//   // 사용자(비관리자)는 총기가 선택된 경우에만 자동 프리뷰/자동삽입 허용
//   const isUser     = !auth.is_admin;
//   const hasFirearm = state.items.some(it => it.type === 'FIREARM');
//   if (isUser && !hasFirearm) return;

//   // 이미 실제 AMMO가 있거나, 이미 자동추가 플래그가 세워졌으면 skip
//   const hasRealAmmo = state.items.some(it => it.type==='AMMO' && !it._preview && !it._auto && !it._auto_return);
//   if (!wantAuto || hasRealAmmo || autoAmmoFlag) return;

//   try {
//     const url = API_BASE + '/api/ammunition?q=' + encodeURIComponent('5.56mm') + '&limit=20';
//     const res = await fetch(url);
//     const rows = await res.json();
//     const cand = Array.isArray(rows) ? rows.filter(r => r.ammo_category === '공포탄') : [];
//     if (!cand.length) return;

//     // 가용 재고 많은 순
//     cand.sort((a,b)=>{
//       const avA = (typeof a.available === 'number') ? a.available : (a.quantity || 0);
//       const avB = (typeof b.available === 'number') ? b.available : (b.quantity || 0);
//       return avB - avA;
//     });

//     const pick  = cand[0];
//     const avail = (typeof pick.available === 'number') ? pick.available : (pick.quantity || 0);

//     if (isDispatch) {
//       const qty = Math.min(30, avail);
//       if (qty <= 0) return; // 재고 0이면 스킵
//       state.items.push({ type:'AMMO', id:pick.id, ident:(pick.ammo_name||'5.56mm'), qty, _auto:true });
//     } else {
//       // 반납 기본 수량
//       state.items.push({ type:'AMMO', id:pick.id, ident:(pick.ammo_name||'5.56mm (자동반납)'), qty:30, _auto_return:true });
//     }

//     autoAmmoFlag = true;
//     renderItems();
//   } catch (e) {
//     // 네트워크 실패 시 화면 프리뷰에만 의존
//   }
// }


function removeAutoAmmoFromState(){
  let removed = false;
  for (let i = state.items.length - 1; i >= 0; i--){
    const it = state.items[i];
    // if (it._auto || it._auto_return) { state.items.splice(i,1); removed = true; }
  }
  if (removed) { autoAmmoFlag = false; renderItems(); }
}

// async function reconcileAutoAmmo(){
//   // 1) 기존 자동탄약(서버삽입 의도) 제거
//   removeAutoAmmoFromState();

//   // 2) 조건 판단
//   const t = getVal(reqType);
//   const isDispatch = (t === 'DISPATCH');
//   const isReturn   = (t === 'RETURN' || t === 'INCOMING');
//   const isDuty     = /(근무|경계)/.test((purpose && purpose.value) ? purpose.value : '');
//   if (!(isDuty && (isDispatch || isReturn))) {
//     // 조건이 깨지면 프리뷰도 제거
//     for (let i = state.items.length - 1; i >= 0; i--){
//       if (state.items[i]._preview) state.items.splice(i,1);
//     }
//     renderItems();
//     return;
//   }

//   // 3) 사용자면 총기 선택 후에만 자동 미리보기/자동삽입 시도
//   const isUser     = !auth.is_admin;
//   const hasFirearm = state.items.some(it => it.type === 'FIREARM');
//   if (isUser && !hasFirearm) { maybeAttachAutoAmmoPreview(state); return; }

//   // 4) 자동 삽입(실탄/반납 라인) + 프리뷰는 maybe.. 가 보완
//   maybeAttachAutoAmmoPreview(state);
// }


function maybeAttachAutoAmmoPreview(state){
  // 1) 목적/조건
  const pv = (purpose && typeof purpose.value === 'string') ? purpose.value.trim() : '';
  const isDuty = /(근무|경계)/.test(pv);

  // 2) 현재 상태
  const hasFirearm  = state.items.some(it => it.type === 'FIREARM');
  const hasRealAmmo = state.items.some(it => it.type === 'AMMO' && !it._preview); // 🔒/실제 라인 포함 금지(이제 안 씀)
  const hasPreview  = state.items.some(it => it._preview === true);

  // 3) 프리뷰 추가/삭제
  if (hasFirearm && isDuty && !hasRealAmmo && !autoPreviewDisabled) {
    if (!hasPreview) {
      state.items.push({ type:'AMMO', ident:'공포탄 5.56mm', qty:30, _preview:true });
      renderItems();
      // 안내 토스트는 과도하게 뜨지 않게 필요 시 한 번만
    }
  } else {
    if (hasPreview) {
      for (let i = state.items.length - 1; i >= 0; i--){
        if (state.items[i]._preview) state.items.splice(i,1);
      }
      renderItems();
    }
  }
}




if (submitBtn) {
  submitBtn.onclick = async function(){
    const body = {
      requester_id: auth.id,
      request_type: reqType.value,
      purpose:      purpose.value,
      location:     locationEl.value,
      scheduled_at: localDatetimeToISOZ(scheduledAt.value),
      notes:        notesEl.value,
      items: []
    };



    // 필수값 체크
    const miss=[];
    if(!body.request_type) miss.push('신청유형');
    if(!body.scheduled_at) miss.push('예정일시');
    if(!body.purpose)      miss.push('목적');
    if(!body.location)     miss.push('장소');
    if(!Array.isArray(state.items) || state.items.length===0) miss.push('항목');
    if(miss.length){ toast('입력 누락: ' + miss.join(', '), 'error'); return; }

    const isUser    = !auth.is_admin;
    const isDuty    = /근무|경계/.test(String(body.purpose||''));
    const isDispatch= (body.request_type==='DISPATCH');
    const isReturn  = (body.request_type==='RETURN' || body.request_type==='INCOMING');

    // 비관리자: 근무/경계면 총기 필수(탄약만 금지)
    if (isUser && isDuty && (isDispatch || isReturn)) {
      const hasFirearm = state.items.some(it=>it.type==='FIREARM');
      if (!hasFirearm) {
        toast('근무/경계 신청은 총기를 함께 선택해야 합니다(탄약만 신청 불가).','error');
        return;
      }
    }

    // 아이템 변환
    for (const it of state.items) {
      if (it.type === 'FIREARM') {
        body.items.push({ type:'FIREARM', firearm_id: it.id, ident: it.ident });
      } else if (it.type === 'AMMO') {
        if (isUser) {
          // ★ 비관리자는 AMMO를 절대 보내지 않음(DISP/RETURN 공통)
          // (근무 + DISPATCH/RETURN에서 서버가 자동첨부하므로 여기선 제외)
          continue;
        } else {
          body.items.push({ type:'AMMO', ammo_id: it.id, qty: it.qty, ident: it.ident });
        }
      }
    }

    if (body.items.length===0) {
      toast('신청 항목이 비어 있습니다. 총기를 추가해주세요.','error');
      return;
    }

    try{
      const res = await fetch(`${API_BASE}/api/requests`, {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(body)
      });
      if(!res.ok){
        let t={}; try{ t=await res.json(); }catch{}
        toast(`신청 실패: ${t.error||t.detail||res.status}`,'error'); return;
      }
      toast('신청 완료','success');
      state.items=[]; autoAmmoFlag=false; renderItems(); autoPreviewDisabled = false;  maybeAttachAutoAmmoPreview(state);
    }catch{ toast('신청 실패: 네트워크 오류','error'); }
  };
  applyPresetFromQuery();
}

