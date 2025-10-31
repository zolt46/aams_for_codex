import { apiGet, apiPost } from './api.js';
import { toast } from './toast.js';
import { currentUser } from './auth.js';

const LISTENERS = new Set();
const POLL_INTERVAL_MS = 8000;
let state = {
  active: false,
  triggeredAt: null,
  triggeredBy: null,
  reason: null,
  message: null,
  clearedAt: null,
  clearedBy: null
};
let pollTimer = null;
let buttonEl = null;
let isPolling = false;

function cloneState() {
  return { ...state };
}

function emit() {
  const snapshot = cloneState();
  LISTENERS.forEach((fn) => {
    try { fn(snapshot); }
    catch (err) { console.warn('[AAMS][lockdown] listener error', err); }
  });
  syncBodyGuard(snapshot.active);
}

function setState(next = {}) {
  const normalized = {
    active: !!next.active,
    triggeredAt: next.triggeredAt || next.triggered_at || null,
    triggeredBy: normalizeActor(next.triggeredBy || next.triggered_by),
    reason: next.reason || null,
    message: next.message || null,
    clearedAt: next.clearedAt || next.cleared_at || null,
    clearedBy: normalizeActor(next.clearedBy || next.cleared_by)
  };
  const changed = JSON.stringify(normalized) !== JSON.stringify(state);
  state = normalized;
  if (buttonEl) updateButton();
  if (changed) emit();
  return state;
}

function normalizeActor(raw) {
  if (!raw) return null;
  if (typeof raw === 'string') {
    return { name: raw };
  }
  if (typeof raw === 'object') {
    const { id, name, rank, unit } = raw;
    return {
      id: id ?? raw.person_id ?? null,
      name: name ?? raw.name ?? null,
      rank: rank ?? raw.rank ?? null,
      unit: unit ?? raw.unit ?? null
    };
  }
  return null;
}

function syncBodyGuard(active) {
  if (typeof window === 'undefined') return;
  if (active) {
    window.onbeforeunload = () => '긴급 개방 프로토콜 진행 중에는 이탈할 수 없습니다.';
    document.body.classList.add('lockdown-active');
  } else {
    if (window.onbeforeunload) {
      window.onbeforeunload = null;
    }
    document.body.classList.remove('lockdown-active');
  }
}

async function fetchState() {
  try {
    const result = await apiGet('/api/system/lockdown');
    setState(result || {});
  } catch (err) {
    console.warn('[AAMS][lockdown] 상태 조회 실패', err);
  }
}

function ensurePolling() {
  if (pollTimer || isPolling) return;
  pollTimer = setInterval(() => {
    if (isPolling) return;
    isPolling = true;
    fetchState().finally(() => { isPolling = false; });
  }, POLL_INTERVAL_MS);
}

function updateButton() {
  if (!buttonEl) return;
  if (state.active) {
    buttonEl.textContent = '긴급 프로토콜 해제';
    buttonEl.dataset.state = 'active';
  } else {
    buttonEl.textContent = '긴급 개방 프로토콜';
    buttonEl.dataset.state = 'idle';
  }
}

function confirmTrigger() {
  const info = [
    '긴급 개방 프로토콜을 시행하면:',
    '• 모든 총기를 불출 상태로 전환합니다.',
    '• UI 단말이 긴급 경보 화면으로 전환됩니다.',
    '• 부저가 울리며 장비 접근이 제한됩니다.',
    '',
    '즉시 시행하시겠습니까?'
  ].join('\n');
  return window.confirm(info);
}

function confirmRelease() {
  return window.confirm('긴급 개방 프로토콜을 해제하시겠습니까?\n장비 상태를 확인한 후 진행하세요.');
}

async function triggerLockdown() {
  const me = currentUser();
  const actor = me?.id ? { id: me.id, name: me.name, rank: me.rank, unit: me.unit } : null;
  const body = { actor };
  try {
    await apiPost('/api/system/lockdown/trigger', body);
    toast('긴급 개방 프로토콜이 시행되었습니다.', 'warning');
    await fetchState();
  } catch (err) {
    toast(`긴급 개방 시행 실패: ${err?.message || err}`, 'error');
    throw err;
  }
}

async function releaseLockdown() {
  const me = currentUser();
  const actor = me?.id ? { id: me.id, name: me.name, rank: me.rank, unit: me.unit } : null;
  const body = { actor };
  try {
    await apiPost('/api/system/lockdown/release', body);
    toast('긴급 개방 프로토콜이 해제되었습니다.', 'success');
    await fetchState();
  } catch (err) {
    toast(`긴급 개방 해제 실패: ${err?.message || err}`, 'error');
    throw err;
  }
}

async function handleButtonClick() {
  if (state.active) {
    if (!confirmRelease()) return;
    await releaseLockdown();
    return;
  }
  if (!confirmTrigger()) return;
  await triggerLockdown();
}

function isAdminMainContext() {
  if (typeof document !== 'undefined') {
    const pageFlag = document.body?.dataset?.page;
    if (pageFlag) return pageFlag === 'admin-main';
  }
  if (typeof window !== 'undefined') {
    const path = window.location?.pathname || '';
    const last = path.split('/').pop() || '';
    const pageName = last.split('?')[0];
    if (pageName) return pageName === 'main_page_new_test.html';
  }
  return false;
}


export function bootLockdownButton() {
  if (buttonEl) return;

  const candidate = document.getElementById('lockdownBtn');
  const auth = currentUser();

  const isAdminMainPage = isAdminMainContext();

  if (!auth?.is_admin || !isAdminMainPage) {
    if (candidate) candidate.remove();
    buttonEl = null;
    ensurePolling();
    fetchState();
    return;
  }

  buttonEl = candidate;
  if (!buttonEl) {
    ensurePolling();
    fetchState();
    return;
  }
  buttonEl.addEventListener('click', async (event) => {
    event.preventDefault();
    buttonEl.disabled = true;
    buttonEl.classList.add('busy');
    try {
      await handleButtonClick();
    } finally {
      buttonEl.disabled = false;
      buttonEl.classList.remove('busy');
    }
  });
  ensurePolling();
  fetchState();
  updateButton();
}

export function onLockdownChange(listener) {
  if (typeof listener !== 'function') return () => {};
  LISTENERS.add(listener);
  try { listener(cloneState()); }
  catch (_) {}
  ensurePolling();
  fetchState();
  return () => LISTENERS.delete(listener);
}

export function getLockdownState() {
  return cloneState();
}

// 초기 상태 동기화
fetchState();
ensurePolling();
