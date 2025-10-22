// assets/js/fingerprint.js
import { mountMobileHeader, saveMe } from "./util.js";
import { openFpEventSource } from "./api.js";

const API_BASE = (window.AAMS_CONFIG && window.AAMS_CONFIG.API_BASE) || "";
const SITE = window.FP_SITE || "site-01";
const WAIT_AFTER_SUCCESS_MS = 3000;
const SCAN_FEEDBACK_DELAY_MS = 420;

const sleep = (ms = 0) => new Promise((resolve) => setTimeout(resolve, ms));

function formatDisplayName(me = {}, fallback = "사용자") {
  const rank = me?.rank ? String(me.rank).trim() : "";
  const name = me?.name ? String(me.name).trim() : String(fallback);
  return [rank, name].filter(Boolean).join(" ").replace(/\s+/g, " ").trim();
}

function formatProfileSub(me = {}) {
  const unit = me.unit || me.unit_name;
  const position = me.position || me.duty;
  const serial = me.serial || me.military_id || me.militaryId || me.service_no;
  return [unit, position, serial]
    .map((value) => (value == null ? "" : String(value).trim()))
    .filter(Boolean)
    .join(" · ");
}

function pickTarget(result, fallback) {
  if (typeof result === "string" && result.trim()) {
    return result.trim();
  }
  if (result && typeof result === "object" && typeof result.target === "string" && result.target.trim()) {
    return result.target.trim();
  }
  return fallback;
}

function createFingerprintStage({ fallbackName = "사용자", errorResetMs = 2600 } = {}) {
  const stage = document.querySelector(".fp-stage");
  if (!stage) {
    return {
      setWaiting() {},
      setScanning() {},
      showSuccess() {},
      showError() {},
    };
  }

  const nameEl = stage.querySelector("[data-role='name']");
  const profileEl = stage.querySelector("[data-role='profile']");
  const profileNameEl = stage.querySelector("[data-role='profile-name']");
  const profileSubEl = stage.querySelector("[data-role='profile-sub']");
  const errorLine = stage.querySelector(".fp-status-line[data-for~='error']");
  const defaultError = errorLine ? errorLine.textContent.trim() : "";

  let resetTimer = null;
  const clearReset = () => { if (resetTimer) { clearTimeout(resetTimer); resetTimer = null; } };

  const applyState = (state) => {
    stage.dataset.state = state;
    if (!profileEl) return;
    const hasDetail = !!(profileNameEl?.textContent || profileSubEl?.textContent);
    profileEl.hidden = !(state === "success" && hasDetail);
  };

  const setWaiting = () => {
    clearReset();
    if (errorLine) errorLine.textContent = defaultError;
    if (profileNameEl) profileNameEl.textContent = "";
    if (profileSubEl) profileSubEl.textContent = "";
    applyState("waiting");
  };

  const setScanning = () => {
    clearReset();
    if (profileEl) profileEl.hidden = true;
    applyState("scanning");
  };

  const showSuccess = (me = {}) => {
    clearReset();
    const displayName = formatDisplayName(me, fallbackName);
    if (nameEl) nameEl.textContent = displayName;
    if (profileNameEl) profileNameEl.textContent = displayName;
    if (profileSubEl) profileSubEl.textContent = formatProfileSub(me);
    if (errorLine) errorLine.textContent = defaultError;
    applyState("success");
  };

  const showError = (message, { autoResetMs = errorResetMs } = {}) => {
    clearReset();
    if (errorLine) errorLine.textContent = message || defaultError;
    if (profileEl) profileEl.hidden = true;
    applyState("error");
    if (autoResetMs && autoResetMs > 0) {
      resetTimer = setTimeout(() => {
        if (errorLine) errorLine.textContent = defaultError;
        applyState("waiting");
      }, autoResetMs);
    }
  };

  setWaiting();

  return { setWaiting, setScanning, showSuccess, showError };
}

async function enrichAndSave(me) {
  try {
    const r = await fetch(`${API_BASE}/api/personnel/${encodeURIComponent(me.id)}`);
    const detail = r.ok ? await r.json() : null;

    const mergedDetail = detail || {};
    const { is_admin: detailIsAdmin, ...restDetail } = mergedDetail;
    const merged = { ...me, ...restDetail };
    if (typeof me?.is_admin === "boolean") {
      merged.is_admin = me.is_admin || !!detailIsAdmin || !!merged.is_admin;
    } else if (detailIsAdmin !== undefined) {
      merged.is_admin = !!detailIsAdmin;
    }
    saveMe(merged);
    return merged;
  } catch {
    saveMe(me);
    return me;
  }
}

function resolveRedirect(me, redirect) {
  if (typeof redirect === "function") {
    try {
      return redirect(me);
    } catch {
      return null;
    }
  }
  if (typeof redirect === "string" && redirect.trim()) {
    return redirect;
  }
  return me?.is_admin ? "#/admin" : "#/user";
}


async function claimOnce({ adminOnly = false, requireAdmin = false, redirect, autoRedirect = true, onResolved } = {}) {
  try {
    const after = Number(localStorage.getItem("AAMS_LOGOUT_AT") || 0);
    const body = { site: SITE, after };
    if (adminOnly) body.adminOnly = true;
    const r = await fetch(`${API_BASE}/api/fp/claim`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });
    const j = await r.json();
    if (j && j.ok && j.person_id) {
      const base = { id: Number(j.person_id), name: j.name, is_admin: !!j.is_admin };
      if (requireAdmin && !base.is_admin) {
        return { success: false };
      }
      const me = await enrichAndSave(base);
      const resolvedTarget = resolveRedirect(me, redirect);
      const ctx = { source: "claim", target: resolvedTarget };
      let cbResult;
      if (typeof onResolved === "function") {
        try { cbResult = await onResolved(me, ctx); } catch {}
      }
      if (cbResult === false) {
        return { success: false, me, target: resolvedTarget };
      }
      const nextTarget = pickTarget(cbResult, resolvedTarget);
      if (autoRedirect !== false && nextTarget) {
        location.hash = nextTarget;
      }
      return { success: true, me, target: nextTarget };
    }
  } catch {}
  return { success: false };
}

function listenAndRedirect({ requireAdmin = false, redirect, autoRedirect = true, onResolved } = {}) {
  let handled = false;
  const es = openFpEventSource({
    site: SITE,
    onEvent: async (payload) => {
      if (handled) return;
      const d = payload?.data;
      const r = payload?.resolved;
      if (!(d && d.type === "identify" && d.ok && r && r.person_id)) return;
      const base = { id: Number(r.person_id), name: r.name, is_admin: !!r.is_admin };
      if (requireAdmin && !base.is_admin) {
        return;
      }
      const me = await enrichAndSave(base);
      const resolvedTarget = resolveRedirect(me, redirect);
      const ctx = { source: "event", event: payload, target: resolvedTarget };
      let cbResult;
      if (typeof onResolved === "function") {
        try { cbResult = await onResolved(me, ctx); } catch {}
      }
      if (cbResult === false) {
        return;
      }
      if (handled) return;
      handled = true;
      const nextTarget = pickTarget(cbResult, resolvedTarget);
      if (autoRedirect !== false && nextTarget) {
        location.hash = nextTarget;
      }
      try { es.close(); } catch {}
    }
  });
  window.addEventListener("beforeunload", () => { try { es.close(); } catch {} });
  return es;
}

async function claimOnceAdmin(options = {}) {
  const { redirect = "#/admin", ...rest } = options || {};
  return claimOnce({ adminOnly: true, requireAdmin: true, redirect, ...rest });
}

export async function initFpUser() {
  await mountMobileHeader({ title: "사용자 지문 인증", pageType: "login", backTo: "#/" });
  const stage = createFingerprintStage({ fallbackName: "사용자" });

  let redirectTimer = null;
  const scheduleRedirect = (target) => {
    const next = target || "#/user";
    if (!next) return;
    if (redirectTimer) clearTimeout(redirectTimer);
    redirectTimer = setTimeout(() => { location.hash = next; }, WAIT_AFTER_SUCCESS_MS);
  };

  const handleResolved = async (me, ctx) => {
    stage.setScanning();
    await sleep(SCAN_FEEDBACK_DELAY_MS);
    stage.showSuccess(me);
    scheduleRedirect(ctx?.target || "#/user");
    return true;
  };



  const claimResult = await claimOnce({ redirect: "#/user", autoRedirect: false, onResolved: handleResolved });
  if (claimResult.success) {
    return;
  }

  listenAndRedirect({ redirect: "#/user", autoRedirect: false, onResolved: handleResolved });
}

export async function initFpAdmin() {
  await mountMobileHeader({ title: "관리자 지문 인증", pageType: "login", backTo: "#/admin-login" });
  const stage = createFingerprintStage({ fallbackName: "관리자" });
  const loginId = String(sessionStorage.getItem("AAMS_ADMIN_LOGIN_ID") || "").trim();
  const mismatchMessage = loginId
    ? `현재 로그인한 관리자 계정(${loginId})과 지문이 일치하지 않습니다. 다시 시도해 주세요.`
    : "로그인한 관리자 계정과 지문이 일치하지 않습니다. 다시 시도해 주세요.";


  let redirectTimer = null;
  const scheduleRedirect = (target) => {
    const next = target || "#/admin";
    if (!next) return;
    if (redirectTimer) clearTimeout(redirectTimer);
    redirectTimer = setTimeout(() => { location.hash = next; }, WAIT_AFTER_SUCCESS_MS);
  };

  const handleResolved = async (me, ctx) => {
    const actualId = me?.user_id ? String(me.user_id).trim() : "";
    if (loginId && actualId && loginId !== actualId) {
      stage.showError(mismatchMessage, { autoResetMs: 2600 });
      return false;
    }
    stage.setScanning();
    await sleep(SCAN_FEEDBACK_DELAY_MS);
    stage.showSuccess(me);
    scheduleRedirect(ctx?.target || "#/admin");
    return true;
  };

  const claimResult = await claimOnceAdmin({ autoRedirect: false, onResolved: handleResolved });
  if (claimResult.success) {
    return;
  }

  listenAndRedirect({ requireAdmin: true, redirect: "#/admin", autoRedirect: false, onResolved: handleResolved });
}