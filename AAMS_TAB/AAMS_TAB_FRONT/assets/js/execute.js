import {
  fetchRequestDetail,
  executeRequest,
  markDispatchFailure,
  completeExecution,
  invalidateRequestDetail
} from "./api.js";
import { getMe, mountMobileHeader } from "./util.js";
import {
  buildDispatchPayload,
  dispatchRobotViaLocal,
  formatKST,
  formatAmmoLabel,
  resolveStatusInfo
} from "./user.js";
import {
  loadExecuteContext,
  setExecuteContext,
  updateExecuteContext,
  clearExecuteContext
} from "./execute_context.js";

const WAITING_MESSAGES = [
  "로봇과 레일 위치를 초기화하는 중…",
  "비전 센서를 정렬하고 있습니다…",
  "안전 검사용 데이터를 불러오는 중…",
  "장비를 사용자에게 전달하고 있습니다…"
];

const LOG_LIMIT = 60;

const MODE_LABEL = {
  DISPATCH: "불출",
  ISSUE: "불출",
  RETURN: "불입",
  RECEIVE: "불입"
};

let screenEl;
let robotEl;
let stageLabelEl;
let stageMessageEl;
let stageSubEl;
let logListEl;
let dispatchPreEl;
let metaBodyEl;
let backBtnEl;
let ambientTimer = null;
let redirectTimer = null;
let currentStageKey = null;

function sanitizeStageKey(value) {
  return (String(value || "pending").toLowerCase().replace(/[^a-z0-9]+/g, "-") || "pending");
}

function setMood(mood) {
  if (screenEl) screenEl.setAttribute("data-mood", mood || "focus");
  if (robotEl) robotEl.setAttribute("data-mood", mood || "focus");
}

function updateStage(stageKey, label, message, { level = "info", log = true, subMessage } = {}) {
  const key = sanitizeStageKey(stageKey);
  if (screenEl) screenEl.setAttribute("data-stage", key);
  if (stageLabelEl && typeof label === "string") {
    stageLabelEl.textContent = label;
  }
  if (stageMessageEl && typeof message === "string") {
    stageMessageEl.textContent = message;
  }
  if (stageSubEl) {
    stageSubEl.textContent = subMessage || "";
  }
  if (log && (currentStageKey !== key || (currentStageKey === key && level !== "info"))) {
    appendLog(level, label, message);
  }
  currentStageKey = key;
}

function appendLog(level, title, message, data) {
  if (!logListEl) return;
  const li = document.createElement("li");
  li.className = `log-item level-${sanitizeStageKey(level)}`;
  const time = document.createElement("time");
  time.className = "log-time";
  time.textContent = formatClock(Date.now());
  li.appendChild(time);

  const content = document.createElement("div");
  content.className = "log-body";
  const heading = document.createElement("strong");
  heading.className = "log-title";
  heading.textContent = title || "진행";
  const paragraph = document.createElement("p");
  paragraph.className = "log-message";
  paragraph.textContent = message || "-";
  content.appendChild(heading);
  content.appendChild(paragraph);

  if (data) {
    const details = document.createElement("details");
    details.className = "log-extra";
    const summary = document.createElement("summary");
    summary.textContent = "추가 정보";
    const pre = document.createElement("pre");
    try {
      pre.textContent = JSON.stringify(data, null, 2);
    } catch {
      pre.textContent = String(data);
    }
    details.appendChild(summary);
    details.appendChild(pre);
    content.appendChild(details);
  }

  li.appendChild(content);
  logListEl.appendChild(li);
  logListEl.scrollTop = logListEl.scrollHeight;

  if (logListEl.children.length > LOG_LIMIT) {
    while (logListEl.children.length > LOG_LIMIT) {
      logListEl.removeChild(logListEl.firstChild);
    }
  }
}

function formatClock(ts) {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "--:--:--";
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

function startAmbientTicker() {
  stopAmbientTicker();
  if (!stageSubEl) return;
  let idx = 0;
  stageSubEl.textContent = WAITING_MESSAGES[idx];
  ambientTimer = setInterval(() => {
    idx = (idx + 1) % WAITING_MESSAGES.length;
    stageSubEl.textContent = WAITING_MESSAGES[idx];
  }, 3200);
}

function stopAmbientTicker() {
  if (ambientTimer) {
    clearInterval(ambientTimer);
    ambientTimer = null;
  }
  if (stageSubEl) {
    stageSubEl.textContent = "";
  }
}

function renderDispatch(dispatch) {
  if (!dispatchPreEl) return;
  if (!dispatch) {
    dispatchPreEl.textContent = "장비 명령을 준비 중…";
    return;
  }
  try {
    dispatchPreEl.textContent = JSON.stringify(dispatch, null, 2);
  } catch (err) {
    dispatchPreEl.textContent = String(dispatch);
  }
}

function formatAmmoSummary(items = []) {
  if (!Array.isArray(items) || !items.length) return "-";
  return items.map((item) => formatAmmoLabel(item)).join(", ");
}

function renderMeta(dispatch, detail) {
  if (!metaBodyEl) return;
  if (!dispatch) {
    metaBodyEl.innerHTML = '<div class="muted">집행 정보를 준비 중…</div>';
    return;
  }

  const pieces = [];
  const requestId = dispatch.request_id || dispatch.requestId || detail?.request?.id || "-";
  const typeKey = String(dispatch.type || detail?.request?.type || detail?.request?.request_type || "").toUpperCase();
  const modeLabel = dispatch.includes?.label
    || (dispatch.mode === "firearm_and_ammo" ? "총기+탄약"
      : dispatch.mode === "firearm_only" ? "총기"
      : dispatch.mode === "ammo_only" ? "탄약" : null);
  const typeLabel = MODE_LABEL[typeKey] || (typeKey === "RETURN" ? "불입" : "불출");
  pieces.push(renderMetaRow("요청 번호", `#${requestId}`));
  pieces.push(renderMetaRow("집행 유형", [typeLabel, modeLabel].filter(Boolean).join(" · ") || typeLabel || "-"));

  const firearm = dispatch.firearm || null;
  if (firearm) {
    const firearmParts = [firearm.type, firearm.code].filter(Boolean).join(" · ");
    const lockerInfo = firearm.locker || dispatch.locker;
    pieces.push(renderMetaRow("총기", lockerInfo ? `${firearmParts} (보관함 ${lockerInfo})` : firearmParts || "-"));
  }

  if (Array.isArray(dispatch.ammo) && dispatch.ammo.length) {
    pieces.push(renderMetaRow("탄약", formatAmmoSummary(dispatch.ammo)));
  }

  if (dispatch.location) {
    pieces.push(renderMetaRow("근무지", dispatch.location));
  }

  if (dispatch.locker && (!firearm || firearm.locker !== dispatch.locker)) {
    pieces.push(renderMetaRow("보관함", dispatch.locker));
  }

  if (dispatch.purpose) {
    pieces.push(renderMetaRow("용도", dispatch.purpose));
  }

  if (detail?.request?.approved_at || dispatch.approved_at) {
    const approved = formatKST(dispatch.approved_at || detail.request.approved_at) || "-";
    pieces.push(renderMetaRow("승인 시각", approved));
  }

  metaBodyEl.innerHTML = pieces.join("");
}

function renderMetaRow(term, desc) {
  return `<div class="meta-row"><dt>${escapeHtml(term || "")}</dt><dd>${escapeHtml(desc || "-")}</dd></div>`;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function showBackButton(text) {
  if (!backBtnEl) return;
  if (typeof text === "string") backBtnEl.textContent = text;
  backBtnEl.hidden = false;
  backBtnEl.disabled = false;
}

function scheduleRedirect(delay = 2600) {
  if (redirectTimer) return;
  redirectTimer = setTimeout(() => {
    clearExecuteContext();
    location.hash = "#/user";
  }, delay);
}

function clearRedirectTimer() {
  if (redirectTimer) {
    clearTimeout(redirectTimer);
    redirectTimer = null;
  }
}

function extractErrorMessage(err) {
  if (!err) return "알 수 없는 오류";
  if (typeof err === "string") return err;
  const message = err.message || String(err);
  const match = message.match(/HTTP\s+\d+\s*:\s*(.+)$/i);
  if (match) {
    const tail = match[1].trim();
    try {
      const parsed = JSON.parse(tail);
      if (parsed && typeof parsed === "object") {
        return parsed.error || parsed.message || message;
      }
    } catch (_) {
      return tail;
    }
    return tail;
  }
  return message;
}

async function handleFailure(context, title, error, { stage = "failed", actorId = null, job = null } = {}) {
  const message = extractErrorMessage(error);
  setMood("sad");
  updateStage(stage, title, message, { level: "error", log: true });
  if (job) {
    appendLog("error", title, message, job);
  }

  let current = context || loadExecuteContext() || {};
  if (current.requestId) {
    updateExecuteContext((prev) => ({ ...prev, state: "failed", error: message }));
    if (!current.failureReported) {
      try {
        await markDispatchFailure({ requestId: current.requestId, reason: message, actorId });
        updateExecuteContext((prev) => ({ ...prev, failureReported: true }));
      } catch (reportErr) {
        appendLog("error", "오류 보고 실패", extractErrorMessage(reportErr));
      }
    }
    invalidateRequestDetail(current.requestId);
  }

  showBackButton("사용자 페이지로 돌아가기");
  scheduleRedirect(4200);
}

async function runExecutionFlow(initialContext) {
  if (!initialContext || !initialContext.requestId) {
    updateStage("invalid", "집행 요청을 찾을 수 없습니다", "사용자 페이지로 돌아갑니다.");
    showBackButton();
    scheduleRedirect(1800);
    return;
  }

  let context = setExecuteContext({ ...initialContext, state: initialContext.state || "pending" });
  const requestId = context.requestId;
  const me = context.executor && context.executor.id ? context.executor : getMe();

  if (!context.executor && me) {
    context = updateExecuteContext((prev) => ({ ...prev, executor: sanitizeExecutor(me) }));
  }

  setMood("focus");
  updateStage("queued", "집행 명령 준비 중", "승인된 정보를 확인하고 있습니다…", { log: true });

  let detail = context.detail || null;
  if (!detail) {
    try {
      detail = await fetchRequestDetail(requestId, { force: true });
      context = updateExecuteContext((prev) => ({ ...prev, detail, state: "detail-loaded" }));
    } catch (err) {
      await handleFailure(context, "요청 정보를 불러오지 못했습니다", err, { stage: "detail-failed", actorId: me?.id });
      return;
    }
  }

  const dispatch = buildDispatchPayload({ requestId, row: context.row || null, detail, executor: me });
  if (!dispatch) {
    await handleFailure(context, "장비 명령 생성 실패", new Error("장비 명령 데이터가 부족합니다."), { stage: "dispatch-missing", actorId: me?.id });
    return;
  }

  context = updateExecuteContext((prev) => ({ ...prev, dispatch }));
  renderMeta(dispatch, detail);
  renderDispatch(dispatch);

  let serverResult = context.serverResult || null;
  if (!serverResult) {
    updateStage("dispatching", "서버 동기화 중", "Render 서버로 집행 명령을 전달하고 있습니다…", { log: true });
    try {
      serverResult = await executeRequest({ requestId, executorId: me?.id, dispatch });
      context = updateExecuteContext((prev) => ({ ...prev, serverResult, state: "server-dispatched" }));
    } catch (err) {
      await handleFailure(context, "서버 통신 실패", err, { stage: "server-failed", actorId: me?.id });
      return;
    }
  } else {
    updateStage("dispatching", "서버 동기화 중", "이전에 전송된 명령 정보를 이어서 표시합니다.", { log: false });
  }

  if (serverResult && serverResult.ok === false) {
    await handleFailure(context, "집행 명령 처리 실패", new Error(serverResult.error || "execute_failed"), { stage: "server-reject", actorId: me?.id });
    return;
  }

  if (serverResult?.status) {
    const info = resolveStatusInfo(serverResult.status, { status_reason: serverResult.status_reason, status: serverResult.status });
    updateStage(info.key || "dispatch-pending", info.label || "장비 명령 대기", serverResult.status_reason || info.hint || "장비 명령을 준비하고 있습니다.", { log: true });
  }

  const localPayload = context.localPayload || serverResult?.payload || null;
  const requiresManual = !!(localPayload && serverResult?.bridge?.manualRequired !== false);
  context = updateExecuteContext((prev) => ({ ...prev, localPayload }));

  if (!requiresManual || !localPayload) {
    updateStage("auto-dispatch", "자동 명령 전달", "로컬 브릿지가 자동으로 장비 명령을 처리하고 있습니다. 사용자 페이지에서 결과를 확인해 주세요.", { log: true });
    showBackButton("사용자 페이지로 돌아가기");
    invalidateRequestDetail(requestId);
    scheduleRedirect(3600);
    return;
  }

  updateStage("executing", "장비 동작 중", "로컬 장비 제어 코드를 호출했습니다. 실행이 완료될 때까지 기다려 주세요.", { log: true });
  startAmbientTicker();

  let localResult = context.localResult || null;
  if (!localResult) {
    try {
      localResult = await dispatchRobotViaLocal(localPayload, { timeoutMs: localPayload?.timeoutMs || 120000 });
      context = updateExecuteContext((prev) => ({ ...prev, localResult, state: "local-finished" }));
    } catch (err) {
      stopAmbientTicker();
      await handleFailure(context, "로컬 브릿지 오류", err, { stage: "dispatch-failed", actorId: me?.id });
      return;
    }
  } else {
    stopAmbientTicker();
    appendLog("info", "로컬 진행", "이전에 수신한 로컬 브릿지 결과를 표시합니다.", localResult?.job || localResult);
  }

  const job = localResult?.job || null;
  const jobStatus = String(job?.status || "").toLowerCase();
  const completionMessage = job?.message
    || job?.result?.message
    || (job?.summary?.actionLabel && job?.summary?.includes?.label
      ? `${job.summary.actionLabel} ${job.summary.includes.label}`
      : "장비 제어가 정상적으로 완료되었습니다.");

  if (jobStatus && jobStatus !== "succeeded") {
    stopAmbientTicker();
    await handleFailure(context, "장비 동작 오류", new Error(job?.message || job?.error || job?.result?.message || "장비 제어 실패"), { stage: "execution-failed", actorId: me?.id, job });
    return;
  }

  stopAmbientTicker();
  setMood("happy");
  updateStage("completed", "집행 완료", completionMessage, { level: "success", log: true });
  appendLog("success", "장비 완료", completionMessage, job);

  if (!context.completionReported) {
    try {
      await completeExecution({
        requestId,
        actorId: me?.id,
        eventId: serverResult?.event_id,
        result: job,
        statusReason: completionMessage
      });
      context = updateExecuteContext((prev) => ({ ...prev, completionReported: true, state: "completed" }));
    } catch (err) {
      await handleFailure(context, "집행 결과 반영 실패", err, { stage: "report-failed", actorId: me?.id, job });
      return;
    }
  }

  invalidateRequestDetail(requestId);
  showBackButton("집행이 완료되었습니다. 사용자 페이지로 돌아갑니다.");
  scheduleRedirect(3200);
}

function sanitizeExecutor(executor = {}) {
  if (!executor || typeof executor !== "object") return null;
  const cleaned = {
    id: executor.id || executor.user_id || null,
    name: executor.name || null,
    rank: executor.rank || null,
    unit: executor.unit || executor.unit_name || null
  };
  Object.keys(cleaned).forEach((key) => {
    if (cleaned[key] === undefined || cleaned[key] === null) delete cleaned[key];
  });
  return Object.keys(cleaned).length ? cleaned : null;
}

export async function initExecutionPage() {
  screenEl = document.getElementById("execute-screen");
  robotEl = document.getElementById("execute-bot");
  stageLabelEl = document.getElementById("execute-stage-label");
  stageMessageEl = document.getElementById("execute-stage-message");
  stageSubEl = document.getElementById("execute-stage-sub");
  logListEl = document.getElementById("execute-log");
  dispatchPreEl = document.getElementById("execute-dispatch-json");
  metaBodyEl = document.getElementById("execute-meta-body");
  backBtnEl = document.getElementById("execute-back");

  await mountMobileHeader({ title: "집행 진행 중", pageType: "subpage", backTo: "#/user", showLogout: true });

  if (backBtnEl) {
    backBtnEl.addEventListener("click", () => {
      clearRedirectTimer();
      clearExecuteContext();
      location.hash = "#/user";
    });
  }

  const context = loadExecuteContext();
  if (!context || !context.requestId) {
    updateStage("missing", "집행 요청을 찾을 수 없습니다", "사용자 페이지로 돌아갑니다.");
    showBackButton();
    scheduleRedirect(1800);
    return;
  }

  renderMeta(context.dispatch || null, context.detail || null);
  renderDispatch(context.dispatch || null);

  await runExecutionFlow(context);
}