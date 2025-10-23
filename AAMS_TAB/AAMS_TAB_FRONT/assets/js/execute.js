import {
  fetchRequestDetail,
  executeRequest,
  markDispatchFailure,
  completeExecution,
  invalidateRequestDetail
} from "./api.js";
import { getMe } from "./util.js";
import { buildDispatchPayload, dispatchRobotViaLocal } from "./user.js";
import {
  loadExecuteContext,
  setExecuteContext,
  updateExecuteContext,
  clearExecuteContext
} from "./execute_context.js";

const DOT_ROWS = 12;
const DOT_COLS = 16;
const DOT_COUNT = DOT_ROWS * DOT_COLS;

const WAITING_MESSAGES = [
  "레일 위치를 정렬하는 중…",
  "비전 센서 캘리브레이션 중…",
  "안전 점검 데이터를 불러오는 중…",
  "사용자 전달 준비를 마무리하는 중…"
];

const STAGE_BASE_EXPRESSION = {
  queued: "focus",
  "detail-loading": "focus",
  "dispatch-ready": "focus",
  "await-local": "focus",
  "auto-dispatch": "smile",
  executing: "determined",
  completed: "salute",
  "dispatch-failed": "sad",
  "execution-failed": "sad",
  "report-failed": "sad",
  invalid: "sad",
  missing: "sad"
};

const LEFT_EYE = { row: 3, col: 4 };
const RIGHT_EYE = { row: 3, col: 9 };
const MOUTH = { row: 8, col: 6 };
const BASE_FRAME = buildBaseFrame();
const SALUTE_ARM = buildSaluteArm();

const EXPRESSIONS = {
  sleep: createExpression({ leftEye: "closed", rightEye: "closed", leftPupil: "none", rightPupil: "none", mouth: "neutral" }),
  idle: createExpression({ mouth: "neutral", leftPupil: "center", rightPupil: "center" }),
  focus: createExpression({ leftEye: "narrow", rightEye: "narrow", mouth: "neutral", leftPupil: "center", rightPupil: "center" }),
  determined: createExpression({ leftEye: "narrow", rightEye: "narrow", mouth: "neutral", leftPupil: "center", rightPupil: "center" }),
  lookLeft: createExpression({ mouth: "neutral", leftPupil: "left", rightPupil: "left" }),
  lookRight: createExpression({ mouth: "neutral", leftPupil: "right", rightPupil: "right" }),
  blink: createExpression({ leftEye: "closed", rightEye: "closed", leftPupil: "none", rightPupil: "none", mouth: "neutral" }),
  wink: createExpression({ leftEye: "open", rightEye: "closed", leftPupil: "center", rightPupil: "none", mouth: "smirk" }),
  smile: createExpression({ mouth: "smile", leftPupil: "center", rightPupil: "center" }),
  grin: createExpression({ mouth: "smile", leftPupil: "center", rightPupil: "center" }),
  salute: createExpression({ mouth: "smile", leftPupil: "center", rightPupil: "center", extras: [SALUTE_ARM] }),
  sad: createExpression({ mouth: "frown", leftEye: "narrow", rightEye: "narrow", leftPupil: "center", rightPupil: "center" }),
  surprised: createExpression({ mouth: "open", leftPupil: "center", rightPupil: "center" })
};


const EXPRESSION_ALIASES = {
  happy: "smile"
};

let screenEl;
let gridEl;
let statusEl;
let exitBtn;
let dots = [];
let baseExpression = "sleep";
let activeExpression = "sleep";
let microTimer = null;
let ambientAnimTimer = null;
let ambientTimer = null;
let ambientMessages = [];
let ambientIndex = 0;
let statusLabel = "";
let statusMessage = "";
let ambientMessage = "";
let currentStageKey = null;
let exitAutoTimer = null;
let exiting = false;

export async function initExecutionPage() {
  screenEl = document.getElementById("execute-screen");
  gridEl = document.getElementById("execute-grid");
  statusEl = document.getElementById("execute-status");
  exitBtn = document.getElementById("execute-exit");

  if (!screenEl || !gridEl || !statusEl) {
    console.error("[AAMS][execute] 필수 요소를 찾지 못했습니다.");
    return;
  }

  if (exitBtn) {
    exitBtn.addEventListener("click", () => {
      powerDownAndExit();
    });
  }

  gridEl.style.setProperty("--cols", String(DOT_COLS));
  gridEl.style.setProperty("--rows", String(DOT_ROWS));

  createDotGrid();
  applyExpression("sleep");

  const context = loadExecuteContext();
  if (!context || !context.requestId) {
    setStatus("집행 요청을 찾을 수 없습니다", "사용자 페이지로 돌아갑니다.", "error");
    await wait(1200);
    await powerDownAndExit({ immediate: true });
    return;
  }

  await playBootSequence();
  await runExecutionFlow(context);
}
async function runExecutionFlow(initialContext) {
  if (!initialContext || !initialContext.requestId) {
    updateStage("missing", "집행 요청을 찾을 수 없습니다", "사용자 페이지로 돌아갑니다.", { level: "error" });
    enableExit({ autoDelay: 2000 });
    return;
  }

  let context = setExecuteContext({ ...initialContext, state: initialContext.state || "pending" });
  const requestId = context.requestId;
  const me = context.executor && context.executor.id ? context.executor : getMe();

  if (!context.executor && me) {
    context = updateExecuteContext((prev) => ({ ...prev, executor: sanitizeExecutor(me) }));
  }

  updateStage("queued", "집행 명령 준비 중", "승인된 요청을 확인하고 있습니다…");

  let detail = context.detail || null;
  if (!detail) {
    try {
      detail = await fetchRequestDetail(requestId, { force: true });
      context = updateExecuteContext((prev) => ({ ...prev, detail }));
    } catch (err) {
      await handleFailure(context, "요청 정보 조회 실패", err, { stage: "invalid", actorId: me?.id });
      return;
    }
  }

  let dispatch = context.dispatch || null;
  if (!dispatch) {
    dispatch = buildDispatchPayload({ requestId, row: context.row, detail, executor: me });
    context = updateExecuteContext((prev) => ({ ...prev, dispatch }));
  }

  updateStage("dispatch-ready", "장비 명령 구성", "로봇이 수행할 명령을 조합하는 중…");

  let serverResult = context.serverResult || null;
  if (!serverResult) {
    try {
      serverResult = await executeRequest({ requestId, executorId: me?.id, dispatch });
      context = updateExecuteContext((prev) => ({ ...prev, serverResult }));
    } catch (err) {
    await handleFailure(context, "집행 명령 등록 실패", err, { stage: "dispatch-failed", actorId: me?.id });
      return;
    }
  }

  const dispatchFromServer = serverResult?.dispatch || dispatch;
  const localPayload = context.localPayload || serverResult?.payload || null;
  const requiresManual = !!(localPayload && serverResult?.bridge?.manualRequired !== false);
  context = updateExecuteContext((prev) => ({ ...prev, dispatch: dispatchFromServer, localPayload }));

  updateStage("await-local", "로컬 장비 연결 확인", "로봇 브릿지가 응답을 준비하고 있습니다…");

  if (!requiresManual || !localPayload) {
    updateStage("auto-dispatch", "자동 장비 명령", "로컬 브릿지가 자동으로 집행을 처리합니다.", { level: "success", expression: "smile" });
    invalidateRequestDetail(requestId);
    enableExit({ autoDelay: 6000 });
    return;
  }

  updateStage("executing", "장비 동작 중", "로봇이 현장을 제어하고 있습니다…");

  let localResult = context.localResult || null;
  if (!localResult) {
    try {
      localResult = await dispatchRobotViaLocal(localPayload, { timeoutMs: localPayload?.timeoutMs || 120000 });
      context = updateExecuteContext((prev) => ({ ...prev, localResult, state: "local-finished" }));
    } catch (err) {
      stopAmbientMessages();
      await handleFailure(context, "로컬 장비 호출 실패", err, { stage: "dispatch-failed", actorId: me?.id });
      return;
    }
  }

  stopAmbientMessages();

  const job = localResult?.job || null;
  const jobStatus = String(job?.status || job?.state || "").toLowerCase();
  const completionMessage = job?.message
    || job?.result?.message
    || job?.summary?.message
    || (job?.summary?.actionLabel && job?.summary?.includes?.label
      ? `${job.summary.actionLabel} ${job.summary.includes.label}`
      : "장비 제어가 정상적으로 완료되었습니다.");

  if (jobStatus && !["success", "succeeded", "done", "completed"].includes(jobStatus)) {
    await handleFailure(
      context,
      "장비 동작 오류",
      new Error(job?.message || job?.error || job?.result?.message || "장비 제어 실패"),
      { stage: "execution-failed", actorId: me?.id, job }
    );
    return;
  }

  updateStage("completed", "집행 완료", completionMessage, { level: "success", expression: "salute" });

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
  enableExit({ autoDelay: 20000 });
}

function updateStage(stageKey, label, message, { level = "info", expression } = {}) {
  currentStageKey = stageKey;
  const resolved = expression || STAGE_BASE_EXPRESSION[stageKey] || (level === "error" ? "sad" : level === "success" ? "salute" : "focus");
  setBaseExpression(resolved);
  if (stageKey === "executing") {
    startAmbientMessages(WAITING_MESSAGES);
  } else {
    stopAmbientMessages();
  }
  setStatus(label, message, level);
}

function setStatus(label, message, level = "info") {
  statusLabel = label || "";
  statusMessage = message || "";
  ambientMessage = "";
  if (statusEl) {
    statusEl.setAttribute("data-level", level);
  }
  applyStatus();
}

function setAmbientText(text) {
  ambientMessage = text || "";
  applyStatus();
}

function applyStatus() {
  if (!statusEl) return;
  const parts = [];
  if (statusLabel) parts.push(statusLabel);
  const message = ambientMessage || statusMessage;
  if (message) parts.push(message);
  statusEl.textContent = parts.join(" · ") || "\u00A0";
}
function startAmbientMessages(messages) {
  stopAmbientMessages();
  if (!Array.isArray(messages) || !messages.length) return;
  ambientMessages = messages.slice();
  ambientIndex = 0;
  setAmbientText(ambientMessages[ambientIndex]);
  ambientTimer = setInterval(() => {
    ambientIndex = (ambientIndex + 1) % ambientMessages.length;
    setAmbientText(ambientMessages[ambientIndex]);
  }, 3200);
}

function stopAmbientMessages() {
  ambientMessages = [];
  ambientIndex = 0;
  if (ambientTimer) {
    clearInterval(ambientTimer);
    ambientTimer = null;
  }
  setAmbientText("");
}

function startAmbientAnimations() {
  stopAmbientAnimations();
  const schedule = () => {
    const options = pickAmbientExpressions();
    if (!options.length) return;
    const choice = options[Math.floor(Math.random() * options.length)];
    const duration = choice === "blink" ? 260 : 420;
    playMicroExpression(choice, duration);
    ambientAnimTimer = setTimeout(schedule, randomInt(2200, 5200));
  };
  ambientAnimTimer = setTimeout(schedule, randomInt(1400, 2800));
}

function stopAmbientAnimations() {
  if (ambientAnimTimer) {
    clearTimeout(ambientAnimTimer);
    ambientAnimTimer = null;
  }
  if (microTimer) {
    clearTimeout(microTimer);
    microTimer = null;
    applyExpression(baseExpression);
  }
}

function pickAmbientExpressions() {
  const base = baseExpression;
  if (base === "sleep") return [];
  if (base === "sad") return ["blink", "lookLeft", "lookRight"];
  if (base === "salute") return ["blink", "wink", "lookLeft", "lookRight"];
  if (base === "determined" || base === "focus") return ["blink", "lookLeft", "lookRight"];
  return ["blink", "lookLeft", "lookRight", "wink"];
}

function playMicroExpression(name, duration = 400) {
  const resolved = resolveExpressionName(name);
  if (!EXPRESSIONS[resolved]) return;
  applyExpression(resolved);
  if (microTimer) clearTimeout(microTimer);
  microTimer = setTimeout(() => {
    microTimer = null;
    applyExpression(baseExpression);
  }, duration);
}

function setBaseExpression(name) {
  const resolved = resolveExpressionName(name);
  baseExpression = resolved;
  if (!microTimer) {
    applyExpression(resolved);
  }
}

function applyExpression(name) {
  const resolved = resolveExpressionName(name);
  const pattern = EXPRESSIONS[resolved] || EXPRESSIONS.idle;
  renderPattern(pattern);
  activeExpression = resolved;
  if (screenEl) {
    screenEl.setAttribute("data-expression", resolved);
  }
}

function resolveExpressionName(name) {
  if (name && EXPRESSIONS[name]) return name;
  if (name && EXPRESSION_ALIASES[name]) return EXPRESSION_ALIASES[name];
  return "idle";
}

function createDotGrid() {
  dots = [];
  if (!gridEl) return;
  gridEl.innerHTML = "";
  for (let i = 0; i < DOT_COUNT; i += 1) {
    const dot = document.createElement("span");
    dot.className = "execute-dot";
    dot.setAttribute("aria-hidden", "true");
    gridEl.appendChild(dot);
    dots.push(dot);
  }
}

function renderPattern(pattern) {
  if (!dots.length) return;
  const on = pattern?.on || EXPRESSIONS.idle.on;
  const accent = pattern?.accent || EXPRESSIONS.idle.accent;
  dots.forEach((dot, index) => {
    const active = on.has(index);
    dot.classList.toggle("is-on", active);
    dot.classList.toggle("is-accent", active && accent.has(index));
  });
}

function randomScatter(count) {
  if (!dots.length) return;
  const total = DOT_COUNT;
  const sampleCount = Math.max(0, Math.min(count, total));
  const indices = Array.from({ length: total }, (_, i) => i);
  for (let i = indices.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [indices[i], indices[j]] = [indices[j], indices[i]];
  }
  const onSet = new Set(indices.slice(0, sampleCount));
  const accentCount = Math.max(0, Math.floor(sampleCount * 0.2));
  const accentSet = new Set(indices.slice(0, accentCount));
  dots.forEach((dot, index) => {
    const active = onSet.has(index);
    dot.classList.toggle("is-on", active);
    dot.classList.toggle("is-accent", active && accentSet.has(index));
  });
}

async function playBootSequence() {
  if (screenEl) screenEl.dataset.scene = "boot";
  if (gridEl) gridEl.classList.add("is-boot");
  setStatus("시스템 웨이크업", "매트릭스를 정렬하는 중…");
  randomScatter(Math.floor(DOT_COUNT * 0.18));
  await wait(360);
  setStatus("시스템 웨이크업", "에메랄드 코어에 전원을 공급합니다…");
  randomScatter(Math.floor(DOT_COUNT * 0.5));
  await wait(420);
  setStatus("시스템 웨이크업", "감각 모듈을 초기화합니다…");
  randomScatter(Math.floor(DOT_COUNT * 0.72));
  await wait(360);
  applyExpression("blink");
  await wait(280);
  if (gridEl) gridEl.classList.remove("is-boot");
  if (screenEl) screenEl.dataset.scene = "active";
  setBaseExpression("idle");
  setStatus("집행 모드", "로봇을 준비하고 있습니다…");
  startAmbientAnimations();
}

async function powerDownAndExit({ immediate = false } = {}) {
  if (exiting) return;
  exiting = true;
  if (exitAutoTimer) {
    clearTimeout(exitAutoTimer);
    exitAutoTimer = null;
  }
  stopAmbientMessages();
  stopAmbientAnimations();
  if (exitBtn) exitBtn.disabled = true;
  if (screenEl) screenEl.dataset.scene = "shutdown";
  if (gridEl) gridEl.classList.add("is-shutdown");

  if (!immediate) {
    setStatus("시스템 종료", "안전 절차를 마무리하는 중…");
    playMicroExpression("blink", 320);
    await wait(360);
    setBaseExpression("sleep");
    await wait(320);
    randomScatter(Math.floor(DOT_COUNT * 0.32));
    await wait(200);
    randomScatter(Math.floor(DOT_COUNT * 0.12));
    await wait(200);
    randomScatter(0);
    await wait(200);
  }

  try {
    clearExecuteContext();
  } catch (err) {
    console.warn("[AAMS][execute] 컨텍스트 정리 실패:", err);
  }
  location.hash = "#/user";
}

function enableExit({ label = "사용자 페이지로 돌아가기", autoDelay = 20000 } = {}) {
  if (!exitBtn) return;
  exitBtn.hidden = false;
  exitBtn.disabled = false;
  exitBtn.textContent = label;
  if (exitAutoTimer) {
    clearTimeout(exitAutoTimer);
    exitAutoTimer = null;
  }
  if (typeof autoDelay === "number" && autoDelay > 0) {
    exitAutoTimer = setTimeout(() => {
      powerDownAndExit();
    }, autoDelay);
  }
}

async function handleFailure(context, title, error, { stage = "dispatch-failed", actorId = null, job = null } = {}) {
  const message = extractErrorMessage(error);
  console.error("[AAMS][execute]", stage, error);
  updateStage(stage, title, message, { level: "error", expression: "sad" });

  let current = context || loadExecuteContext() || {};
  if (current.requestId) {
    updateExecuteContext((prev) => ({ ...prev, state: "failed", error: message }));
    if (!current.failureReported) {
      try {
        await markDispatchFailure({ requestId: current.requestId, reason: message, actorId });
        updateExecuteContext((prev) => ({ ...prev, failureReported: true }));
      } catch (reportErr) {
        console.warn("[AAMS][execute] 오류 보고 실패:", reportErr);
      }
    }
    invalidateRequestDetail(current.requestId);
  }

  enableExit({ autoDelay: 20000 });
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
function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function idx(row, col) {
  return row * DOT_COLS + col;
}

function mergeInto(target, source) {
  if (!source) return;
  if (source instanceof Set) {
    source.forEach((value) => target.add(value));
    return;
  }
  if (Array.isArray(source)) {
    source.forEach((value) => {
      if (typeof value === "number" && value >= 0 && value < DOT_COUNT) {
        target.add(value);
      }
    });
  }
}

function rectCoords(row, col, height, width) {
  const coords = [];
  for (let r = 0; r < height; r += 1) {
    for (let c = 0; c < width; c += 1) {
      const rr = row + r;
      const cc = col + c;
      if (rr >= 0 && rr < DOT_ROWS && cc >= 0 && cc < DOT_COLS) {
        coords.push(idx(rr, cc));
      }
    }
  }
  return coords;
}

function coordsIndices(points) {
  const coords = [];
  for (const [row, col] of points) {
    if (row >= 0 && row < DOT_ROWS && col >= 0 && col < DOT_COLS) {
      coords.push(idx(row, col));
    }
  }
  return coords;
}

function buildBaseFrame() {
  const frame = new Set();
  for (let c = 2; c < DOT_COLS - 2; c += 1) {
    frame.add(idx(1, c));
    frame.add(idx(DOT_ROWS - 2, c));
  }
  for (let r = 1; r < DOT_ROWS - 1; r += 1) {
    frame.add(idx(r, 2));
    frame.add(idx(r, DOT_COLS - 3));
  }
  coordsIndices([
    [2, 3],
    [2, DOT_COLS - 4],
    [DOT_ROWS - 3, 3],
    [DOT_ROWS - 3, DOT_COLS - 4]
  ]).forEach((value) => frame.add(value));
  return frame;
}
function buildSaluteArm() {
  return new Set(coordsIndices([
    [8, 10], [7, 10], [6, 10],
    [7, 11], [6, 11], [5, 11],
    [5, 12], [4, 12], [4, 11],
    [8, 11]
  ]));
}

function createExpression({
  leftEye = "open",
  rightEye = "open",
  leftPupil = "center",
  rightPupil = "center",
  mouth = "neutral",
  extras = []
} = {}) {
  const on = new Set(BASE_FRAME);
  const accent = new Set();

  mergeInto(on, buildEye(LEFT_EYE, leftEye));
  mergeInto(on, buildEye(RIGHT_EYE, rightEye));
  mergeInto(accent, buildPupil(LEFT_EYE, leftPupil));
  mergeInto(accent, buildPupil(RIGHT_EYE, rightPupil));
  mergeInto(on, buildMouth(mouth));
  extras.forEach((extra) => mergeInto(on, extra));
  accent.forEach((value) => on.add(value));

  return Object.freeze({ on, accent });
}

function buildEye(anchor, mode = "open") {
  const { row, col } = anchor;
  if (mode === "closed") {
    return rectCoords(row + 2, col, 1, 4);
  }
  if (mode === "narrow") {
    return [
      ...rectCoords(row + 1, col, 1, 4),
      ...rectCoords(row + 2, col, 1, 4)
    ];
  }
  return [
    ...rectCoords(row, col + 1, 1, 2),
    ...rectCoords(row + 1, col, 1, 4),
    ...rectCoords(row + 2, col, 1, 4),
    ...rectCoords(row + 3, col + 1, 1, 2)
  ];
}

function buildPupil(anchor, direction = "center") {
  const { row, col } = anchor;
  if (direction === "none") return [];
  if (direction === "left") return rectCoords(row + 1, col, 2, 2);
  if (direction === "right") return rectCoords(row + 1, col + 2, 2, 2);
  if (direction === "up") return rectCoords(row, col + 1, 2, 2);
  return rectCoords(row + 1, col + 1, 2, 2);
}

function buildMouth(mode = "neutral") {
  const { row, col } = MOUTH;
  const coords = [];
  if (mode === "smile") {
    coords.push(...rectCoords(row, col, 1, 4));
    coords.push(...coordsIndices([[row - 1, col], [row - 1, col + 3]]));
  } else if (mode === "frown") {
    coords.push(...rectCoords(row, col, 1, 4));
    coords.push(...coordsIndices([[row + 1, col], [row + 1, col + 3]]));
  } else if (mode === "open") {
    coords.push(...rectCoords(row - 1, col + 1, 3, 2));
  } else if (mode === "smirk") {
    coords.push(...rectCoords(row, col, 1, 3));
    coords.push(...coordsIndices([[row - 1, col + 2], [row, col + 3]]));
  } else {
    coords.push(...rectCoords(row, col, 1, 4));
  }
  return coords;
}