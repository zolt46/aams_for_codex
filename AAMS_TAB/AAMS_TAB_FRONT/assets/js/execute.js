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

const DOT_ROWS = 24;
const DOT_COLS = 32;
const DOT_COUNT = DOT_ROWS * DOT_COLS;

const EYE_WIDTH = 6;
const EYE_HEIGHT = 5;
const EYE_ROW = 6;
const LEFT_EYE_COL = 7;
const RIGHT_EYE_COL = DOT_COLS - LEFT_EYE_COL - EYE_WIDTH;
const MOUTH_WIDTH = 10;
const MOUTH_ROW = DOT_ROWS - 6;
const MOUTH_COL = Math.floor((DOT_COLS - MOUTH_WIDTH) / 2);

const WAITING_MESSAGES = [
  "센서 정렬 중",
  "안전 점검",
  "경로 준비",
  "전달 대기"
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

const LEFT_EYE = { row: EYE_ROW, col: LEFT_EYE_COL };
const RIGHT_EYE = { row: EYE_ROW, col: RIGHT_EYE_COL };
const MOUTH = { row: MOUTH_ROW, col: MOUTH_COL };
const BASE_FRAME = buildBaseFrame();
const SALUTE_ARM = buildSaluteArm();
const CHEEK_LEFT = buildCheek(MOUTH.row - 3, Math.max(3, LEFT_EYE.col - 2));
const CHEEK_RIGHT = buildCheek(MOUTH.row - 3, Math.min(DOT_COLS - 4, RIGHT_EYE.col + EYE_WIDTH - 2));
const CHEEK_BLUSH = combineSets(CHEEK_LEFT, CHEEK_RIGHT);

const EXPRESSIONS = {
  sleep: createExpression({ leftEye: "closed", rightEye: "closed", leftPupil: "none", rightPupil: "none", mouth: "neutral" }),
  idle: createExpression({ mouth: "soft-smile", leftPupil: "center", rightPupil: "center", accentExtras: [CHEEK_BLUSH] }),
  focus: createExpression({ leftEye: "narrow", rightEye: "narrow", mouth: "neutral", leftPupil: "center", rightPupil: "center" }),
  determined: createExpression({ leftEye: "narrow", rightEye: "narrow", mouth: "soft-smile", leftPupil: "center", rightPupil: "center", accentExtras: [CHEEK_BLUSH] }),
  lookLeft: createExpression({ mouth: "soft-smile", leftPupil: "left", rightPupil: "left", accentExtras: [CHEEK_BLUSH] }),
  lookRight: createExpression({ mouth: "soft-smile", leftPupil: "right", rightPupil: "right", accentExtras: [CHEEK_BLUSH] }),
  blink: createExpression({ leftEye: "closed", rightEye: "closed", leftPupil: "none", rightPupil: "none", mouth: "soft-smile", accentExtras: [CHEEK_BLUSH] }),
  wink: createExpression({ leftEye: "open", rightEye: "closed", leftPupil: "center", rightPupil: "none", mouth: "smirk", accentExtras: [CHEEK_BLUSH] }),
  smile: createExpression({ mouth: "smile", leftPupil: "center", rightPupil: "center", accentExtras: [CHEEK_BLUSH] }),
  grin: createExpression({ mouth: "smile", leftPupil: "up", rightPupil: "up", accentExtras: [CHEEK_BLUSH] }),
  salute: createExpression({ mouth: "smile", leftPupil: "center", rightPupil: "center", extras: [SALUTE_ARM], accentExtras: [CHEEK_BLUSH] }),
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

  updateStage("queued", "집행 준비", "승인 정보 확인");

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

  updateStage("dispatch-ready", "명령 구성", "시퀀스 조립");

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

  updateStage("await-local", "로컬 대기", "브릿지 확인");

  if (!requiresManual || !localPayload) {
    updateStage("auto-dispatch", "자동 실행", "로봇 즉시 진행", { level: "success", expression: "smile" });
    invalidateRequestDetail(requestId);
    enableExit({ autoDelay: 6000 });
    return;
  }

  updateStage("executing", "로봇 동작", "현장 제어");

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
      : "장비 제어 완료");

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
    if (label) {
      statusEl.setAttribute("data-label", label);
    } else {
      statusEl.removeAttribute("data-label");
    }
  }
  applyStatus();
}

function setAmbientText(text) {
  ambientMessage = text || "";
  applyStatus();
}

function applyStatus() {
  if (!statusEl) return;
  const message = ambientMessage || statusMessage || statusLabel;
  statusEl.textContent = message || "\u00A0";
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
  setStatus("부팅", "전원 주입");
  randomScatter(Math.floor(DOT_COUNT * 0.2));
  await wait(360);
  setStatus("부팅", "신경망 정렬");
  randomScatter(Math.floor(DOT_COUNT * 0.55));
  await wait(420);
  setStatus("부팅", "표정 매핑");
  randomScatter(Math.floor(DOT_COUNT * 0.78));
  await wait(420);
  applyExpression("blink");
  await wait(320);
  if (gridEl) gridEl.classList.remove("is-boot");
  if (screenEl) screenEl.dataset.scene = "active";
  setBaseExpression("idle");
  setStatus("집행 준비", "웨이크업 완료");
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
    setStatus("종료", "안전 절차 진행");
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

function combineSets(...sets) {
  const merged = new Set();
  sets.forEach((set) => mergeInto(merged, set));
  return merged;
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
  const baseRow = Math.max(4, MOUTH.row - 1);
  const baseCol = Math.min(DOT_COLS - 4, RIGHT_EYE.col + EYE_WIDTH + 1);
  return new Set(coordsIndices([
    [baseRow + 1, baseCol - 1],
    [baseRow, baseCol - 1],
    [baseRow - 1, baseCol - 1],
    [baseRow - 2, baseCol - 1],
    [baseRow - 2, baseCol],
    [baseRow - 3, baseCol],
    [baseRow - 4, baseCol],
    [baseRow - 4, baseCol + 1],
    [baseRow - 3, baseCol + 1],
    [baseRow - 1, baseCol]
  ]));
}

function buildCheek(row, col) {
  return new Set(rectCoords(row, col, 2, 2));
}

function createExpression({
  leftEye = "open",
  rightEye = "open",
  leftPupil = "center",
  rightPupil = "center",
  mouth = "neutral",
  extras = [],
  accentExtras = []
} = {}) {
  const on = new Set(BASE_FRAME);
  const accent = new Set();

  mergeInto(on, buildEye(LEFT_EYE, leftEye));
  mergeInto(on, buildEye(RIGHT_EYE, rightEye));
  mergeInto(accent, buildPupil(LEFT_EYE, leftPupil));
  mergeInto(accent, buildPupil(RIGHT_EYE, rightPupil));
  mergeInto(on, buildMouth(mouth));
  extras.forEach((extra) => mergeInto(on, extra));
  accentExtras.forEach((extra) => mergeInto(accent, extra));
  accent.forEach((value) => on.add(value));

  return Object.freeze({ on, accent });
}

function buildEye(anchor, mode = "open") {
  const { row, col } = anchor;
  if (mode === "closed") {
    return rectCoords(row + Math.floor(EYE_HEIGHT / 2), col, 1, EYE_WIDTH);
  }
  if (mode === "narrow") {
    return [
      ...rectCoords(row + 1, col, 1, EYE_WIDTH),
      ...rectCoords(row + 2, col, 1, EYE_WIDTH),
      ...rectCoords(row + 3, col, 1, EYE_WIDTH)
    ];
  }
  return [
    ...rectCoords(row, col + 1, 1, EYE_WIDTH - 2),
    ...rectCoords(row + 1, col, 1, EYE_WIDTH),
    ...rectCoords(row + 2, col, 1, EYE_WIDTH),
    ...rectCoords(row + 3, col, 1, EYE_WIDTH),
    ...rectCoords(row + 4, col + 1, 1, EYE_WIDTH - 2)
  ];
}

function buildPupil(anchor, direction = "center") {
  const { row, col } = anchor;
  if (direction === "none") return [];
  const width = 2;
  const height = 2;
  const centerRow = row + 2;
  const centerCol = col + Math.floor((EYE_WIDTH - width) / 2);
  let targetRow = centerRow;
  let targetCol = centerCol;
  if (direction === "left") targetCol = col + 1;
  if (direction === "right") targetCol = col + EYE_WIDTH - width - 1;
  if (direction === "up") targetRow = row + 1;
  if (direction === "down") targetRow = row + 3;
  return rectCoords(targetRow, targetCol, height, width);
}

function buildMouth(mode = "neutral") {
  const { row, col } = MOUTH;
  const width = MOUTH_WIDTH;
  const coords = [];
  if (mode === "smile") {
    coords.push(...rectCoords(row, col, 1, width));
    coords.push(...coordsIndices([[row - 1, col], [row - 1, col + width - 1]]));
  } else if (mode === "soft-smile") {
    coords.push(...rectCoords(row, col + 1, 1, width - 2));
    coords.push(...coordsIndices([[row - 1, col + 1], [row - 1, col + width - 2]]));
  } else if (mode === "frown") {
    coords.push(...rectCoords(row, col, 1, width));
    coords.push(...coordsIndices([[row + 1, col], [row + 1, col + width - 1]]));
  } else if (mode === "open") {
    coords.push(...rectCoords(row - 1, col + Math.floor((width - 2) / 2), 3, 2));
  } else if (mode === "smirk") {
    coords.push(...rectCoords(row, col + width - 4, 1, 4));
    coords.push(...coordsIndices([[row - 1, col + width - 3], [row, col + width - 1]]));
  } else {
    coords.push(...rectCoords(row, col, 1, width));
  }
  return coords;
}