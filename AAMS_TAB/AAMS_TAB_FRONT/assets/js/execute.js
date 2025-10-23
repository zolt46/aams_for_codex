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

const DOT_ROWS = 36;
const DOT_COLS = 64;
const DOT_COUNT = DOT_ROWS * DOT_COLS;

const EYE_WIDTH = 12;
const EYE_HEIGHT = 6;
const EYE_ROW = 10;
const LEFT_EYE_COL = 14;
const RIGHT_EYE_COL = DOT_COLS - LEFT_EYE_COL - EYE_WIDTH;
const MOUTH_WIDTH = 22;
const MOUTH_ROW = 26;
const MOUTH_COL = Math.floor((DOT_COLS - MOUTH_WIDTH) / 2);

const WAITING_MESSAGES = [
  "경로 확보 중",
  "안전 점검 중",
  "전달 시퀀스 준비",
  "시각 검증 준비"
];

const FAILURE_STAGES = new Set([
  "dispatch-failed",
  "execution-failed",
  "report-failed",
  "invalid",
  "missing"
]);

function buildHatBandExtra() {
  const bandRow = Math.max(0, EYE_ROW - 6);
  const width = (RIGHT_EYE_COL + EYE_WIDTH) - LEFT_EYE_COL;
  return {
    points: [
      ...rectCoords(bandRow, LEFT_EYE_COL - 3, 1, width + 6),
      ...rectCoords(bandRow + 1, LEFT_EYE_COL - 2, 1, width + 4)
    ]
  };
}

function buildSaluteHandExtra() {
  const startRow = EYE_ROW + 1;
  const startCol = RIGHT_EYE_COL + EYE_WIDTH - 3;
  return {
    points: [
      ...rectCoords(startRow - 1, startCol + 1, 1, 3),
      ...rectCoords(startRow, startCol, 1, 5),
      ...rectCoords(startRow + 1, startCol + 1, 1, 4),
      ...rectCoords(startRow + 2, startCol + 2, 1, 3)
    ]
  };
}

function buildSparkleExtra() {
  const coords = [
    [EYE_ROW - 6, LEFT_EYE_COL - 3],
    [EYE_ROW - 5, LEFT_EYE_COL - 5],
    [EYE_ROW - 4, LEFT_EYE_COL - 2],
    [EYE_ROW - 6, RIGHT_EYE_COL + EYE_WIDTH + 3],
    [EYE_ROW - 5, RIGHT_EYE_COL + EYE_WIDTH + 5],
    [EYE_ROW - 4, RIGHT_EYE_COL + EYE_WIDTH + 2]
  ];
  return {
    points: coordsIndices(coords),
    accent: true
  };
}

const STAGE_BASE_EXPRESSION = {
  queued: "focus",
  "detail-loading": "focus",
  "dispatch-ready": "focus",
  "await-local": "focus",
  "auto-dispatch": "smile",
  executing: "determined",
  completed: "smile",
  "dispatch-failed": "sad",
  "execution-failed": "sad",
  "report-failed": "sad",
  invalid: "sad",
  missing: "sad"
};

const LEFT_EYE = { row: EYE_ROW, col: LEFT_EYE_COL };
const RIGHT_EYE = { row: EYE_ROW, col: RIGHT_EYE_COL };
const MOUTH = { row: MOUTH_ROW, col: MOUTH_COL };

const EXPRESSIONS = {
  sleep: createExpression({ leftEye: "closed", rightEye: "closed", leftPupil: "none", rightPupil: "none", mouth: "neutral" }),
  idle: createExpression({ leftEye: "open", rightEye: "open", leftPupil: "center", rightPupil: "center", mouth: "soft-smile" }),
  focus: createExpression({ leftEye: "soft", rightEye: "soft", leftPupil: "center", rightPupil: "center", mouth: "neutral" }),
  determined: createExpression({ leftEye: "narrow", rightEye: "narrow", leftPupil: "center", rightPupil: "center", mouth: "soft-smile" }),
  lookLeft: createExpression({ leftEye: "open", rightEye: "open", leftPupil: "left", rightPupil: "left", mouth: "soft-smile" }),
  lookRight: createExpression({ leftEye: "open", rightEye: "open", leftPupil: "right", rightPupil: "right", mouth: "soft-smile" }),
  lookUp: createExpression({ leftEye: "open", rightEye: "open", leftPupil: "up", rightPupil: "up", mouth: "neutral" }),
  lookDown: createExpression({ leftEye: "open", rightEye: "open", leftPupil: "down", rightPupil: "down", mouth: "soft-smile" }),
  blink: createExpression({ leftEye: "closed", rightEye: "closed", leftPupil: "none", rightPupil: "none", mouth: "neutral" }),
  wink: createExpression({ leftEye: "open", rightEye: "closed", leftPupil: "center", rightPupil: "none", mouth: "soft-smile" }),
  winkLeft: createExpression({ leftEye: "closed", rightEye: "open", leftPupil: "none", rightPupil: "center", mouth: "soft-smile" }),
  grin: createExpression({ leftEye: "open", rightEye: "open", leftPupil: "center", rightPupil: "center", mouth: "open" }),
  smile: createExpression({ leftEye: "open", rightEye: "open", leftPupil: "center", rightPupil: "center", mouth: "smile" }),
  calm: createExpression({ leftEye: "soft", rightEye: "soft", leftPupil: "center", rightPupil: "center", mouth: "neutral" }),
  sad: createExpression({ leftEye: "soft", rightEye: "soft", leftPupil: "center", rightPupil: "center", mouth: "frown" }),
  sparkle: createExpression({ leftEye: "open", rightEye: "open", leftPupil: "center", rightPupil: "center", mouth: "soft-smile", extras: [buildSparkleExtra()] }),
  proud: createExpression({ leftEye: "soft", rightEye: "soft", leftPupil: "up", rightPupil: "up", mouth: "smile", extras: [buildHatBandExtra()] }),
  salute: createExpression({ leftEye: "soft", rightEye: "open", leftPupil: "center", rightPupil: "up", mouth: "smile", extras: [buildHatBandExtra(), buildSaluteHandExtra()] }),
  surprised: createExpression({ leftEye: "open", rightEye: "open", leftPupil: "center", rightPupil: "center", mouth: "open" })
};


const EXPRESSION_ALIASES = {
  happy: "smile",
  success: "smile",
  celebrate: "salute",
  saluting: "salute",
  proud: "proud",
  sparkle: "sparkle"
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
    exitBtn.hidden = true;
    exitBtn.disabled = false;
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

  updateStage("queued", "준비", "승인 확인");

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

  updateStage("dispatch-ready", "정렬", "시퀀스 구성");

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

  updateStage("await-local", "연결", "로컬 확인");

  if (!requiresManual || !localPayload) {
    updateStage("auto-dispatch", "자동 실행", "로봇 진행", { level: "success", expression: "smile" });
    invalidateRequestDetail(requestId);
    enableExit({ autoDelay: 12000 });
    return;
  }

  updateStage("executing", "동작", "로봇 제어");

  let localResult = context.localResult || null;
  if (!localResult) {
    try {
      const payloadTimeout = Number(localPayload?.timeoutMs);
      const timeoutMs = Number.isFinite(payloadTimeout) && payloadTimeout > 0
        ? Math.max(payloadTimeout, 180000)
        : 180000;
      localResult = await dispatchRobotViaLocal(localPayload, { timeoutMs });
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

  updateStage("completed", "완료", completionMessage, { level: "success", expression: "smile" });

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
  enableExit({ autoDelay: 45000 });
}

function updateStage(stageKey, label, message, { level = "info", expression } = {}) {
  currentStageKey = stageKey;
  const resolved = expression || STAGE_BASE_EXPRESSION[stageKey] || (level === "error" ? "sad" : level === "success" ? "smile" : "focus");
  setBaseExpression(resolved);
  if (stageKey === "executing") {
    startAmbientMessages(WAITING_MESSAGES);
  } else {
    stopAmbientMessages();
  }
  setStatus(label, message, level);
  if (stageKey === "completed") {
    playCelebrationSequence();
    return;
  }
  if (FAILURE_STAGES.has(stageKey)) {
    stopAmbientAnimations();
  } else {
    startAmbientAnimations();
  }
}

const MAX_STATUS_LENGTH = 160;

function normalizeText(value) {
  if (value === null || value === undefined) return "";
  const text = String(value);
  return typeof text.normalize === "function" ? text.normalize("NFC") : text;
}

function truncateStatus(text) {
  if (!text) return "";
  return text.length > MAX_STATUS_LENGTH ? `${text.slice(0, MAX_STATUS_LENGTH - 1)}…` : text;
}

function setStatus(label, message, level = "info") {
  statusLabel = normalizeText(label);
  statusMessage = normalizeText(message);
  ambientMessage = "";
  if (statusEl) {
    statusEl.setAttribute("data-level", level);
  }
  applyStatus();
}

function setAmbientText(text) {
  ambientMessage = normalizeText(text);
  applyStatus();
}

function applyStatus() {
  if (!statusEl) return;
  let full = "";
  if (ambientMessage) {
    full = ambientMessage;
  } else {
    const parts = [];
    if (statusLabel) parts.push(statusLabel);
    if (statusMessage && statusMessage !== statusLabel) parts.push(statusMessage);
    full = parts.join(" · ");
  }
  const safe = full || "\u00A0";
  const display = truncateStatus(safe);
  statusEl.textContent = display;
  statusEl.title = safe === "\u00A0" ? "" : safe;
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

function playCelebrationSequence() {
  stopAmbientAnimations();
  const fallback = resolveExpressionName(baseExpression === "sad" ? "smile" : baseExpression || "smile");
  applyExpression("salute");
  setTimeout(() => {
    setBaseExpression(fallback);
    applyExpression(fallback);
    if (!FAILURE_STAGES.has(currentStageKey)) {
      startAmbientAnimations();
      setTimeout(() => {
        playMicroExpression("wink", 260);
      }, 600);
    }
  }, 1400);
}

function pickAmbientExpressions() {
  const base = baseExpression;
  if (base === "sleep") return [];
  if (base === "sad") return ["blink", "lookLeft", "lookRight", "lookDown"];
  if (base === "smile") return ["blink", "wink", "winkLeft", "lookLeft", "lookRight", "sparkle"];
  if (base === "determined" || base === "focus") return ["blink", "lookLeft", "lookRight", "lookUp"];
  if (base === "calm") return ["blink", "lookLeft", "lookRight", "lookDown"];
  return ["blink", "lookLeft", "lookRight", "wink", "winkLeft", "lookUp", "lookDown", "sparkle", "proud"];
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
  setStatus("웨이크업", "에너지 주입");
  randomScatter(Math.floor(DOT_COUNT * 0.18));
  await wait(380);
  setStatus("웨이크업", "신호 정렬");
  randomScatter(Math.floor(DOT_COUNT * 0.48));
  await wait(420);
  setStatus("웨이크업", "형상 구축");
  randomScatter(Math.floor(DOT_COUNT * 0.72));
  await wait(420);
  applyExpression("blink");
  await wait(300);
  if (gridEl) gridEl.classList.remove("is-boot");
  if (screenEl) screenEl.dataset.scene = "active";
  setBaseExpression("idle");
  setStatus("준비", "웨이크업 완료");
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

function enableExit({ label = "사용자 페이지로 돌아가기", autoDelay = 45000 } = {}) {
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

  enableExit({ autoDelay: 45000 });
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

function normalizeExtra(extra) {
  if (!extra) return null;
  if (Array.isArray(extra)) {
    if (!extra.length) return null;
    const points = [];
    extra.forEach((value) => {
      if (typeof value === "number") {
        if (value >= 0 && value < DOT_COUNT) points.push(value);
      } else if (Array.isArray(value) && value.length >= 2) {
        points.push(...coordsIndices([value]));
      }
    });
    return points.length ? { points, accent: false } : null;
  }
  if (typeof extra === "object") {
    if (Array.isArray(extra.points)) {
      const filtered = extra.points.filter((value) => typeof value === "number" && value >= 0 && value < DOT_COUNT);
      if (filtered.length) {
        return { points: filtered, accent: !!extra.accent };
      }
    }
    if (Array.isArray(extra.coords)) {
      const converted = coordsIndices(extra.coords);
      if (converted.length) {
        return { points: converted, accent: !!extra.accent };
      }
    }
  }
  return null;
}

function createExpression({
  leftEye = "open",
  rightEye = "open",
  leftPupil = "center",
  rightPupil = "center",
  mouth = "neutral",
  extras = []
} = {}) {
  const on = new Set();
  const accent = new Set();

  const leftEyePixels = buildEye(LEFT_EYE, leftEye);
  const rightEyePixels = buildEye(RIGHT_EYE, rightEye);
  mergeInto(on, leftEyePixels);
  mergeInto(on, rightEyePixels);

  const leftPupilPixels = buildPupil(LEFT_EYE, leftPupil);
  const rightPupilPixels = buildPupil(RIGHT_EYE, rightPupil);
  mergeInto(accent, leftPupilPixels);
  mergeInto(accent, rightPupilPixels);
  mergeInto(on, leftPupilPixels);
  mergeInto(on, rightPupilPixels);

  mergeInto(on, buildMouth(mouth));

  const extraList = Array.isArray(extras) ? extras : [extras];
  extraList.forEach((extra) => {
    const normalized = normalizeExtra(extra);
    if (!normalized) return;
    mergeInto(on, normalized.points);
    if (normalized.accent) {
      mergeInto(accent, normalized.points);
    }
  });

  return Object.freeze({ on, accent });
}

function buildEye(anchor, mode = "open") {
  const { row, col } = anchor;
  if (mode === "closed") {
    return rectCoords(row + Math.floor(EYE_HEIGHT / 2), col, 1, EYE_WIDTH);
  }
  if (mode === "narrow") {
    return [
      ...rectCoords(row + 1, col + 1, 1, EYE_WIDTH - 2),
      ...rectCoords(row + 2, col, 1, EYE_WIDTH),
      ...rectCoords(row + 3, col + 1, 1, EYE_WIDTH - 2)
    ];
  }
  if (mode === "soft") {
    return [
      ...rectCoords(row, col + 1, 1, EYE_WIDTH - 2),
      ...rectCoords(row + 1, col, 1, EYE_WIDTH),
      ...rectCoords(row + 2, col, 1, EYE_WIDTH),
      ...rectCoords(row + 3, col + 1, 1, EYE_WIDTH - 2)
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
  if (mode === "smile") {
    return [
      ...rectCoords(row, col + 1, 1, width - 2),
      ...coordsIndices([
        [row - 1, col + 1],
        [row - 1, col + width - 2]
      ])
    ];
  }
  if (mode === "soft-smile") {
    return [
      ...rectCoords(row, col + 3, 1, width - 6),
      ...coordsIndices([
        [row - 1, col + 3],
        [row - 1, col + width - 4]
      ])
    ];
  }
  if (mode === "frown") {
    return [
      ...rectCoords(row, col + 1, 1, width - 2),
      ...coordsIndices([
        [row + 1, col + 1],
        [row + 1, col + width - 2]
      ])
    ];
  }
  if (mode === "open") {
    return rectCoords(row - 1, col + Math.floor((width - 3) / 2), 3, 3);
  }
  return rectCoords(row, col + 1, 1, width - 2);
}