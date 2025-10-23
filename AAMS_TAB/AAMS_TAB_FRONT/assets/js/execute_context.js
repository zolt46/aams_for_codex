const STORAGE_KEY = 'AAMS_EXECUTE_CONTEXT';

function safeStorage() {
  try {
    if (typeof window === 'undefined') return null;
    if (!window.sessionStorage) return null;
    return window.sessionStorage;
  } catch (err) {
    console.warn('[AAMS][execute] sessionStorage unavailable:', err?.message || err);
    return null;
  }
}

function sanitize(value) {
  if (value === undefined) {
    return undefined;
  }
  if (value === null) {
    return null;
  }
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => sanitize(entry)).filter((entry) => entry !== undefined);
  }
  if (typeof value === 'object') {
    try {
      return JSON.parse(JSON.stringify(value));
    } catch (err) {
      console.warn('[AAMS][execute] sanitize failed:', err?.message || err);
      return null;
    }
  }
  return null;
}

function applyDefaults(context = {}) {
  const base = { ...context };
  if (base.requestId !== undefined && base.requestId !== null) {
    base.requestId = String(base.requestId);
  }
  base.createdAt = base.createdAt || Date.now();
  base.state = base.state || 'pending';
  if (base.row !== undefined) base.row = sanitize(base.row);
  if (base.detail !== undefined) base.detail = sanitize(base.detail);
  if (base.executor !== undefined) base.executor = sanitize(base.executor);
  if (base.dispatch !== undefined) base.dispatch = sanitize(base.dispatch);
  if (base.serverResult !== undefined) base.serverResult = sanitize(base.serverResult);
  if (base.localPayload !== undefined) base.localPayload = sanitize(base.localPayload);
  if (base.localResult !== undefined) base.localResult = sanitize(base.localResult);
  if (base.error !== undefined) base.error = sanitize(base.error);
  base.failureReported = !!base.failureReported;
  base.completionReported = !!base.completionReported;
  return pruneUndefined(base);
}

function pruneUndefined(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const next = {};
  Object.entries(obj).forEach(([key, val]) => {
    if (val === undefined) return;
    next[key] = val;
  });
  return next;
}

export function loadExecuteContext() {
  const store = safeStorage();
  if (!store) return null;
  try {
    const raw = store.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return parsed || null;
  } catch (err) {
    console.warn('[AAMS][execute] failed to load context:', err?.message || err);
    try { store.removeItem(STORAGE_KEY); } catch (_) {}
    return null;
  }
}

export function setExecuteContext(context) {
  const store = safeStorage();
  if (!store) return null;
  const prepared = applyDefaults(context || {});
  try {
    store.setItem(STORAGE_KEY, JSON.stringify(prepared));
  } catch (err) {
    console.warn('[AAMS][execute] failed to store context:', err?.message || err);
  }
  return prepared;
}

export function updateExecuteContext(updater) {
  const current = loadExecuteContext() || {};
  const next = typeof updater === 'function'
    ? updater({ ...current })
    : { ...current, ...updater };
  return setExecuteContext(next);
}

export function clearExecuteContext() {
  const store = safeStorage();
  if (!store) return;
  try { store.removeItem(STORAGE_KEY); } catch (err) {
    console.warn('[AAMS][execute] failed to clear context:', err?.message || err);
  }
}