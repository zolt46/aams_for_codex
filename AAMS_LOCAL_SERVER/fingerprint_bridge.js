/**
 * fingerprint_bridge.js  — Render 서버 ↔ 로컬 장비 브릿지
 *
 * 기능 요약
 *  - 시리얼 포트를 통해 아두이노 지문 센서를 제어하고 결과를 Render 서버로 전달
 *  - HTTP /health, /identify/start, /identify/stop, /led 엔드포인트를 제공하여
 *    TAB 단말에서 로컬 브릿지 상태 확인 및 지문 인식 세션을 온디맨드로 시작/종료
 *  - AUTO_IDENTIFY=1 설정 시 기존처럼 연속 Identify 루프 유지, 기본값은 필요 시에만 스캔
 *
 * 필요한 패키지: serialport, @serialport/parser-readline, ws, dotenv
 */

require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const { SerialPort } = require('serialport');
const { ReadlineParser } = require('@serialport/parser-readline');
const WebSocket = require('ws');
const http = require('http');
const { URL } = require('url');

const PORT_HINT      = process.env.FINGERPRINT_PORT || 'auto';
const BAUD           = Number(process.env.FINGERPRINT_BAUD || 115200);
const AUTO_IDENTIFY  = (process.env.AUTO_IDENTIFY || '0') === '1';
const IDENTIFY_BACKOFF_MS = Number(process.env.IDENTIFY_BACKOFF_MS || 300);

const FORWARD_URL    = process.env.RENDER_FP_URL || '';
const FORWARD_TOKEN  = process.env.RENDER_FP_TOKEN || '';
const FP_SITE        = process.env.FP_SITE || 'default';

const LOCAL_PORT     = Number(process.env.LOCAL_PORT || process.env.FP_LOCAL_PORT || 8790);

const DEBUG_WS       = (process.env.DEBUG_WS || '') === '1';
const DEBUG_WS_PORT  = Number(process.env.DEBUG_WS_PORT || 8787);

const DEFAULT_LED_ON = { mode: 'breathing', color: 'blue', speed: 18 };
const DEFAULT_LED_OFF = { mode: 'off' };

function log(...args){ console.log('[fp-bridge]', ...args); }
function warn(...args){ console.warn('[fp-bridge]', ...args); }
const sleep = (ms)=>new Promise((resolve)=>setTimeout(resolve, ms));

let serial = null;
let parser = null;
let lastGoodPath = null;
let reconnecting = false;
let identifyLoopRunning = false;
let closedByUs = false;

let manualSession = null;
let manualSessionCounter = 0;
let manualIdentifyRequested = false;
let manualIdentifyDeadline = 0;

const forwardStatus = { enabled: !!FORWARD_URL, lastOkAt: 0, lastErrorAt: 0 };
const ledState = { mode: null, color: null, speed: null, cycles: null, ok: null, pending: false, lastCommandAt: 0 };
let lastIdentifyEvent = null;
let lastIdentifyAt = 0;
let lastSerialEventAt = 0;

const timeNow = () => Date.now();

async function listCandidates(){
  const ports = await SerialPort.list();
  const preferred = [];
  const normal = [];
  for (const p of ports){
    const manufacturer = (p.manufacturer || '').toLowerCase();
    const vendor = (p.vendorId || '').toLowerCase();
    const isUsb = manufacturer.includes('arduino') || manufacturer.includes('wch') || manufacturer.includes('silicon labs') || manufacturer.includes('ftdi') || vendor === '2341' || vendor === '1a86' || vendor === '10c4' || vendor === '0403';
    (isUsb ? preferred : normal).push(p);
  }
  const ordered = [];
  if (lastGoodPath){
    const all = [...preferred, ...normal];
    const found = all.find(p => p.path === lastGoodPath);
    if (found) ordered.push(found);
  }
  for (const p of [...preferred, ...normal]){
    if (!ordered.find(x => x.path === p.path)) ordered.push(p);
  }
  return ordered;
}

async function tryOpen(path){
  const port = new SerialPort({ path, baudRate: BAUD, autoOpen: false });
  const lineParser = port.pipe(new ReadlineParser({ delimiter: '\n' }));
  await new Promise((resolve, reject) => port.open(err => err ? reject(err) : resolve()));
  log(`opened serial ${path}@${BAUD}`);
  return { port, lineParser };
}

async function findAndOpen(){
  if (PORT_HINT !== 'auto'){
    try { return await tryOpen(PORT_HINT); }
    catch (err) { warn('explicit port failed:', err.message || err); }
  }
  const candidates = await listCandidates();
  for (const entry of candidates){
    try { return await tryOpen(entry.path); }
    catch (err) { warn('candidate open failed:', entry.path, err.message || err); }
  }
  throw new Error('no usable serial port found');
}

function writeSerial(obj){
  if (!serial || !serial.isOpen) return false;
  try {
    serial.write(JSON.stringify(obj) + '\n');
    return true;
  } catch (err) {
    warn('serial write failed:', err.message || err);
    return false;
  }
}

async function forwardToRender(obj){
  if (!FORWARD_URL || !FORWARD_TOKEN) return;
  try {
    const res = await fetch(FORWARD_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-fp-token': FORWARD_TOKEN
      },
      body: JSON.stringify({ site: FP_SITE, data: obj })
    });
    if (!res.ok){
      forwardStatus.lastErrorAt = timeNow();
      const text = await res.text().catch(() => '');
      warn('forward failed:', res.status, res.statusText, text || '');
    } else {
      forwardStatus.lastOkAt = timeNow();
    }
  } catch (err) {
    forwardStatus.lastErrorAt = timeNow();
    warn('forward error:', err.message || err);
  }
}

let wsServer = null;
function setupDebugWS(){
  if (!DEBUG_WS) return;
  wsServer = new WebSocket.Server({ port: DEBUG_WS_PORT });
  wsServer.on('connection', ws => {
    ws.send(JSON.stringify({ hello: 'fp-bridge', version: 'bridge-2.0' }));
    ws.on('message', buf => {
      let obj;
      try { obj = JSON.parse(String(buf)); }
      catch { return; }
      writeSerial(obj);
    });
  });
  log(`debug ws on ws://localhost:${DEBUG_WS_PORT}`);
}

function wsBroadcast(obj){
  if (!wsServer) return;
  const payload = JSON.stringify(obj);
  wsServer.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN){
      client.send(payload);
    }
  });
}

function normalizeLedCommand(cmd){
  if (!cmd || typeof cmd !== 'object') return null;
  const out = {};
  if (cmd.mode) out.mode = String(cmd.mode);
  else if (cmd.state) out.mode = String(cmd.state);
  if (cmd.color) out.color = String(cmd.color);
  if (cmd.speed !== undefined) out.speed = Number(cmd.speed);
  else if (cmd.brightness !== undefined) out.speed = Number(cmd.brightness);
  if (cmd.cycles !== undefined) out.cycles = Number(cmd.cycles);
  return out;
}

function applyLedCommand(command){
  const payload = normalizeLedCommand(command);
  if (!payload) return false;
  const ok = writeSerial({ cmd: 'led', ...payload });
  ledState.mode = payload.mode || ledState.mode;
  ledState.color = payload.color || ledState.color;
  if (payload.speed !== undefined && !Number.isNaN(payload.speed)) ledState.speed = payload.speed;
  if (payload.cycles !== undefined && !Number.isNaN(payload.cycles)) ledState.cycles = payload.cycles;
  ledState.lastCommandAt = timeNow();
  ledState.pending = true;
  if (!ok){
    ledState.ok = false;
    ledState.pending = false;
  }
  return ok;
}

function manualIdentifyActive(){
  if (!manualIdentifyRequested) return false;
  if (manualIdentifyDeadline && timeNow() > manualIdentifyDeadline){
    stopManualIdentify('timeout', { turnOffLed: true });
    return false;
  }
  return true;
}

function shouldIdentify(){
  return AUTO_IDENTIFY || manualIdentifyActive();
}

function startManualIdentify(options = {}){
  if (manualSession && manualSession.active){
    stopManualIdentify('replaced', { turnOffLed: false });
  }
  manualSessionCounter += 1;
  const startAt = timeNow();
  const timeoutMs = Math.max(3000, Number(options.timeoutMs) || 60000);
  const ledOn = options.led === false ? null : (normalizeLedCommand(options.led) || DEFAULT_LED_ON);
  const ledOff = options.ledOff === false ? null : (normalizeLedCommand(options.ledOff || options.onStopLed) || DEFAULT_LED_OFF);

  manualSession = {
    id: manualSessionCounter,
    requestedAt: startAt,
    deadline: startAt + timeoutMs,
    options: { ledOn, ledOff, site: options.site || null },
    active: true,
    reason: null
  };

  manualIdentifyRequested = true;
  manualIdentifyDeadline = manualSession.deadline;

  if (ledOn) applyLedCommand(ledOn);

  return manualSession;
}

function stopManualIdentify(reason = 'manual_stop', { turnOffLed = true, ledOverride = null } = {}){
  if (manualSession){
    manualSession.active = false;
    manualSession.reason = reason;
    manualSession.stoppedAt = timeNow();
  }
  manualIdentifyRequested = false;
  manualIdentifyDeadline = 0;

  const target = ledOverride ? normalizeLedCommand(ledOverride) : (manualSession?.options?.ledOff || DEFAULT_LED_OFF);
  if (turnOffLed && target){
    applyLedCommand(target);
  }
  return manualSession;
}


function waitForIdentifyResult(timeoutMs){
  return new Promise(resolve => {
    let done = false;
    const timer = setTimeout(() => {
      if (!done){
        done = true;
        cleanup();
        resolve(null);
      }
    }, timeoutMs);

    const handler = (obj) => {
      if (done) return;
      const ok = obj && obj.ok === true && obj.type === 'identify';
      const err = obj && obj.ok === false && (
        obj.error === 'timeout_or_no_finger' ||
        obj.error === 'image2tz_failed' ||
        obj.error === 'search_error' ||
        obj.error === 'no_match'
      );
      if (ok || err){
        done = true;
        clearTimeout(timer);
        cleanup();
        resolve(obj);
      }
    };

    const cleanup = () => parser?.off('dataLine', handler);
    parser?.on('dataLine', handler);
  });
}

async function identifyLoop(){
  if (identifyLoopRunning) return;
  identifyLoopRunning = true;
  while (!closedByUs){
    try {
      if (!serial || !serial.isOpen){
        await sleep(250);
        continue;
      }
      if (!shouldIdentify()){
        await sleep(120);
        continue;
      }
      const wrote = writeSerial({ cmd: 'identify' });
      if (!wrote){
        await sleep(400);
        continue;
      }
      await waitForIdentifyResult(9000);
      await sleep(IDENTIFY_BACKOFF_MS);
    } catch (err) {
      warn('identify loop error:', err.message || err);
      await sleep(600);
    }
  }
  identifyLoopRunning = false;
}


async function openAndWire(){
  const { port, lineParser } = await findAndOpen();
  serial = port;
  parser = lineParser;
  lastGoodPath = port.path;

  try { serial.write('{"cmd":"open"}\n'); } catch (err) { warn('write open failed:', err.message || err); }

  parser.on('data', raw => {
    const line = String(raw || '').trim();
    if (!line) return;
    let obj;
    try { obj = JSON.parse(line); }
    catch { obj = { raw: line }; }
    parser.emit('dataLine', obj);
    lastSerialEventAt = timeNow();

    if (obj && obj.type === 'identify'){
      lastIdentifyEvent = { ...obj };
      lastIdentifyAt = timeNow();
      if (obj.ok) stopManualIdentify('matched', { turnOffLed: true });
    }
    if (obj && obj.type === 'led'){
      ledState.mode = obj.mode || obj.state || ledState.mode;
      if (obj.color) ledState.color = obj.color;
      if (obj.speed !== undefined) ledState.speed = obj.speed;
      if (obj.cycles !== undefined) ledState.cycles = obj.cycles;
      ledState.ok = obj.ok !== false;
      ledState.pending = false;
      ledState.lastCommandAt = timeNow();
    }
    if (obj && obj.error === 'led_failed'){
      ledState.ok = false;
      ledState.pending = false;
      ledState.lastCommandAt = timeNow();
    }

    wsBroadcast(obj);
    forwardToRender(obj);
    if (obj.type === 'identify' || obj.error) {
      log('sensor:', JSON.stringify(obj));
    }
  });

  serial.on('close', () => {
    if (closedByUs) return;
    warn('serial closed; reconnecting...');
    reconnect();
  });
  serial.on('error', err => {
    warn('serial error:', err.message || err);
    try { serial.close(); } catch (_) {}
  });
}

async function reconnect(){
  if (reconnecting) return;
  reconnecting = true;
  try {
    await sleep(1000);
    await openAndWire();
  } catch (err) {
    warn('reconnect fail:', err.message || err);
    reconnecting = false;
    await sleep(1500);
    return reconnect();
  }
  reconnecting = false;
}

function buildHealthPayload(){
  const manualActive = manualIdentifyActive();
  return {
    ok: true,
    time: timeNow(),
    serial: {
      connected: !!(serial && serial.isOpen),
      path: (serial && serial.path) || lastGoodPath || null,
      lastEventAt: lastSerialEventAt || null
    },
    identify: {
      auto: AUTO_IDENTIFY,
      running: identifyLoopRunning,
      manual: manualSession ? {
        active: manualActive,
        id: manualSession.id,
        requestedAt: manualSession.requestedAt,
        deadline: manualSession.deadline,
        reason: manualSession.reason || null
      } : { active: false },
      last: lastIdentifyEvent ? { ...lastIdentifyEvent, at: lastIdentifyAt } : null
    },
    led: { ...ledState },
    forward: { ...forwardStatus }
  };
}

function applyCors(res){
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function sendJson(res, status, payload){
  applyCors(res);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload ?? {}));
}

async function readJson(req){
  const chunks = [];
  for await (const chunk of req){ chunks.push(chunk); }
  if (!chunks.length) return {};
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch (err) {
    const error = new Error('invalid_json');
    error.statusCode = 400;
    error.message = err.message || 'invalid_json';
    throw error;
  }
}

async function handleHttpRequest(req, res){
  applyCors(res);
  if (req.method === 'OPTIONS'){
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  try {
    if (req.method === 'GET' && pathname === '/health'){
      return sendJson(res, 200, buildHealthPayload());
    }

    if (req.method === 'POST' && pathname === '/identify/start'){
      const body = await readJson(req);
      const session = startManualIdentify({
        timeoutMs: body?.timeoutMs,
        led: body?.led,
        ledOff: body?.ledOff || body?.onStopLed,
        site: body?.site
      });
      identifyLoop();
      return sendJson(res, 200, {
        ok: true,
        session: {
          id: session.id,
          requestedAt: session.requestedAt,
          deadline: session.deadline
        },
        serial: {
          connected: !!(serial && serial.isOpen),
          path: (serial && serial.path) || lastGoodPath || null
        },
        led: { ...ledState }
      });
    }

    if (req.method === 'POST' && pathname === '/identify/stop'){
      const body = await readJson(req);
      const turnOffLed = body?.led === false ? false : true;
      const ledOverride = (turnOffLed && body && typeof body.led === 'object') ? body.led : null;
      const session = stopManualIdentify(body?.reason || 'manual_stop', { turnOffLed, ledOverride });
      return sendJson(res, 200, {
        ok: true,
        session: session ? {
          id: session.id,
          active: session.active,
          reason: session.reason || null,
          stoppedAt: session.stoppedAt || null
        } : null,
        led: { ...ledState }
      });
    }

    if (req.method === 'POST' && pathname === '/led'){
      const body = await readJson(req);
      const ok = applyLedCommand(body);
      return sendJson(res, ok ? 200 : 503, {
        ok,
        led: { ...ledState },
        serial: { connected: !!(serial && serial.isOpen) }
      });
    }

    return sendJson(res, 404, { ok: false, error: 'not_found' });
  } catch (err) {
    const status = err?.statusCode || 500;
    return sendJson(res, status, { ok: false, error: err.message || 'server_error' });
  }
}

function startHttpServer(){
  const server = http.createServer(handleHttpRequest);
  server.listen(LOCAL_PORT, '0.0.0.0', () => {
    log(`local HTTP bridge listening on http://0.0.0.0:${LOCAL_PORT}`);
  });
  server.on('error', err => warn('http server error:', err.message || err));
}

log('env:', {
  PORT_HINT,
  BAUD,
  AUTO_IDENTIFY,
  IDENTIFY_BACKOFF_MS,
  FORWARD_URL: FORWARD_URL ? '[set]' : '',
  FP_SITE,
  LOCAL_PORT,
  DEBUG_WS,
  DEBUG_WS_PORT
});

setupDebugWS();
startHttpServer();
identifyLoop().catch(err => warn('identify loop exited:', err?.message || err));

(async () => {
  try {
    await openAndWire();
  } catch (err) {
    warn('initial open failed:', err.message || err);
    await reconnect();
  }

  process.on('SIGINT', async () => {
    closedByUs = true;
    try { serial?.isOpen && serial.close(); } catch (_) {}
    process.exit(0);
  });
})();
