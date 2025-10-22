import { currentUser } from './auth.js';
import { api } from './config.js';

function $(sel, root=document){ return root.querySelector(sel); }

function setWelcomeName(){
  const auth = currentUser();
  const name = auth?.name || auth?.user_name || auth?.user_id || '사용자';
  const who = $('#who'); if (who) who.textContent = name;
}

async function fetchJson(url, timeoutMs=5000){
  const ctrl = new AbortController();
  const t = setTimeout(()=>ctrl.abort(), timeoutMs);
  try{
    const res = await fetch(url, { headers:{'Accept':'application/json'}, signal: ctrl.signal });
    const ok = res.ok;
    let data=null; try{ data = await res.json(); }catch{}
    return { ok, data, status: res.status };
  }catch(e){
    return { ok:false, error: String(e) };
  }finally{ clearTimeout(t); }
}

function setLabel(pill, text){
  if(!pill) return;
  const el = pill.querySelector('.label');
  if (el) el.textContent = text;
}

async function checkHealth(){
  const pill = $('#status-pill'); if(!pill) return;
  pill.dataset.state = 'checking';
  setLabel(pill, '점검중…');

  const t0 = performance.now();
  const [h, db] = await Promise.all([
    fetchJson(api('/health'), 4000),
    fetchJson(api('/health/db'), 5000)
  ]);
  const latency = Math.round(performance.now() - t0);

  const httpOK = !!(h && h.ok && h.data && (h.data.ok===true));
  const dbOK   = !!(db && db.ok && db.data && (db.data.db || db.data.firearms_total!==undefined));

  let state = 'online';
  if(!httpOK && !dbOK) state='offline';
  else if(!httpOK || !dbOK || latency > 1200) state='degraded'; // 약간 여유

  pill.dataset.state = state;
  const label = (state==='online'?'시스템 정상': state==='degraded'?'부분지연':'접속오류');
  setLabel(pill, label);

  const httpNode = $('#h-http');
  const dbNode = $('#h-db');
  const latNode = $('#h-latency');
  if(httpNode){ httpNode.textContent = httpOK?'OK':'ERR'; httpNode.className = httpOK?'ok':'err'; }
  if(dbNode){
    if(dbOK){
      const t = db.data || {};
      dbNode.textContent = `OK · ${t.db_user || 'db'}@${t.db || ''} · 총기:${t.firearms_total ?? '-'} · 탄약:${t.ammo_total ?? '-'}`;
      dbNode.className='ok';
    }else{ dbNode.textContent='ERR'; dbNode.className='err'; }
  }
  if(latNode){ latNode.textContent = `${latency} ms`; latNode.className = (latency>1200?'warn':'ok'); }
}

export function initHealth(){
  setWelcomeName();
  checkHealth();
  setInterval(checkHealth, 60000);
}