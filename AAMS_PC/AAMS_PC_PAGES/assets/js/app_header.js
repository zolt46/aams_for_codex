// ===== AAMS_UI Topbar: Welcome + Live Health =====
(function(){
  const API_BASE = ''; // same origin

  function $(sel, root=document){ return root.querySelector(sel); }
  function el(tag, attrs={}){
    const n=document.createElement(tag);
    Object.entries(attrs).forEach(([k,v])=>{
      if(k==='class') n.className=v;
      else if(k==='text') n.textContent=v;
      else if(k.startsWith('on') && typeof v==='function') n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v);
    });
    return n;
  }

  // UI mount (idempotent)
  function mountTopbar(){
    let wrap = $('.aams-topbar-right');
    if(!wrap){
      // Try to find a right area in an existing top bar/nav
      const nav = document.querySelector('.topbar, header, .navbar, .app-header') || document.body;
      wrap = el('div', { class:'aams-topbar-right' });
      nav.appendChild(wrap);
    }

    // Welcome
    let wb = $('#aams-welcome');
    if(!wb){
      wb = el('span', { id:'aams-welcome', class:'welcome-badge' });
      wb.innerHTML = '환영합니다,&nbsp;<b id="aams-welcome-name">사용자</b><small>님</small>';
      wrap.appendChild(wb);
    }

    // Status
    let sw = $('#aams-status-wrap');
    if(!sw){
      sw = el('span', { id:'aams-status-wrap', class:'status-wrap' });
      const pill = el('span', { id:'aams-status', class:'status-pill', 'data-state':'checking' });
      pill.innerHTML = '<span class="dot"></span><span class="label">상태 확인중…</span>';
      const extra = el('div', { class:'status-extra', id:'aams-status-extra' });
      extra.innerHTML = '<div class="row"><span>서버</span><strong id="aams-h-http" class="muted">—</strong></div>' +
                        '<div class="row"><span>DB</span><strong id="aams-h-db" class="muted">—</strong></div>' +
                        '<div class="row"><span>지연</span><strong id="aams-h-latency" class="muted">—</strong></div>';
      sw.appendChild(pill); sw.appendChild(extra);
      wrap.appendChild(sw);
    }
  }

  function setWelcomeName(name){
    const n = $('#aams-welcome-name');
    if(n) n.textContent = name || '사용자';
  }

  // Simple fetch with timeout
  async function fetchJson(url, {timeoutMs=5000}={}){
    const ctrl = new AbortController();
    const t = setTimeout(()=>ctrl.abort(), timeoutMs);
    try{
      const res = await fetch(url, { signal: ctrl.signal, headers:{'Accept':'application/json'} });
      const ok = res.ok;
      let data=null;
      try{ data = await res.json(); }catch(e){ /* ignore */ }
      return { ok, data, status: res.status };
    }catch(e){
      return { ok:false, error: String(e) };
    }finally{ clearTimeout(t); }
  }

  async function checkHealth(){
    const pill = $('#aams-status'); const extra = $('#aams-status-extra');
    if(!pill) return;

    pill.dataset.state='checking';
    $('.label', pill).textContent = '점검중…';

    const t0 = performance.now();
    const [h, db] = await Promise.all([
      fetchJson('/health', {timeoutMs:4000}),
      fetchJson('/health/db', {timeoutMs:5000})
    ]);
    const latency = Math.round(performance.now() - t0);

    // Decide state
    const httpOK = !!(h && h.ok && h.data && (h.data.ok===true));
    const dbOK   = !!(db && db.ok && db.data && (db.data.db || db.data.firearms_total!==undefined));

    let state = 'online';
    if(!httpOK && !dbOK) state='offline';
    else if(!httpOK || !dbOK || latency > 800) state='degraded';

    pill.dataset.state = state;
    const label = (state==='online'?'정상':
                   state==='degraded'?'부분지연':'접속오류');
    $('.label', pill).textContent = `시스템 ${label}`;

    // Tooltip details
    const httpLabel = httpOK ? 'OK' : 'ERR';
    const dbLabel   = dbOK   ? 'OK' : 'ERR';
    const httpNode = document.getElementById('aams-h-http');
    const dbNode = document.getElementById('aams-h-db');
    const latNode = document.getElementById('aams-h-latency');
    if(httpNode){ httpNode.textContent = httpLabel; httpNode.className = httpOK?'ok':'err'; }
    if(dbNode){
      if(dbOK){
        const t = db.data;
        dbNode.textContent = `OK · ${t.db_user || 'db'}@${t.db || ''} · 총기:${t.firearms_total ?? '-'} · 탄약:${t.ammo_total ?? '-'}`;
        dbNode.className='ok';
      }else{ dbNode.textContent='ERR'; dbNode.className='err'; }
    }
    if(latNode){ latNode.textContent = `${latency} ms`; latNode.className = (latency>800?'warn':'ok'); }
  }

  function loadUserFromStorage(){
    try{
      const raw = localStorage.getItem('aams.currentUser');
      if(raw){
        const u = JSON.parse(raw);
        return u?.name || u?.user_name || u?.user_id || null;
      }
    }catch(e){}
    // Fallback: try dataset on body
    const el = document.querySelector('[data-user-name]');
    return el ? el.getAttribute('data-user-name') : null;
  }

  function init(){
    mountTopbar();
    setWelcomeName(loadUserFromStorage());
    checkHealth();
    // refresh every 60s
    setInterval(checkHealth, 60000);
  }

  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();