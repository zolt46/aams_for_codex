import { API_BASE } from './config.js';
import { toast } from './toast.js';

async function handle(res){
  if (!res.ok){
    let msg = `HTTP ${res.status}`;
    try { const j = await res.json(); if (j?.message) msg = j.message; } catch {}
    throw new Error(msg);
  }
  const ct = res.headers.get('content-type')||'';
  return ct.includes('application/json') ? res.json() : res.text();
}
export const apiGet  = (p)             => fetch(`${API_BASE}${p}`).then(handle);
export const apiPost = (p, body)       => fetch(`${API_BASE}${p}`, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) }).then(handle);
export const apiPut  = (p, body)       => fetch(`${API_BASE}${p}`, { method:'PUT',  headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) }).then(handle);
export const apiDel  = (p)             => fetch(`${API_BASE}${p}`, { method:'DELETE' }).then(handle);

export async function safeDo(fn, okMsg){
  try{
    const r = await fn();
    if (okMsg) toast(okMsg,'success');
    return r;
  }catch(e){
    toast(`오류: ${e.message||e}`,'error');
    console.error(e);
    throw e;
  }
}
