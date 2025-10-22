import { toast } from './toast.js';

export async function injectModal(){
  if (document.getElementById('aams-modal')) return;
  const div = document.createElement('div');
  const html = await fetch('components/modal.html').then(r=>r.text());
  div.innerHTML = html;
  document.body.appendChild(div.firstElementChild);
  const modal = document.getElementById('aams-modal');
  modal.addEventListener('click', e => { if (e.target.closest('[data-close]')) closeModal(); });
}
export function openModal({ title='상세', body='', onSave=null }){
  const modal = document.getElementById('aams-modal');
  document.getElementById('aams-modal-title').textContent = title;
  document.getElementById('aams-modal-body').innerHTML   = body;
  modal.hidden = false;
  const saveBtn = document.getElementById('aams-modal-save');
  saveBtn.onclick = async () => {
    try { if (onSave) await onSave(); closeModal(); } catch(e){ toast(String(e.message||e),'error'); }
  };
}
export function closeModal(){ const modal = document.getElementById('aams-modal'); if (modal) modal.hidden = true; }
