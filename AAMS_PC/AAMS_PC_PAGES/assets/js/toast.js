export function toast(msg, type='info', timeout=2200){
  let box = document.getElementById('aams-toast-box');
  if (!box){ box = document.createElement('div'); box.id='aams-toast-box'; document.body.appendChild(box); }
  const t = document.createElement('div');
  t.className = `aams-toast ${type}`; t.textContent = msg;
  box.appendChild(t);
  setTimeout(()=>{ t.classList.add('hide'); setTimeout(()=>t.remove(), 400); }, timeout);
}
