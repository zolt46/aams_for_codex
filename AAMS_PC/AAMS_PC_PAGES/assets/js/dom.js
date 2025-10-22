export async function injectHeader() {
  if (document.querySelector('.main-header')) return;
  const wrap = document.createElement('div');
  const resp = await fetch('components/header.html');
  wrap.innerHTML = await resp.text();
  document.body.prepend(wrap.firstElementChild);
}

// 보조 유틸은 그대로 유지
export const fmtDateTime = (iso) =>
  !iso ? '' : new Date(iso).toISOString().slice(0,16).replace('T',' ');
