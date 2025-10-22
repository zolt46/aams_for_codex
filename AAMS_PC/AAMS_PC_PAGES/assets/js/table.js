export function mountSelectAll(tbody, selectedIds, updateSelectedCount) {
  const selAll = document.getElementById('select-all');
  if (!selAll) return;
  selAll.addEventListener('change', () => {
    const allChecks = tbody.querySelectorAll('input.row-select[type="checkbox"]');
    selectedIds.clear();
    allChecks.forEach(cb => { cb.checked = selAll.checked; const rid = cb.dataset.id; if (selAll.checked) selectedIds.add(rid); });
    updateSelectedCount?.();
  });
}
export function addSelectHeader(table) {
  const tr = table.querySelector('thead tr');
  if (!tr || (tr.firstElementChild?.classList?.contains('select-col'))) return;
  const th = document.createElement('th');
  th.classList.add('select-col'); th.style.width = '44px';
  th.innerHTML = `<input type="checkbox" id="select-all"/>`;
  tr.insertBefore(th, tr.firstElementChild);
}
export function statusBadge(td, value) {
  const s = document.createElement('span');
  s.className = `status-badge ${value}`;
  s.textContent = value;
  td.appendChild(s);
}
