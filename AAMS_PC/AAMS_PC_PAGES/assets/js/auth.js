export function guard() {
  try {
    const raw = sessionStorage.getItem('auth');
    if (!raw) location.replace('index.html');
  } catch {
    sessionStorage.removeItem('auth');
    location.replace('index.html');
  }
}

export function currentUser() {
  try { return JSON.parse(sessionStorage.getItem('auth') || '{}'); }
  catch { return {}; }
}

export function initHeaderRoleRouting() {
  const auth = currentUser();

  // 환영 인사
  const who = document.getElementById('who');
  if (who) who.textContent = auth?.name || (auth?.is_admin ? '관리자' : '사용자');

  // 로고 링크: 역할별 메인페이지로 강제
  const logo = document.getElementById('logoLink');
  if (logo) {
    logo.setAttribute('href', auth?.is_admin ? 'main_page_new_test.html' : 'main_page_user_new_test.html');
  }

  // 혹시 남아있는 탭이 있다면 안전하게 제거 (청소용)
  document.querySelectorAll('.tabs').forEach(el => el.remove());
}

export function wireLogout() {
  const btn = document.getElementById('logoutBtn');
  if (btn) btn.addEventListener('click', e => {
    e.preventDefault();
    try { sessionStorage.removeItem('auth'); } catch {}
    location.replace('index.html');
  });
}
