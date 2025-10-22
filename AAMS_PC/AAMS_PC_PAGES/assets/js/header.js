import { injectHeader } from './dom.js';
import { guard, initHeaderRoleRouting, wireLogout } from './auth.js';

export async function bootHeader() {
  guard();
  await injectHeader();          // 1) 무조건 헤더 먼저 붙임
  initHeaderRoleRouting();
  wireLogout();

  // 2) health.js는 동적 import로 로드 실패해도 상단바는 유지
  try {
    const mod = await import('./health.js');
    if (mod?.initHealth) mod.initHealth();
  } catch (e) {
    // 상태 배지 텍스트만 안전하게 설정
    const pill = document.getElementById('status-pill');
    if (pill) {
      pill.dataset.state = 'degraded';
      const label = pill.querySelector('.label');
      if (label) label.textContent = '상태 확인 불가';
    }
    console.warn('health.js 로드 실패:', e);
  }
}