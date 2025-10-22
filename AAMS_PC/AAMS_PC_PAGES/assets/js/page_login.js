import { API_BASE } from './config.js';
import { toast } from './toast.js';

// 로그인 폼 요소
const form = document.getElementById('login-form');
const msg  = document.getElementById('login-msg');
const idEl = document.getElementById('username');
const pwEl = document.getElementById('password');

// 과거/현재 백엔드 호환: /api/auth/login → /api/login 둘 다 시도
async function tryLogin(body){
  const endpoints = ['/api/auth/login', '/api/login'];
  let lastErr;
  for (const ep of endpoints){
    try{
      const res = await fetch(API_BASE + ep, {
        method: 'POST',
        headers: { 'Content-Type':'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json(); // {id,name,is_admin,rank,unit,position,user_id...}
    }catch(e){ lastErr = e; }
  }
  throw lastErr || new Error('로그인 실패');
}

form?.addEventListener('submit', async (e)=>{
  e.preventDefault();
  msg.textContent = '';

  const user_id  = (idEl.value || '').trim();
  const password = pwEl.value || '';

  if (!user_id || !password){
    msg.textContent = '아이디/비밀번호를 입력하세요.';
    return;
  }

  try{
    const user = await tryLogin({ user_id, password });

    // 세션 저장 (사이트 전반과 호환되는 키로 저장)
    sessionStorage.setItem('auth', JSON.stringify({
      id: user.id,
      name: user.name,
      user_id: user.user_id,
      is_admin: !!user.is_admin,
      rank: user.rank,
      unit: user.unit,
      position: user.position,
      ts: Date.now(),
    }));

    // 권한 분기
    location.replace(user.is_admin ? 'main_page_new_test.html' : 'main_page_user_new_test.html');
  }catch(e){
    console.error(e);
    msg.textContent = '아이디 또는 비밀번호가 올바르지 않습니다.';
    toast('로그인 실패: 자격 증명을 확인하세요','error');
  }
});
