export const kType = t => t==='DISPATCH' ? '불출' : (t==='RETURN' ? '불입' : t);
export const kStatus = s => ({SUBMITTED:'제출',APPROVED:'승인됨',REJECTED:'거부됨',EXECUTED:'집행됨',CANCELLED:'취소됨'}[s]||s);
export const statusClass = s => ({SUBMITTED:'b-submitted',APPROVED:'b-approved',REJECTED:'b-rejected',EXECUTED:'b-executed',CANCELLED:'b-cancelled'}[s]||'b-submitted');

export const csvEscape = v => `"${String(v??'').replaceAll('"','""')}"`;

export function requireAuth() {
  try{
    const raw=sessionStorage.getItem('auth'); if(!raw) throw new Error('noauth');
    return JSON.parse(raw||'{}');
  }catch{
    sessionStorage.removeItem('auth'); location.replace('index.html');
    throw new Error('noauth');
  }
}

// work_utils.js

// === Timezone & Formatters (KST 고정) ===
export const KST_TZ = 'Asia/Seoul';

// dateStyle/timeStyle 조합 기본 포맷터
const KST_FULL_FMT = new Intl.DateTimeFormat('ko-KR', {
  timeZone: KST_TZ, dateStyle: 'medium', timeStyle: 'short'
});
const KST_DATE_FMT = new Intl.DateTimeFormat('ko-KR', {
  timeZone: KST_TZ, dateStyle: 'medium'
});
const KST_TIME_FMT = new Intl.DateTimeFormat('ko-KR', {
  timeZone: KST_TZ, timeStyle: 'short'
});

// 표준 포맷 함수들
export function fmt(ts) {
  return ts ? KST_FULL_FMT.format(new Date(ts)) : '-';
}
export function fmtDate(ts) {
  return ts ? KST_DATE_FMT.format(new Date(ts)) : '-';
}
export function fmtTime(ts) {
  return ts ? KST_TIME_FMT.format(new Date(ts)) : '-';
}

// <input type="datetime-local"> 값을 UTC ISO(Z)로 변환
// 예: '2025-10-18T09:30' -> '2025-10-18T00:30:00.000Z' (KST가 로컬이면 +09:00 보정되어 ISOZ)
export function localDatetimeToISOZ(localStr) {
  if (!localStr) return '';
  const [date, hm] = localStr.split('T');
  const [y,m,d] = date.split('-').map(n=>parseInt(n,10));
  const [hh,mm]  = (hm||'0:0').split(':').map(n=>parseInt(n,10));
  const dt = new Date(y, (m-1), d, hh, mm, 0); // 브라우저 로컬 타임존 기준 생성
  return dt.toISOString();
}
