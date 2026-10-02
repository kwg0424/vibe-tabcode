// 금고 암호화 키(secret) 결정 — 사용자에게 별도 암호를 묻지 않는다.
//   서버 모드  : WebDAV 아이디·비밀번호에서 만든다 → 다른 PC 에서도 같은 아이디·비밀번호만 넣으면 열림.
//                서버는 비밀번호(또는 그 해시)만 가지므로 서버 파일만으로는 못 푼다.
//   프로필 모드: 처음 설정 때 만든 무작위 키 (프로필 저장소에 보관)

// cfg: { url, username, password }
export const hasCredentials = (cfg) => !!(cfg?.username && cfg?.password);

// Basic 인증 아이디에는 ":" 가 들어갈 수 없어 "아이디:비밀번호" 는 겹치지 않는다
export function credentialSecret(cfg) {
  return `basic:${cfg.username}:${cfg.password}`;
}

// WebDAV 금고 파일 이름: 아이디·비밀번호에서 PBKDF2(600k)로 만든 32자리 16진수.
// 비밀번호(=접속 정보이자 암호화 키 재료)가 서버 로그·폴더 목록에 드러나지 않고,
// 대입 공격도 금고 암호화만큼 느리다. 같은 아이디·비밀번호면 어느 PC 에서나 같은 이름.
const fileNames = new Map(); // 팝업/백그라운드가 떠 있는 동안 메모리에만 캐시

export async function credentialFileName(cfg) {
  const material = `${cfg.username}:${cfg.password}`;
  if (fileNames.has(material)) return fileNames.get(material);
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey("raw", enc.encode(material), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: enc.encode("tapcode:webdav-file-name:v2"), iterations: 600000 },
    base,
    128
  );
  const name = [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
  fileNames.set(material, name);
  return name;
}

export function newLocalKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes));
}

// 무작위 256비트 키는 PBKDF2 반복이 필요 없다
export const LOCAL_KEY_ITERATIONS = 1;

export function vaultSecret({ mode, webdav, localKey }) {
  if (mode === "server" && hasCredentials(webdav)) return credentialSecret(webdav);
  // 1.3.0 토큰 방식으로 저장된 금고: 이 기기에서는 계속 열리고, 아이디·비밀번호로 다시 연결하면 새 키로 바뀐다
  if (mode === "server" && webdav?.token) return `bearer:${webdav.token}`;
  if (mode === "local" && localKey) return localKey;
  return null;
}
