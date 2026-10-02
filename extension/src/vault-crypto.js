// 금고 암호화: PBKDF2-SHA256 → AES-256-GCM. 서버에는 이 결과물(암호문)만 저장된다.
// secret 은 사용자가 입력하는 암호가 아니라 vault-key.js 가 정하는 값
// (서버 모드: WebDAV 접속 정보, 프로필 모드: 무작위 키)

const ITERATIONS = 600000;
// 서버 파일을 열어 봤을 때 무엇이 만든 파일인지 알 수 있게 (복호화에는 쓰지 않음)
export const TITLE = "TapCode OTP 금고 (Edge 확장)";
const enc = new TextEncoder();
const dec = new TextDecoder();

export class WrongKeyError extends Error {
  constructor() {
    super("금고를 열 수 없습니다. 금고를 만들 때와 다른 접속 정보입니다");
  }
}

function toB64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromB64(s) {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

// PBKDF2는 느리므로 마지막 파생 키를 메모리에만 보관
let cached = null;

async function deriveKey(secret, salt, iterations) {
  const saltB64 = toB64(salt);
  if (cached && cached.secret === secret && cached.salt === saltB64 && cached.iterations === iterations) {
    return cached.key;
  }
  const base = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  cached = { secret, salt: saltB64, iterations, key };
  return key;
}

// prevBlob 을 주면 같은 salt·반복 횟수를 재사용해 키 파생을 생략한다 (IV는 매번 새로 생성).
// iterations: 무작위 256비트 키처럼 이미 충분히 강한 secret 이면 낮춰도 된다.
export async function encryptVault(data, secret, prevBlob, { iterations = ITERATIONS } = {}) {
  const salt = prevBlob ? fromB64(prevBlob.salt) : crypto.getRandomValues(new Uint8Array(16));
  const iter = prevBlob ? prevBlob.iter : iterations;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(secret, salt, iter);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(data)));
  return {
    title: TITLE,
    v: 1,
    kdf: "PBKDF2-SHA256",
    iter,
    salt: toB64(salt),
    iv: toB64(iv),
    ct: toB64(new Uint8Array(ct)),
  };
}

export async function decryptVault(blob, secret) {
  const key = await deriveKey(secret, fromB64(blob.salt), blob.iter);
  try {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(blob.iv) }, key, fromB64(blob.ct));
    return JSON.parse(dec.decode(pt));
  } catch {
    throw new WrongKeyError();
  }
}
