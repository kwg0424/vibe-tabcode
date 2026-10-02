// WebDAV 금고 파일 읽기/쓰기. 충돌 감지는 ETag + If-Match (서버에 이미 바뀐 게 있으면 412).
// cfg: { url(폴더), username, password } — Authorization: Basic (아이디:비밀번호)
// 금고 파일 = <폴더>/<아이디·비밀번호로 만든 파일 이름>.json → 계정마다 다른 파일이라 서로 덮어쓰지 않는다.
import { credentialFileName, hasCredentials } from "./vault-key.js";
import { TITLE } from "./vault-crypto.js";

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

// UTF-8 → base64 (btoa 는 Latin-1 만 받으므로 한글 비밀번호도 되게)
const authHeader = (cfg) =>
  `Basic ${btoa(String.fromCharCode(...new TextEncoder().encode(`${cfg.username}:${cfg.password}`)))}`;

// Basic 인증은 비밀번호를 사실상 그대로(base64) 보내므로 HTTPS 로만 보낸다. 개발용 localhost 만 예외
export function assertSecureUrl(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    throw new ApiError("올바른 주소가 아닙니다", 0);
  }
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (u.protocol !== "https:" && !(local && u.protocol === "http:")) {
    throw new ApiError("https:// 주소만 사용할 수 있습니다 (비밀번호 보호)", 0);
  }
}

// 폴더 주소 정리. 예전 설정(…/vault.json 처럼 파일까지 적은 주소)은 그 폴더로 본다
export function folderUrl(url) {
  return url.trim().replace(/\/[^/]*\.json$/i, "").replace(/\/+$/, "");
}

export async function vaultFileUrl(cfg) {
  return `${folderUrl(cfg.url)}/${await credentialFileName(cfg)}.json`;
}

async function request(cfg, method, { url, body, headers = {} } = {}) {
  // 1.3.0 토큰 방식으로 저장된 설정
  if (!hasCredentials(cfg)) throw new ApiError("서버 접속 정보(아이디·비밀번호)를 다시 입력하세요", 0);
  url ??= await vaultFileUrl(cfg);
  assertSecureUrl(url);
  let res;
  try {
    res = await fetch(url, {
      method,
      cache: "no-store",
      credentials: "omit",
      headers: { Authorization: authHeader(cfg), ...headers },
      body,
    });
  } catch {
    throw new ApiError("서버에 연결할 수 없습니다", 0);
  }
  if (res.status === 401 || res.status === 403) {
    throw new ApiError("인증 실패: 아이디 또는 비밀번호가 틀립니다", res.status);
  }
  return res;
}

// 서버가 알려 준 원인을 붙인다. SabreDAV(OMV·Nextcloud)는 <s:message>, nginx/Apache 는 <title> 에 담는다
async function serverError(prefix, res) {
  const text = await res.text().catch(() => "");
  const reason = (
    /<s:message>([\s\S]*?)<\/s:message>/i.exec(text)?.[1] ||
    /<s:exception>([\s\S]*?)<\/s:exception>/i.exec(text)?.[1] ||
    /<title>([\s\S]*?)<\/title>/i.exec(text)?.[1] ||
    (/</.test(text) ? "" : text)
  )
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 200);
  return new ApiError(`${prefix} (${res.status})${reason ? `: ${reason}` : ""}`, res.status);
}

// → { etag, blob } — 파일이 없으면 { etag: null, blob: null }
export async function pullVault(cfg) {
  const res = await request(cfg, "GET");
  if (res.status === 404) return { etag: null, blob: null };
  if (!res.ok) throw await serverError("WebDAV 오류", res);
  let blob;
  try {
    blob = await res.json();
  } catch {
    throw new ApiError("서버 파일이 TapCode 금고 형식이 아닙니다", res.status);
  }
  return { etag: res.headers.get("ETag"), blob };
}

// → { etag } 또는 그 사이 다른 기기가 올렸으면 { conflict: true }
export async function pushVault(cfg, baseEtag, blob) {
  const put = () =>
    request(cfg, "PUT", {
      body: JSON.stringify({ title: TITLE, ...blob }), // 제목 없이 만든 예전 금고도 올릴 때 제목을 붙인다
      headers: {
        "Content-Type": "application/json",
        ...(baseEtag ? { "If-Match": baseEtag } : { "If-None-Match": "*" }),
      },
    });
  let res = await put();
  if (res.status === 409) {
    // WebDAV 409 = 폴더 없음 → 만들고 한 번 더
    await createFolders(cfg);
    res = await put();
  }
  if (res.status === 412) return { conflict: true };
  if (!res.ok) throw await serverError("WebDAV 업로드 오류", res);

  let etag = res.headers.get("ETag");
  if (!etag) etag = (await request(cfg, "HEAD")).headers.get("ETag");
  if (!etag) throw new ApiError("서버가 ETag 를 지원하지 않아 충돌을 감지할 수 없습니다", res.status);
  return { etag };
}

async function createFolders(cfg) {
  const folder = new URL(`${folderUrl(cfg.url)}/`);
  let path = "";
  for (const part of folder.pathname.split("/").filter(Boolean)) {
    path += `/${part}`;
    // 201 생성됨 / 405 이미 있음 — 둘 다 진행
    await request(cfg, "MKCOL", { url: new URL(`${path}/`, folder).href });
  }
}
