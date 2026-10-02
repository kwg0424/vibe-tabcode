// TapCode 금고 서버 — 금고 파일용 최소 WebDAV (GET / HEAD / PUT / MKCOL / OPTIONS, ETag·If-Match)
//   VAULT_USERS="아이디:비밀번호,아이디2:비밀번호2" node server.js
// 인증: "Authorization: Basic base64(아이디:비밀번호)" (비밀번호에 쉼표는 쓸 수 없음)
// 아이디·경로마다 별도 파일. 서버는 암호문만 보관하며 복호화할 수 없다.
// 운영 시에는 반드시 HTTPS 리버스 프록시(nginx, Caddy 등) 뒤에서 실행할 것.
// Synology/Nextcloud 등 기존 WebDAV 서버를 쓴다면 이 서버는 필요 없다.

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const PORT = Number(process.env.PORT) || 8787;
const HOST = process.env.HOST || "127.0.0.1";
const DATA_DIR = process.env.DATA_DIR || path.join(import.meta.dirname, "data");
const MAX_BODY = 1024 * 1024;

const sha256 = (s) => crypto.createHash("sha256").update(s).digest();
// 메모리에도 비밀번호 원문은 두지 않는다: { user: 아이디 해시, cred: "아이디:비밀번호" 해시 }
const USERS = (process.env.VAULT_USERS || "")
  .split(",")
  .map((t) => t.trim())
  .filter(Boolean)
  .map((pair) => {
    const i = pair.indexOf(":");
    if (i <= 0 || i === pair.length - 1) {
      console.error("VAULT_USERS 형식은 아이디:비밀번호 입니다");
      process.exit(1);
    }
    return { user: sha256(pair.slice(0, i)), cred: sha256(pair) };
  });

if (USERS.length === 0) {
  console.error('VAULT_USERS 환경변수를 설정하세요. 예: VAULT_USERS="alice:비밀번호1,bob:비밀번호2"');
  process.exit(1);
}
if (USERS.some((u, i) => USERS.findIndex((v) => v.user.equals(u.user)) !== i)) {
  console.error("VAULT_USERS 에 중복된 아이디가 있습니다");
  process.exit(1);
}
fs.mkdirSync(DATA_DIR, { recursive: true });

function presentedCredential(req) {
  const b64 = /^Basic ([A-Za-z0-9+/=]+)$/.exec(req.headers.authorization || "")?.[1];
  return b64 ? Buffer.from(b64, "base64").toString("utf8") : null;
}

// 해시는 상수 시간 비교. 일치하면 (아이디, 경로)에 해당하는 저장 파일 경로
function authenticate(req, pathname) {
  const cred = presentedCredential(req);
  if (!cred) return null;
  const given = sha256(cred);
  let matched = null;
  for (const u of USERS) if (crypto.timingSafeEqual(u.cred, given)) matched = u;
  if (!matched) return null;
  const pathKey = sha256(pathname).toString("hex").slice(0, 16);
  return path.join(DATA_DIR, `vault-${matched.user.toString("hex").slice(0, 32)}-${pathKey}.json`);
}

const etagOf = (content) => `"${sha256(content).toString("hex").slice(0, 32)}"`;

function read(file) {
  try {
    return fs.readFileSync(file, "utf8");
  } catch {
    return null;
  }
}

function write(file, content) {
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, content);
  fs.renameSync(tmp, file);
}

function isBlob(b) {
  return (
    b && typeof b === "object" && b.v === 1 &&
    ["salt", "iv", "ct"].every((k) => typeof b[k] === "string") &&
    Number.isInteger(b.iter)
  );
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error("too large"));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function end(res, status, headers = {}, body = "") {
  res.writeHead(status, { "Cache-Control": "no-store", ...headers });
  res.end(body);
}

http
  .createServer(async (req, res) => {
    const pathname = decodeURIComponent(new URL(req.url, "http://x").pathname);

    if (req.method === "OPTIONS") {
      return end(res, 200, { DAV: "1", Allow: "OPTIONS, GET, HEAD, PUT, MKCOL" });
    }

    const file = authenticate(req, pathname);
    if (!file) return end(res, 401, { "WWW-Authenticate": 'Basic realm="TapCode", charset="UTF-8"' });

    // 폴더는 실제로 만들지 않는다 (파일은 아이디+경로로 구분)
    if (req.method === "MKCOL") return end(res, 201);

    const current = read(file);

    if (req.method === "GET" || req.method === "HEAD") {
      if (current === null) return end(res, 404);
      return end(
        res,
        200,
        { "Content-Type": "application/json", ETag: etagOf(current) },
        req.method === "GET" ? current : ""
      );
    }

    if (req.method === "PUT") {
      // Node 는 단일 스레드라 아래 비교 → 쓰기 사이에 다른 요청이 끼지 않는다
      const ifMatch = req.headers["if-match"];
      const ifNoneMatch = req.headers["if-none-match"];
      if (ifNoneMatch === "*" && current !== null) return end(res, 412);
      if (ifMatch && (current === null || ifMatch !== etagOf(current))) return end(res, 412);

      let body;
      try {
        body = await readBody(req);
        if (!isBlob(JSON.parse(body))) throw new Error();
      } catch {
        return end(res, 400); // 암호화된 금고 형식이 아니면 저장하지 않는다
      }
      if (read(file) !== current) return end(res, 412); // 본문을 받는 사이 바뀐 경우
      write(file, body);
      return end(res, current === null ? 201 : 204, { ETag: etagOf(body) });
    }

    end(res, 405, { Allow: "OPTIONS, GET, HEAD, PUT, MKCOL" });
  })
  .listen(PORT, HOST, () =>
    console.log(`TapCode WebDAV 서버: http://${HOST}:${PORT}/<경로>/vault.json (사용자 ${USERS.length}명)`)
  );
