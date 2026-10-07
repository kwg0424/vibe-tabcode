// node test/run.mjs  — 서버를 임시로 띄워 TOTP, 암호화, QR 파싱, WebDAV 동기화 흐름을 검증한다
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { hotp, generate, parseOtpauth, base32Decode, normalizeAccount } from "../extension/src/totp.js";
import { encryptVault, decryptVault, WrongKeyError } from "../extension/src/vault-crypto.js";
import { sync } from "../extension/src/sync.js";
import { pullVault, pushVault, vaultFileUrl, folderUrl } from "../extension/src/webdav.js";
import { findAccounts, normalizeDomain, baseDomain, addDomain, domainList, joinDomains } from "../extension/src/match.js";
import { accountsFromQr, accountsFromText, mergeAccounts, toOtpauthUri } from "../extension/src/qr-import.js";
import { credentialSecret, credentialFileName, vaultSecret } from "../extension/src/vault-key.js";

const b32 = (ascii) => {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "", out = "";
  for (const c of Buffer.from(ascii)) bits += c.toString(2).padStart(8, "0");
  for (let i = 0; i < bits.length; i += 5) out += A[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
  return out;
};

let passed = 0;
async function test(name, fn) {
  await fn();
  passed++;
  console.log(`  ok  ${name}`);
}

// --- RFC 4226 / 6238 ---
await test("RFC 4226 HOTP 벡터", async () => {
  const secret = b32("12345678901234567890");
  const expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
  for (let i = 0; i < 10; i++) assert.equal(await hotp(secret, i), expected[i]);
});

await test("RFC 6238 TOTP 벡터 (SHA1/256/512, 8자리)", async () => {
  const keys = {
    SHA1: b32("12345678901234567890"),
    SHA256: b32("12345678901234567890123456789012"),
    SHA512: b32("1234567890123456789012345678901234567890123456789012345678901234"),
  };
  const vectors = [
    [59, "94287082", "46119246", "90693936"],
    [1111111109, "07081804", "68084774", "25091201"],
    [1234567890, "89005924", "91819424", "93441116"],
    [20000000000, "65353130", "77737706", "47863826"],
  ];
  for (const [t, s1, s256, s512] of vectors) {
    for (const [alg, want] of [["SHA1", s1], ["SHA256", s256], ["SHA512", s512]]) {
      const a = { type: "totp", secret: keys[alg], algorithm: alg, digits: 8, period: 30 };
      assert.equal(await generate(a, t * 1000), want, `${alg} @${t}`);
    }
  }
});

await test("otpauth URI 파싱", async () => {
  const a = parseOtpauth("otpauth://totp/ACME%20Co:john@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&digits=8&algorithm=SHA256&period=60");
  assert.equal(a.issuer, "ACME Co");
  assert.equal(a.account, "john@example.com");
  assert.equal(a.digits, 8);
  assert.equal(a.algorithm, "SHA256");
  assert.equal(a.period, 60);
  assert.throws(() => parseOtpauth("https://x"));
  assert.throws(() => parseOtpauth("otpauth://totp/x?secret=!!!"));
  assert.equal(base32Decode("jbsw y3dp").length, 5);
});

await test("QR 내용: Google Authenticator 내보내기(otpauth-migration) / 일반 / 비인증 QR", async () => {
  const m = accountsFromQr(
    "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZSABKAEwAhABGAEgACjr4JKK%2Bv%2F%2F%2F%2F8B"
  );
  assert.equal(m.length, 1);
  assert.deepEqual(
    { issuer: m[0].issuer, account: m[0].account, secret: m[0].secret, type: m[0].type, digits: m[0].digits },
    { issuer: "Example", account: "alice@google.com", secret: "JBSWY3DPEHPK3PXP", type: "totp", digits: 6 }
  );
  assert.equal(accountsFromQr("otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP")[0].issuer, "GitHub");
  assert.throws(() => accountsFromQr("https://example.com"), /2단계 인증용 QR/);
});

await test("OTP 내보내기 → 가져오기 왕복 (사이트·HOTP 카운터·8자리 보존, 주석/잘못된 줄 처리)", async () => {
  const src = [
    parseOtpauth("otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"),
    parseOtpauth("otpauth://hotp/Bank:me?secret=MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U&issuer=Bank&counter=7&digits=8&algorithm=SHA256"),
    parseOtpauth("otpauth://totp/%ED%95%9C%EA%B8%80:%EA%B3%84%EC%A0%95?secret=ONSWG4TFOQYTEMZUGU3DOOBZ&period=60"),
  ];
  src[0].domain = "github.com";
  const file = ["# TapCode OTP 백업", "", ...src.map(toOtpauthUri), "otpauth://totp/bad?secret=!!!", "아무 텍스트"].join("\r\n");
  const { accounts, failed } = accountsFromText(file);
  assert.equal(failed, 1);
  const pick = (a) => ({ type: a.type, issuer: a.issuer, account: a.account, secret: a.secret, algorithm: a.algorithm, digits: a.digits, period: a.period, counter: a.counter, domain: a.domain });
  assert.deepEqual(accounts.map(pick), src.map(pick));
  assert.equal(accounts[2].issuer, "한글");
  assert.equal(mergeAccounts(src, accounts).added.length, 0); // 같은 파일 다시 가져오면 전부 중복
});

await test("QR 중복 추가 방지", async () => {
  const a = parseOtpauth("otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP");
  const again = parseOtpauth("otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP");
  const other = parseOtpauth("otpauth://totp/GitHub:you?secret=JBSWY3DPEHPK3PXP");
  const r = mergeAccounts([a], [again, other, other]);
  assert.equal(r.added.length, 1);
  assert.equal(r.skipped, 2);
  assert.equal(r.merged.length, 2);
});

await test("사이트 매칭: 지정 도메인 / 서비스명 추정 / 피싱 주소 차단", async () => {
  const accts = [
    { id: "gh", issuer: "GitHub" },
    { id: "nv", issuer: "Naver" },
    { id: "aws", issuer: "Amazon Web Services", domain: "signin.aws.amazon.com" },
    { id: "corp", issuer: "Company", domain: "example.com" },
  ];
  const ids = (host) => findAccounts(accts, host).map((a) => a.id).join(",");
  assert.equal(ids("github.com"), "gh");
  assert.equal(ids("www.github.com"), "gh");
  assert.equal(ids("nid.naver.com"), "nv");
  assert.equal(ids("naver.co.kr"), "nv");
  assert.equal(ids("signin.aws.amazon.com"), "aws");
  assert.equal(ids("sso.example.com"), "corp");
  assert.equal(ids("github.com.evil.io"), "");
  assert.equal(ids("evilgithub.com"), "");
  assert.equal(ids("notexample.com"), "");
  assert.equal(normalizeDomain("https://GitHub.com/login?x"), "github.com");
  assert.equal(parseOtpauth("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP").domain, "");
});

await test("계정 하나에 사이트 여러 개 / 클릭 입력 시 사이트 추가", async () => {
  const acct = { id: "acct", issuer: "Admin", domain: "" };
  const other = { id: "gh", issuer: "GitHub", domain: "github.com" };
  const host = "admin.example.com";
  assert.equal(findAccounts([acct, other], host).length, 0); // 저장 전: Alt+X 가 못 찾음
  acct.domain = addDomain(acct.domain, host);
  assert.equal(acct.domain, "admin.example.com");
  assert.deepEqual(findAccounts([acct, other], host).map((a) => a.id), ["acct"]);
  assert.equal(findAccounts([acct], "wiki.example.com").length, 0); // 같은 회사 다른 서비스엔 안 걸림
  acct.domain = addDomain(acct.domain, "admin2.example.net");
  assert.equal(addDomain(acct.domain, host), acct.domain); // 중복 추가 안 됨
  assert.deepEqual(domainList(acct.domain), ["admin.example.com", "admin2.example.net"]);
  assert.deepEqual(findAccounts([acct], "admin2.example.net").map((a) => a.id), ["acct"]);
  assert.equal(joinDomains(" https://A.com/x , b.com,, a.com "), "a.com,b.com");
  const round = accountsFromText(toOtpauthUri(normalizeAccount({ ...acct, secret: "JBSWY3DPEHPK3PXP" }))).accounts[0];
  assert.equal(round.domain, acct.domain); // 내보내기/가져오기에도 유지
});

await test("QR 스캔한 사이트의 대표 도메인", async () => {
  assert.equal(baseDomain("console.aws.amazon.com"), "amazon.com");
  assert.equal(baseDomain("nid.naver.co.kr"), "naver.co.kr");
  assert.equal(baseDomain("github.com"), "github.com");
  assert.equal(baseDomain("127.0.0.1"), "127.0.0.1");
  assert.equal(baseDomain("localhost"), "localhost");
});

await test("WebDAV 파일 이름: 계정마다 다르고, 같으면 같고, 아이디·비밀번호가 드러나지 않음", async () => {
  const me = { username: "kim", password: "my-secret-pw" };
  const a = await credentialFileName(me);
  assert.equal(a, await credentialFileName({ ...me }));
  assert.notEqual(a, await credentialFileName({ ...me, password: "my-secret-pw2" }));
  assert.notEqual(a, await credentialFileName({ ...me, username: "lee" }));
  assert.match(a, /^[0-9a-f]{32}$/);
  const f = await vaultFileUrl({ url: "https://server/setting/tabCode/", ...me });
  assert.equal(f, `https://server/setting/tabCode/${a}.json`);
  assert.ok(!f.includes("my-secret-pw") && !f.includes("kim"));
  // 예전 설정(파일까지 적은 주소)은 그 폴더로
  assert.equal(folderUrl("https://server/.setting/tabCode/vault.json"), "https://server/.setting/tabCode");
  assert.equal(folderUrl(" https://server/setting/tabCode// "), "https://server/setting/tabCode");
});

await test("계정 구분 없는 공유 폴더 WebDAV 에서도 서로 덮어쓰지 않음", async () => {
  // 경로만 보고 파일을 저장하는 단순 WebDAV (여러 계정이 같은 폴더를 쓰는 경우)
  const files = new Map();
  let n = 0;
  const plain = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const cur = files.get(req.url);
    if (req.method === "GET") return cur ? res.writeHead(200, { ETag: cur.etag }).end(cur.body) : res.writeHead(404).end();
    if (req.method === "PUT") {
      if (req.headers["if-none-match"] === "*" && cur) return res.writeHead(412).end();
      if (req.headers["if-match"] && req.headers["if-match"] !== cur?.etag) return res.writeHead(412).end();
      const etag = `"${++n}"`;
      files.set(req.url, { body: Buffer.concat(chunks).toString(), etag });
      return res.writeHead(cur ? 204 : 201, { ETag: etag }).end();
    }
    res.writeHead(405).end();
  });
  await new Promise((r) => plain.listen(8799, "127.0.0.1", r));
  try {
    const folder = "http://127.0.0.1:8799/setting/tabCode";
    const me = { url: folder, username: "me", password: "pw-me" };
    const you = { url: folder, username: "you", password: "pw-you" };
    const keep = () => assert.fail("충돌 질문이 나오면 안 됨");
    const meBlob = await encryptVault({ accounts: [{ issuer: "Mine" }] }, credentialSecret(me));
    await sync(me, credentialSecret(me), { blob: meBlob, baseEtag: null, dirty: true }, keep);
    const r = await sync(you, credentialSecret(you), null, keep); // 다른 계정: 빈 금고를 새로 만듦 (내 파일을 덮지 않음)
    assert.equal(r.action, "created");
    assert.equal(files.size, 2);
    assert.ok([...files.keys()].every((k) => /^\/setting\/tabCode\/[0-9a-f]{32}\.json$/.test(k)));
    const mine = await sync(me, credentialSecret(me), null, keep);
    assert.equal((await decryptVault(mine.vault.blob, credentialSecret(me))).accounts[0].issuer, "Mine");
  } finally {
    plain.close();
  }
});

// --- 암호화 ---
await test("금고 암호화 왕복 / 틀린 키 거부 / 평문 미포함 / 무작위 키는 반복 1회", async () => {
  const fast = await encryptVault({ a: 1 }, "random-key", null, { iterations: 1 });
  assert.equal(fast.iter, 1);
  assert.deepEqual(await decryptVault(fast, "random-key"), { a: 1 });
  const data = { accounts: [{ secret: "JBSWY3DPEHPK3PXP" }] };
  const blob = await encryptVault(data, "correct horse");
  assert.deepEqual(await decryptVault(blob, "correct horse"), data);
  await assert.rejects(decryptVault(blob, "wrong"), WrongKeyError);
  assert.ok(!JSON.stringify(blob).includes("JBSWY3DP"));
  const blob2 = await encryptVault(data, "correct horse", blob);
  assert.equal(blob2.salt, blob.salt);
  assert.notEqual(blob2.iv, blob.iv);
});

// --- WebDAV 서버 + 동기화 ---
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "syncotp-"));
const server = spawn(process.execPath, ["server/server.js"], {
  env: { ...process.env, VAULT_USERS: "alice:pw:A한글,bob:pwB", DATA_DIR: dataDir, PORT: "8787" },
  stdio: ["ignore", "pipe", "inherit"],
});
await new Promise((r) => server.stdout.once("data", r));

const URL_A = "http://127.0.0.1:8787/setting/tabCode"; // 폴더 주소
const A_CFG = { url: URL_A, username: "alice", password: "pw:A한글" }; // 비밀번호의 : 와 한글(UTF-8)도 됨
const B_CFG = { url: URL_A, username: "bob", password: "pwB" };
const FILE_A = await vaultFileUrl(A_CFG);
const basicA = "Basic " + Buffer.from("alice:pw:A한글").toString("base64");

try {
  const A = credentialSecret(A_CFG);
  const keep = () => assert.fail("충돌 질문이 나오면 안 됨");

  await test("틀린 비밀번호 / 다른 사람 비밀번호 / Bearer → 인증 실패", async () => {
    await assert.rejects(sync({ ...A_CFG, password: "nope" }, A, null, keep), /인증 실패: 아이디 또는 비밀번호/);
    await assert.rejects(sync({ ...A_CFG, password: "pwB" }, A, null, keep), /인증 실패/);
    const bearer = await fetch(FILE_A, { headers: { Authorization: "Bearer pwB" } });
    assert.equal(bearer.status, 401);
    assert.match(bearer.headers.get("WWW-Authenticate"), /^Basic /);
  });

  await test("https 가 아니면 비밀번호를 보내지 않음 (localhost 만 예외) / 예전 토큰 설정은 다시 입력 요구", async () => {
    await assert.rejects(pullVault({ ...A_CFG, url: "http://example.com/dav" }), /https:\/\//);
    await assert.rejects(pullVault({ url: URL_A, token: "old-token" }), /다시 입력/);
    // 예전 토큰 설정의 금고는 이 기기에서 계속 열린다 (다시 연결할 때 새 키로 바뀜)
    assert.equal(vaultSecret({ mode: "server", webdav: { url: URL_A, token: "t" } }), "bearer:t");
    assert.equal(vaultSecret({ mode: "server", webdav: A_CFG }), A);
  });

  let dev1, dev2;
  await test("기기1: 빈 서버에 새 금고 생성 (If-None-Match: *)", async () => {
    const r = await sync(A_CFG, A, null, keep);
    assert.equal(r.action, "created");
    assert.match(r.vault.baseEtag, /^".+"$/);
    dev1 = r.vault;
  });

  await test("기기1: 계정 추가 후 동기화 → 업로드 (If-Match)", async () => {
    const blob = await encryptVault({ accounts: [{ id: "1", issuer: "GitHub" }] }, A, dev1.blob);
    const r = await sync(A_CFG, A, { ...dev1, blob, dirty: true }, keep);
    assert.equal(r.action, "pushed");
    assert.notEqual(r.vault.baseEtag, dev1.baseEtag);
    dev1 = r.vault;
  });

  await test("기기2: 같은 아이디·비밀번호로 가져오기", async () => {
    const r = await sync(A_CFG, A, null, keep);
    assert.equal(r.action, "pulled");
    dev2 = r.vault;
    assert.equal((await decryptVault(dev2.blob, A)).accounts[0].issuer, "GitHub");
  });

  await test("다른 접속 정보로 만든 키로는 가져오지 않음", async () => {
    await assert.rejects(sync(A_CFG, "basic:other:pw", null, keep), WrongKeyError);
  });

  await test("변경 없으면 unchanged", async () => {
    assert.equal((await sync(A_CFG, A, dev1, keep)).action, "unchanged");
  });

  await test("양쪽 변경 시 충돌 → 서버 버전 선택", async () => {
    const b1 = await encryptVault({ accounts: [{ id: "x", issuer: "from-dev1" }] }, A, dev1.blob);
    dev1 = (await sync(A_CFG, A, { ...dev1, blob: b1, dirty: true }, keep)).vault;
    const b2 = await encryptVault({ accounts: [{ id: "y", issuer: "from-dev2" }] }, A, dev2.blob);
    let asked = false;
    const r = await sync(A_CFG, A, { ...dev2, blob: b2, dirty: true }, async () => ((asked = true), "remote"));
    assert.ok(asked);
    assert.equal(r.action, "pulled");
    assert.equal((await decryptVault(r.vault.blob, A)).accounts[0].issuer, "from-dev1");
    dev2 = r.vault;
  });

  await test("충돌 → 이 기기 버전 선택 / 취소(QR 자동 업로드는 취소로 처리)", async () => {
    const b1 = await encryptVault({ accounts: [{ id: "z", issuer: "dev1-again" }] }, A, dev1.blob);
    dev1 = (await sync(A_CFG, A, { ...dev1, blob: b1, dirty: true }, keep)).vault;
    const b2 = await encryptVault({ accounts: [{ id: "w", issuer: "dev2-wins" }] }, A, dev2.blob);
    await assert.rejects(sync(A_CFG, A, { ...dev2, blob: b2, dirty: true }, async () => null), /취소/);
    const r = await sync(A_CFG, A, { ...dev2, blob: b2, dirty: true }, async () => "local");
    assert.equal(r.action, "pushed");
    assert.equal((await decryptVault((await sync(A_CFG, A, null, keep)).vault.blob, A)).accounts[0].issuer, "dev2-wins");
  });

  await test("계정별 금고 분리", async () => {
    const r = await sync(B_CFG, credentialSecret(B_CFG), null, keep);
    assert.equal(r.action, "created");
    assert.equal(fs.readdirSync(dataDir).filter((f) => f.endsWith(".json")).length, 2);
  });

  await test("같은 계정이라도 경로가 다르면 다른 파일 / 상위 폴더 MKCOL", async () => {
    const cfg = { ...A_CFG, url: "http://127.0.0.1:8787/other/deep/vault.json" };
    assert.deepEqual(await pullVault(cfg), { etag: null, blob: null });
    assert.equal((await sync(cfg, A, null, keep)).action, "created");
  });

  await test("WebDAV: 오래된 ETag → 412 충돌 / 금고 형식 아니면 400", async () => {
    const blob = await encryptVault({ accounts: [] }, credentialSecret(B_CFG));
    assert.equal((await pushVault(B_CFG, '"stale"', blob)).conflict, true);
    assert.equal((await pushVault(B_CFG, null, blob)).conflict, true); // 이미 있는데 If-None-Match: *
    const res = await fetch(FILE_A, {
      method: "PUT",
      headers: { Authorization: basicA, "Content-Type": "application/json" },
      body: JSON.stringify({ plain: "secret" }),
    });
    assert.equal(res.status, 400);
    const opt = await fetch(FILE_A, { method: "OPTIONS" });
    assert.equal(opt.headers.get("DAV"), "1");
  });

  await test("금고 키: 계정마다 다르고 주소와는 무관", async () => {
    assert.notEqual(credentialSecret(A_CFG), credentialSecret(B_CFG));
    assert.equal(credentialSecret(A_CFG), credentialSecret({ ...A_CFG, url: "https://other/x.json" }));
    assert.equal(credentialSecret(A_CFG), "basic:alice:pw:A한글");
  });

  await test("접속 정보 변경 후 재암호화: 서버가 내가 올린 그대로면 새 키로 업로드", async () => {
    const cur = await sync(A_CFG, A, null, keep); // 최신 상태
    const NEW = "basic:alice:rotated";
    const { accounts } = await decryptVault(cur.vault.blob, A);
    const blob = await encryptVault({ accounts }, NEW);
    const r = await sync(A_CFG, NEW, { blob, baseEtag: cur.vault.baseEtag, dirty: true }, keep);
    assert.equal(r.action, "pushed");
    assert.equal((await sync(A_CFG, NEW, null, keep)).action, "pulled");
    await assert.rejects(sync(A_CFG, A, null, keep), WrongKeyError); // 옛 키로는 더 이상 안 열림
    dev1 = r.vault;
  });

  await test("접속 정보 변경 후 서버도 바뀌어 있으면: 덮어쓸지 묻고(서버 버전 선택지 없음) 취소 가능", async () => {
    const OTHER = "basic:someone:else";
    const blob = await encryptVault({ accounts: [] }, OTHER);
    let asked = null;
    await assert.rejects(sync(A_CFG, OTHER, { blob, baseEtag: "\"old\"", dirty: true }, async (o) => ((asked = o), null)), /열 수 없어/);
    assert.deepEqual(asked, { remoteUnreadable: true });
    const r = await sync(A_CFG, OTHER, { blob, baseEtag: "\"old\"", dirty: true }, async () => "local");
    assert.equal(r.action, "pushed");
  });

  await test("서버 파일에 평문 키 없음", async () => {
    for (const f of fs.readdirSync(dataDir)) {
      const txt = fs.readFileSync(path.join(dataDir, f), "utf8");
      assert.ok(!/GitHub|dev2-wins|issuer/.test(txt), f);
    }
  });
} finally {
  server.kill();
  fs.rmSync(dataDir, { recursive: true, force: true });
}
console.log(`\n${passed}개 통과`);
