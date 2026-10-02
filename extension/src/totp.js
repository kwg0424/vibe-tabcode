// RFC 4226 (HOTP) / RFC 6238 (TOTP) — WebCrypto 기반, 외부 라이브러리 없음
import { joinDomains } from "./match.js";

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const HASH = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };

export function base32Decode(input) {
  const s = input.toUpperCase().replace(/[\s=-]/g, "");
  const out = [];
  let bits = 0;
  let value = 0;
  for (const ch of s) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error(`잘못된 Base32 문자: ${ch}`);
    value = ((value << 5) | idx) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export async function hotp(secret, counter, { digits = 6, algorithm = "SHA1" } = {}) {
  const key = await crypto.subtle.importKey(
    "raw",
    base32Decode(secret),
    { name: "HMAC", hash: HASH[algorithm] },
    false,
    ["sign"]
  );
  const msg = new DataView(new ArrayBuffer(8));
  msg.setUint32(0, Math.floor(counter / 2 ** 32));
  msg.setUint32(4, counter % 2 ** 32);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg.buffer));
  const off = mac[mac.length - 1] & 0x0f;
  const bin =
    ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(bin % 10 ** digits).padStart(digits, "0");
}

export function generate(account, now = Date.now()) {
  const counter =
    account.type === "hotp" ? account.counter : Math.floor(now / 1000 / account.period);
  return hotp(account.secret, counter, account);
}

export function secondsLeft(period, now = Date.now()) {
  return period - (Math.floor(now / 1000) % period);
}

export function normalizeAccount(a) {
  const account = {
    id: a.id || crypto.randomUUID(),
    type: a.type === "hotp" ? "hotp" : "totp",
    issuer: (a.issuer || "").trim(),
    account: (a.account || "").trim(),
    secret: (a.secret || "").toUpperCase().replace(/[\s=-]/g, ""),
    algorithm: (a.algorithm || "SHA1").toUpperCase().replace("-", ""),
    digits: Number(a.digits) || 6,
    period: Number(a.period) || 30,
    counter: Number(a.counter) || 0,
    domain: joinDomains(a.domain),
  };
  if (!account.secret) throw new Error("시크릿 키가 비어 있습니다");
  if (base32Decode(account.secret).length < 10) throw new Error("시크릿 키가 너무 짧습니다");
  if (!HASH[account.algorithm]) throw new Error(`지원하지 않는 알고리즘: ${account.algorithm}`);
  if (account.digits < 6 || account.digits > 8) throw new Error("자릿수는 6~8만 지원합니다");
  if (account.period < 1) throw new Error("주기가 올바르지 않습니다");
  if (!account.issuer && !account.account) throw new Error("서비스명 또는 계정명을 입력하세요");
  return account;
}

export function parseOtpauth(uri) {
  const m = /^otpauth:\/\/(totp|hotp)\/([^?]*)\?(.*)$/i.exec(uri.trim());
  if (!m) throw new Error("otpauth:// URI 형식이 아닙니다");
  const label = decodeURIComponent(m[2]);
  const params = new URLSearchParams(m[3]);
  let issuer = params.get("issuer") || "";
  let account = label;
  const sep = label.indexOf(":");
  if (sep >= 0) {
    if (!issuer) issuer = label.slice(0, sep);
    account = label.slice(sep + 1);
  }
  return normalizeAccount({
    type: m[1].toLowerCase(),
    issuer,
    account,
    secret: params.get("secret"),
    algorithm: params.get("algorithm"),
    digits: params.get("digits"),
    period: params.get("period"),
    counter: params.get("counter"),
    domain: params.get("x-domain"),
  });
}
