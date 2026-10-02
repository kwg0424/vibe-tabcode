// QR 내용 → 계정 목록
//   otpauth://totp/...            일반 2단계 인증 QR
//   otpauth-migration://offline?data=...  Google Authenticator "계정 내보내기" QR (protobuf)
import { parseOtpauth, normalizeAccount } from "./totp.js";

export function accountsFromQr(text) {
  const t = (text || "").trim();
  if (/^otpauth:\/\//i.test(t)) return [parseOtpauth(t)];
  if (/^otpauth-migration:\/\//i.test(t)) return parseMigration(t);
  throw new Error("2단계 인증용 QR 코드가 아닙니다");
}

// OTP 가져오기: 텍스트 파일의 각 줄 중 otpauth:// · otpauth-migration:// 만 읽는다 (# 주석·빈 줄 무시)
// → { accounts, failed(읽지 못한 줄 수) }
export function accountsFromText(text) {
  const accounts = [];
  let failed = 0;
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!/^otpauth(-migration)?:\/\//i.test(t)) continue;
    try {
      accounts.push(...accountsFromQr(t));
    } catch {
      failed++;
    }
  }
  return { accounts, failed };
}

// OTP 내보내기: 계정 → otpauth URI. 자동 입력 사이트는 x-domain 으로 보존 (다른 앱은 무시)
export function toOtpauthUri(a) {
  const label = encodeURIComponent(a.issuer ? `${a.issuer}:${a.account}` : a.account);
  const params = new URLSearchParams({ secret: a.secret, algorithm: a.algorithm, digits: a.digits });
  if (a.issuer) params.set("issuer", a.issuer);
  if (a.type === "hotp") params.set("counter", a.counter);
  else params.set("period", a.period);
  if (a.domain) params.set("x-domain", a.domain);
  return `otpauth://${a.type}/${label}?${params}`;
}

// 이미 같은 키가 있으면 건너뛴다 → { merged, added, skipped }
export function mergeAccounts(existing, incoming) {
  const key = (a) => `${a.secret}|${a.issuer}|${a.account}`;
  const seen = new Set(existing.map(key));
  const added = incoming.filter((a) => !seen.has(key(a)) && seen.add(key(a)));
  return { merged: [...existing, ...added], added, skipped: incoming.length - added.length };
}

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = ((value << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

// 최소 protobuf 리더: varint(0)와 length-delimited(2)만 사용됨
function readMessage(bytes) {
  const fields = [];
  let pos = 0;
  const varint = () => {
    let result = 0;
    let mul = 1;
    for (;;) {
      if (pos >= bytes.length) throw new Error("손상된 내보내기 QR 입니다");
      const b = bytes[pos++];
      result += (b & 0x7f) * mul;
      if (!(b & 0x80)) return result;
      mul *= 128;
    }
  };
  while (pos < bytes.length) {
    const tag = varint();
    const field = Math.floor(tag / 8);
    const wire = tag & 7;
    if (wire === 0) fields.push({ field, value: varint() });
    else if (wire === 2) {
      const len = varint();
      fields.push({ field, value: bytes.subarray(pos, pos + len) });
      pos += len;
    } else if (wire === 5) pos += 4;
    else if (wire === 1) pos += 8;
    else throw new Error("손상된 내보내기 QR 입니다");
  }
  return fields;
}

const ALGORITHMS = { 0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512" };
const DIGITS = { 0: 6, 1: 6, 2: 8 };

function parseMigration(uri) {
  const data = new URLSearchParams(uri.slice(uri.indexOf("?") + 1)).get("data");
  if (!data) throw new Error("내보내기 QR 에 data 가 없습니다");
  const bytes = Uint8Array.from(atob(data.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const dec = new TextDecoder();

  const accounts = [];
  for (const { field, value } of readMessage(bytes)) {
    if (field !== 1) continue; // otp_parameters
    const p = {};
    for (const f of readMessage(value)) p[f.field] = f.value;
    if (p[4] === 4) throw new Error("MD5 알고리즘 계정은 지원하지 않습니다");
    const name = p[2] ? dec.decode(p[2]) : "";
    const issuer = p[3] ? dec.decode(p[3]) : "";
    const sep = name.indexOf(":");
    accounts.push(
      normalizeAccount({
        type: p[6] === 1 ? "hotp" : "totp",
        issuer: issuer || (sep >= 0 ? name.slice(0, sep) : ""),
        account: sep >= 0 ? name.slice(sep + 1) : name,
        secret: base32Encode(p[1] || new Uint8Array()),
        algorithm: ALGORITHMS[p[4] ?? 0],
        digits: DIGITS[p[5] ?? 0],
        period: 30,
        counter: p[7] || 0,
      })
    );
  }
  if (!accounts.length) throw new Error("내보내기 QR 에 계정이 없습니다");
  return accounts;
}
