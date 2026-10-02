// 현재 사이트 hostname 에 맞는 계정 찾기.
// 1순위: 계정에 지정한 도메인 (정확히 같거나 그 하위 도메인). 여러 개면 쉼표로 구분해 저장
// 2순위: 서비스명이 사이트의 대표 이름과 같을 때 (github.com, naver.co.kr 의 "naver")
//        "github.com.evil.io" 같은 피싱 주소에는 걸리지 않도록 끝에서 두 번째 라벨만 본다.

const SECOND_LEVEL = new Set(["co", "com", "ne", "net", "or", "org", "go", "gov", "ac", "edu", "re", "pe"]);

export function normalizeDomain(input) {
  return (input || "")
    .trim()
    .toLowerCase()
    .replace(/^[a-z]+:\/\//, "")
    .replace(/[/:?#].*$/, "")
    .replace(/^\*?\./, "");
}

// "a.com, https://b.com/x" → ["a.com", "b.com"]
export function domainList(value) {
  return [...new Set((value || "").split(",").map(normalizeDomain).filter(Boolean))];
}

export const joinDomains = (value) => domainList(value).join(",");

// 계정의 사이트 목록에 host 추가 (이미 있으면 그대로)
export const addDomain = (value, host) => joinDomains(`${value || ""},${host}`);

function siteName(hostname) {
  const labels = hostname.split(".");
  if (labels.length < 2) return hostname;
  const second = labels[labels.length - 2];
  if (labels.length >= 3 && SECOND_LEVEL.has(second) && labels[labels.length - 1].length === 2) {
    return labels[labels.length - 3];
  }
  return second;
}

// QR 을 스캔한 페이지의 대표 도메인 (console.aws.amazon.com → amazon.com, nid.naver.co.kr → naver.co.kr)
export function baseDomain(hostname) {
  const host = hostname.toLowerCase();
  if (/^[\d.]+$/.test(host) || host.startsWith("[") || !host.includes(".")) return host;
  const labels = host.split(".");
  const keep = labels.length >= 3 && siteName(host) === labels[labels.length - 3] ? 3 : 2;
  return labels.slice(-keep).join(".");
}

const simplify = (s) => (s || "").toLowerCase().replace(/[^a-z0-9]/g, "");

export function findAccounts(accounts, hostname) {
  const host = hostname.toLowerCase();
  const byDomain = accounts.filter((a) =>
    domainList(a.domain).some((d) => host === d || host.endsWith(`.${d}`))
  );
  if (byDomain.length) return byDomain;

  const name = siteName(host);
  return accounts.filter((a) => !domainList(a.domain).length && simplify(a.issuer) && simplify(a.issuer) === name);
}
