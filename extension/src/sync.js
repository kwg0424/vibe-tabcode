import { pullVault, pushVault } from "./webdav.js";
import { encryptVault, decryptVault, WrongKeyError, TITLE } from "./vault-crypto.js";

// 서버(WebDAV) 모드에서 동기화 버튼, QR 추가 직후, 접속 정보 변경 시 호출된다.
// secret: 이 접속 정보로 만든 금고 키. local.blob 도 이 키로 암호화돼 있어야 한다.
// local: { blob, baseEtag(마지막 동기화 시 서버 ETag), dirty } 또는 null(처음 연결)
// chooseOnConflict({ remoteUnreadable, remoteEmpty }): 양쪽이 모두 바뀌었을 때 "remote" | "local" | null(취소)
//   remoteEmpty: 서버 금고에 계정이 하나도 없음 (연결할 때는 묻지 않고 이 기기 금고를 올리는 데 쓴다)
// 반환: { vault, action: "pulled" | "pushed" | "unchanged" | "created" }
export async function sync(cfg, secret, local, chooseOnConflict) {
  const remote = await pullVault(cfg);

  // 서버 금고가 이 키로 풀리는지 확인 (다른 키로 덮어쓰는 사고 방지)
  let remoteReadable = true;
  let remoteEmpty = false;
  let remoteAccounts = null;
  if (remote.blob) {
    try {
      remoteAccounts = (await decryptVault(remote.blob, secret)).accounts || [];
      remoteEmpty = !remoteAccounts.length;
    } catch (e) {
      if (!(e instanceof WrongKeyError)) throw e;
      remoteReadable = false;
    }
  }

  if (!remoteReadable) {
    // 처음 연결인데 못 풀면: 다른 접속 정보로 만든 금고
    if (!local) throw new WrongKeyError();
    // 접속 정보(아이디·비밀번호)를 바꾼 직후: 서버 파일이 이 기기가 올린 그대로면 새 키로 다시 올린다
    if (remote.etag === local.baseEtag) return push(cfg, local.blob, remote.etag);
    const choice = await chooseOnConflict({ remoteUnreadable: true });
    if (choice === "local") return push(cfg, local.blob, remote.etag);
    throw new Error("서버 금고를 이 접속 정보로 열 수 없어 동기화하지 않았습니다");
  }

  const pulled = () => ({
    vault: { blob: remote.blob, baseEtag: remote.etag, dirty: false },
    action: "pulled",
  });

  if (!local) {
    if (remote.blob) return pulled();
    const blob = await encryptVault({ accounts: [] }, secret);
    const result = await push(cfg, blob, null);
    return { ...result, action: "created" };
  }

  if (!remote.blob) return push(cfg, local.blob, null);

  if (!local.dirty) {
    // 제목 없는 예전 서버 파일: 내용은 그대로 두고 제목만 붙여 다시 쓴다
    if (remote.blob.title !== TITLE) {
      const r = await push(cfg, remote.blob, remote.etag);
      return { ...r, action: remote.etag === local.baseEtag ? "unchanged" : "pulled" };
    }
    if (remote.etag === local.baseEtag) return { vault: local, action: "unchanged" };
    return pulled();
  }

  if (remote.etag === local.baseEtag) return push(cfg, local.blob, remote.etag);

  // 양쪽이 모두 바뀌었지만 계정 내용이 같으면 (같은 상태로 다시 연결 등) 묻지 않고 서버 것을 그대로 쓴다
  try {
    if (sameAccounts(remoteAccounts, (await decryptVault(local.blob, secret)).accounts || [])) return { ...pulled(), action: "unchanged" };
  } catch (e) {
    if (!(e instanceof WrongKeyError)) throw e;
  }

  const choice = await chooseOnConflict({ remoteUnreadable: false, remoteEmpty });
  if (choice === "remote") return pulled();
  if (choice === "local") return push(cfg, local.blob, remote.etag);
  throw new Error("동기화를 취소했습니다");
}

async function push(cfg, blob, baseEtag) {
  const res = await pushVault(cfg, baseEtag, blob);
  if (res.conflict) throw new Error("동기화 중 서버 데이터가 바뀌었습니다. 다시 시도하세요");
  return { vault: { blob, baseEtag: res.etag, dirty: false }, action: "pushed" };
}

// 계정 목록이 같은지 (순서·속성 순서 무관)
export function sameAccounts(a, b) {
  const canon = (v) =>
    Array.isArray(v) ? `[${v.map(canon).join(",")}]`
    : v && typeof v === "object" ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(",")}}`
    : JSON.stringify(v);
  const list = (accounts) => accounts.map(canon).sort().join("\n");
  return a.length === b.length && list(a) === list(b);
}
