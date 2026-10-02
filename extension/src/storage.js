// local: mode("server" | "local"), webdav(접속 정보), localKey(프로필 모드 키),
//        vault { blob(암호문), baseEtag, dirty },
//        syncState { lastSync, error, autoPaused } (서버 모드 동기화 결과, 이 기기에만)

export async function loadState() {
  const { mode = null, webdav = null, localKey = null, vault = null, syncState = {} } = await chrome.storage.local.get([
    "mode",
    "webdav",
    "localKey",
    "vault",
    "syncState",
  ]);
  return { mode, webdav, localKey, vault, syncState };
}

export const saveState = (state) => chrome.storage.local.set(state);
export const saveVault = (vault) => chrome.storage.local.set({ vault });
export const clearLocal = () => chrome.storage.local.clear();

// 동기화 결과 기록. 성공하면 시각만 남기고 오류·자동 멈춤을 지운다.
// auto: 자동 동기화가 실패하면 autoPaused → 수동 동기화가 성공할 때까지 자동으로 다시 시도하지 않는다
export async function recordSync(error = null, { auto = false } = {}) {
  if (!error) return chrome.storage.local.set({ syncState: { lastSync: Date.now() } });
  const { syncState = {} } = await chrome.storage.local.get("syncState");
  return chrome.storage.local.set({ syncState: { ...syncState, error, ...(auto && { autoPaused: true }) } });
}
