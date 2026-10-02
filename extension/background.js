// 단축키 autofill → 현재 탭에 맞는 계정의 코드를 입력칸에 자동 입력
// 팝업 "화면에서 QR 스캔" 버튼 → 페이지에서 QR 영역을 선택해 계정 추가
import { generate } from "./src/totp.js";
import { encryptVault, decryptVault } from "./src/vault-crypto.js";
import { findAccounts, baseDomain } from "./src/match.js";
import { accountsFromQr, mergeAccounts } from "./src/qr-import.js";
import { decodeQr } from "./src/qr-decode.js";
import { sync } from "./src/sync.js";
import { vaultSecret, newLocalKey, LOCAL_KEY_ITERATIONS } from "./src/vault-key.js";
import * as store from "./src/storage.js";

chrome.commands.onCommand.addListener(async (command, tab) => {
  tab ??= (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
  if (!tab?.id) return;
  try {
    if (command === "autofill") await autofill(tab);
  } catch (e) {
    await pageToast(tab.id, `TapCode: ${e.message}`, true);
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return;
  // 팝업을 열 때: 끝나면 응답 (팝업이 바뀐 금고를 다시 읽도록)
  if (message.action === "syncNow") {
    queueSync().then(() => sendResponse({}));
    return true;
  }
  if (message.action === "autoSync") {
    autoSync().then(() => sendResponse({}), () => sendResponse({}));
    return true;
  }
  // 팝업에서 계정 블록 클릭 → 현재 탭 입력칸에 입력 (팝업을 연 순간 activeTab 권한이 있다)
  if (message.action === "fillTab") {
    chrome.scripting
      .executeScript({ target: { tabId: message.tabId }, func: fillCode, args: [message.code, message.label, 1, true] })
      .then(([{ result }]) => sendResponse({ filled: !!result }), () => sendResponse({ filled: false }));
    return true;
  }
  if (message.action === "startScan") {
    startScan(message.tabId).then(
      () => sendResponse({ ok: true }),
      (e) => sendResponse({ error: true, message: e.message })
    );
    return true;
  }
  if (message.action === "scanArea" && sender.tab) {
    scanArea(sender.tab, message.rect, message.viewportWidth).then(sendResponse, (e) =>
      sendResponse({ error: true, message: `TapCode: ${e.message}` })
    );
    return true;
  }
});

// 금고 { state, vault, secret, accounts } 또는 null (설정 전이면 안내)
async function openVault(tabId) {
  let state = await store.loadState();
  // 팝업을 한 번도 열지 않았으면 팝업과 같이 이 브라우저 프로필 저장으로 시작한다
  if (!state.mode) {
    const localKey = newLocalKey();
    const blob = await encryptVault({ accounts: [] }, localKey, null, { iterations: LOCAL_KEY_ITERATIONS });
    await store.saveState({ mode: "local", webdav: null, localKey, vault: { blob, baseEtag: null, dirty: false } });
    state = await store.loadState();
  }
  const secret = vaultSecret(state);
  if (!state.vault || !secret) {
    await pageToast(tabId, "TapCode: 저장된 키를 열 수 없습니다. 팝업을 한 번 열어 주세요", true);
    return null;
  }
  const { accounts } = await decryptVault(state.vault.blob, secret);
  return { state, vault: state.vault, secret, accounts };
}

async function saveAccounts({ state, vault, secret }, accounts) {
  const blob = await encryptVault({ accounts }, secret, vault.blob);
  const next = { ...vault, blob, dirty: state.mode === "server" };
  await store.saveVault(next);
  return next;
}

// 서버 모드에서 QR 로 추가하면 바로 WebDAV 에 업로드. 충돌이면 묻지 않고 미동기화로 남긴다.
function uploadNow(opened, vault) {
  if (opened.state.mode !== "server") return "";
  const run = chain.then(() => uploadNowRun(opened, vault));
  chain = run.catch(() => {});
  return run;
}

async function uploadNowRun({ state, secret }, vault) {
  try {
    const result = await sync(state.webdav, secret, vault, async () => null);
    await store.saveVault(result.vault);
    await store.recordSync();
    return "\n서버(WebDAV)에 업로드했습니다";
  } catch (e) {
    await store.recordSync(e.message);
    return `\n서버 업로드 실패: ${e.message}\n팝업에서 동기화 버튼을 눌러 주세요`;
  }
}

// ---------- 바로 저장 · 자동 동기화 (DragOn 과 같음) ----------
// 팝업에서 계정을 바꾸거나(syncNow) HOTP 카운터가 올라가면 바로 서버에 올린다 — 팝업이 닫혀도 계속되도록 백그라운드에서.
// 마지막 동기화가 하루를 넘으면 브라우저 시작·페이지 로드·팝업 열기 때 한 번 동기화한다 (autoSync).
// 백그라운드는 충돌을 물을 수 없으므로 양쪽이 모두 바뀌었으면 실패로 남기고, 설정의 동기화 버튼에서 고르게 한다.
// 자동 동기화가 실패하면 수동 동기화가 성공할 때까지 자동으로 다시 시도하지 않는다.
const AUTO_SYNC_AFTER = 24 * 60 * 60 * 1000;
const AUTO_CHECK_EVERY = 10 * 60 * 1000; // 페이지를 열 때마다 저장소를 읽지 않도록 (서비스 워커가 떠 있는 동안)
let lastAutoCheck = 0;

// 백그라운드 동기화는 한 줄로 세운다. 연달아 요청하면 아직 시작 안 한 하나로 묶는다
let chain = Promise.resolve();
let queued = false;
function queueSync() {
  if (!queued) {
    queued = true;
    chain = chain.then(() => ((queued = false), syncOnce())).catch(() => {});
  }
  return chain;
}

async function syncOnce({ auto = false } = {}) {
  const state = await store.loadState();
  const secret = vaultSecret(state);
  if (state.mode !== "server" || !state.vault || !secret) return;
  try {
    const result = await sync(state.webdav, secret, state.vault, async () => null);
    const now = (await store.loadState()).vault;
    if (now?.blob?.ct === state.vault.blob.ct) await store.saveVault(result.vault);
    // 동기화하는 사이 팝업에서 또 바꿨으면 그 변경은 덮어쓰지 않는다.
    // 방금 올린 게 이 기기 내용이면 기준(baseEtag)만 옮겨 두어 다음 업로드가 충돌로 보이지 않게
    else if (now && result.vault.blob.ct === state.vault.blob.ct) await store.saveVault({ ...now, baseEtag: result.vault.baseEtag });
    await store.recordSync();
  } catch (e) {
    const reason = /취소/.test(e.message) ? "서버와 이 기기 양쪽에 변경이 있습니다. 설정에서 동기화를 눌러 선택하세요" : e.message;
    await store.recordSync(reason, { auto });
  }
}

async function autoSync() {
  if (Date.now() - lastAutoCheck < AUTO_CHECK_EVERY) return;
  lastAutoCheck = Date.now();
  const { mode, syncState } = await store.loadState();
  if (mode !== "server" || syncState.autoPaused) return;
  if (syncState.lastSync && Date.now() - syncState.lastSync < AUTO_SYNC_AFTER) return;
  chain = chain.then(() => syncOnce({ auto: true })).catch(() => {});
  return chain;
}

chrome.runtime.onStartup.addListener(() => autoSync());
chrome.tabs.onUpdated.addListener((_tabId, info) => {
  if (info.status === "complete") autoSync();
});

// ---------- QR 스캔 ----------

async function startScan(tabId) {
  if (!(await openVault(tabId))) return;
  await chrome.scripting.executeScript({ target: { tabId }, files: ["scan.js"] });
}

async function scanArea(tab, rect, viewportWidth) {
  const opened = await openVault(tab.id);
  if (!opened) return { error: true, message: "TapCode: 저장된 키를 열 수 없습니다. 팝업을 한 번 열어 주세요" };

  const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });
  const blob = await (await fetch(dataUrl)).blob();
  let crop = null;
  if (rect) {
    // CSS 픽셀 → 캡처 이미지 픽셀 (배율·확대 비율 반영)
    const bitmap = await createImageBitmap(blob);
    const scale = bitmap.width / viewportWidth;
    bitmap.close();
    crop = { x: rect.x * scale, y: rect.y * scale, w: rect.w * scale, h: rect.h * scale };
  }
  const text = await decodeQr(blob, crop);
  if (!text) return { error: true, message: "TapCode: QR 코드를 찾지 못했습니다. QR 주변을 조금 넓게 선택해 보세요" };

  const incoming = accountsFromQr(text);
  // 사이트에서 바로 스캔한 단일 QR 은 그 사이트를 자동 입력 대상으로 지정
  const host = /^https?:/.test(tab.url) ? new URL(tab.url).hostname : "";
  if (incoming.length === 1 && host) incoming[0].domain = baseDomain(host);

  const { merged, added, skipped } = mergeAccounts(opened.accounts, incoming);
  if (!added.length) return { message: "TapCode: 이미 등록된 계정입니다" };
  const saved = await saveAccounts(opened, merged);
  const uploaded = await uploadNow(opened, saved);

  const names = added.map((a) => [a.issuer, a.account].filter(Boolean).join(" · ")).join("\n");
  return {
    message: `TapCode: ${added.length}개 추가${skipped ? ` (중복 ${skipped}개 제외)` : ""}\n${names}${uploaded}`,
    error: uploaded.includes("실패"),
  };
}

// ---------- 자동 입력 ----------

async function autofill(tab) {
  const opened = await openVault(tab.id);
  if (!opened) return;
  const { accounts } = opened;
  const hostname = new URL(tab.url).hostname;
  const matches = findAccounts(accounts, hostname);
  if (!matches.length) {
    return pageToast(tab.id, `TapCode: ${hostname} 에 저장된 계정이 없습니다. 팝업을 열어 계정을 클릭하면 이 사이트가 저장됩니다`, true);
  }

  const account = matches[0];
  const code = await generate(account);
  const label = [account.issuer, account.account].filter(Boolean).join(" · ");
  const [{ result }] = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: fillCode,
    args: [code, label, matches.length],
  });

  // HOTP 는 쓸 때마다 카운터를 올려야 함 → 로컬에 반영하고 서버 모드면 바로 올린다
  if (result && account.type === "hotp") {
    await saveAccounts(opened, accounts.map((a) => (a.id === account.id ? { ...a, counter: a.counter + 1 } : a)));
    if (opened.state.mode === "server") queueSync();
  }
}

function pageToast(tabId, message, isError) {
  return chrome.scripting
    .executeScript({ target: { tabId }, func: showToast, args: [message, isError] })
    .catch(() => {}); // edge:// 등 스크립트를 넣을 수 없는 페이지
}

// ---- 아래 함수들은 페이지에 주입되어 실행된다 (외부 변수 참조 불가) ----

function showToast(message, isError) {
  const el = document.createElement("div");
  el.textContent = message;
  el.style.cssText =
    "position:fixed;z-index:2147483647;top:16px;right:16px;max-width:360px;padding:10px 14px;" +
    "border-radius:8px;font:13px/1.4 'Segoe UI','Malgun Gothic',sans-serif;color:#fff;" +
    `background:${isError ? "#c62828" : "#2563eb"};box-shadow:0 4px 12px rgba(0,0,0,.25)`;
  document.documentElement.append(el);
  setTimeout(() => el.remove(), 3000);
}

// quiet: 팝업 클릭에서 호출된 경우 입력칸이 없어도 페이지에 안내를 띄우지 않는다 (복사는 이미 됨)
function fillCode(code, label, matchCount, quiet) {
  const toast = (message, isError) => {
    const el = document.createElement("div");
    el.textContent = message;
    el.style.cssText =
      "position:fixed;z-index:2147483647;top:16px;right:16px;max-width:360px;padding:10px 14px;" +
      "border-radius:8px;font:13px/1.4 'Segoe UI','Malgun Gothic',sans-serif;color:#fff;" +
      `background:${isError ? "#c62828" : "#2563eb"};box-shadow:0 4px 12px rgba(0,0,0,.25)`;
    document.documentElement.append(el);
    setTimeout(() => el.remove(), 3000);
  };
  const usable = (el) =>
    el instanceof HTMLInputElement &&
    !el.disabled &&
    !el.readOnly &&
    ["text", "tel", "number", "password", "search", ""].includes(el.type) &&
    el.getClientRects().length > 0;
  // React/Vue 등이 값 변경을 감지하도록 네이티브 setter + input 이벤트 사용
  const setValue = (el, value) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };

  const inputs = [...document.querySelectorAll("input")].filter(usable);
  const boxes = inputs.filter((i) => i.maxLength === 1);
  let target = usable(document.activeElement) ? document.activeElement : null;
  target ??=
    inputs.find((i) => i.autocomplete === "one-time-code") ||
    inputs.find((i) =>
      /otp|totp|2fa|mfa|one.?time|verif|auth.?code|security.?code|\bcode\b|token|인증|코드/i.test(
        [i.name, i.id, i.placeholder, i.getAttribute("aria-label")].join(" ")
      )
    ) ||
    (boxes.length >= code.length ? boxes[0] : null);
  if (!target) {
    if (!quiet) toast("TapCode: 코드 입력칸을 찾지 못했습니다. 입력칸을 클릭한 뒤 다시 누르세요", true);
    return false;
  }

  // 한 칸에 한 글자씩 나뉜 입력칸 (□□□□□□)
  if (target.maxLength === 1) {
    const start = Math.max(0, Math.min(boxes.indexOf(target), boxes.length - code.length));
    boxes.slice(start, start + code.length).forEach((el, i) => setValue(el, code[i]));
    boxes[Math.min(start + code.length, boxes.length) - 1]?.focus();
  } else {
    target.focus();
    setValue(target, code);
  }
  toast(`TapCode: ${label} 코드 입력${matchCount > 1 ? ` (일치 계정 ${matchCount}개 중 첫 번째)` : ""}`);
  return true;
}
