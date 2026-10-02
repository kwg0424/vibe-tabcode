import { generate, secondsLeft, normalizeAccount } from "./src/totp.js";
import { encryptVault, decryptVault } from "./src/vault-crypto.js";
import { sync } from "./src/sync.js";
import { folderUrl, assertSecureUrl } from "./src/webdav.js";
import { findAccounts, addDomain, joinDomains, domainList } from "./src/match.js";
import { accountsFromQr, accountsFromText, mergeAccounts, toOtpauthUri } from "./src/qr-import.js";
import { decodeQr } from "./src/qr-decode.js";
import { credentialSecret, hasCredentials, newLocalKey, vaultSecret, LOCAL_KEY_ITERATIONS } from "./src/vault-key.js";
import { icon, fillIcons } from "./src/icons.js";
import * as store from "./src/storage.js";

const $ = (sel) => document.querySelector(sel);
fillIcons();

let mode = null; // "server" | "local"
let webdav = null; // { url, username, password }
let vault = null; // { blob, baseEtag, dirty }
let syncState = {}; // { lastSync, error, autoPaused } (storage.js)
let secret = null; // 금고 키 (vault-key.js)
let accounts = [];
let editing = false;
let ticker = null;
let pageHost = null; // 팝업을 연 탭의 사이트 (현재 사이트 표시용)

// ---------- 공통 UI ----------

function show(name) {
  // 목록을 떠나면(＋, 설정 등) 편집 모드 해제
  if (name !== "main") setEditing(false);
  for (const v of document.querySelectorAll(".view")) v.hidden = v.id !== `view-${name}`;
  clearInterval(ticker);
  if (name === "main") {
    renderList();
    ticker = setInterval(tick, 1000);
  }
  document.querySelector(`#view-${name} input:not([type=file])`)?.focus();
}

for (const btn of document.querySelectorAll("[data-goto]")) {
  btn.addEventListener("click", () => show(btn.dataset.goto));
}

let toastTimer;
function toast(message, isError = false) {
  const el = $("#toast");
  el.textContent = message;
  el.className = isError ? "error" : "";
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.hidden = true), isError ? 4000 : 2000);
}

async function busy(fn) {
  $("#busy").hidden = false;
  for (const b of document.querySelectorAll(".view button")) b.disabled = true;
  try {
    return await fn();
  } catch (e) {
    toast(e.message, true);
  } finally {
    $("#busy").hidden = true;
    for (const b of document.querySelectorAll(".view button")) b.disabled = false;
  }
}

function askConflict({ remoteUnreadable }) {
  const dlg = $("#conflict");
  $("#conflict-text").textContent = remoteUnreadable
    ? "서버 금고가 다른 접속 정보로 암호화되어 있어 열 수 없습니다. 이 기기 데이터로 서버 금고를 덮어쓸까요?"
    : "서버와 이 기기 양쪽에 변경 사항이 있습니다. 어느 쪽을 유지할까요?";
  $("#conflict-remote").hidden = remoteUnreadable;
  return new Promise((resolve) => {
    dlg.addEventListener("close", () => resolve(dlg.returnValue || null), { once: true });
    dlg.returnValue = "";
    dlg.showModal();
  });
}
for (const btn of document.querySelectorAll("#conflict button")) {
  btn.addEventListener("click", () => $("#conflict").close(btn.value));
}

// ---------- 금고 ----------

// key: 이 동기화에 쓸 금고 키 (접속 정보를 바꾸는 중이면 새 키). 성공했을 때만 상태에 반영
// 결과는 syncState 에 기록 (성공하면 자동 동기화 멈춤도 풀림). 접속 정보를 바꾸다 실패한 것과 사용자가 취소한 것은 남기지 않는다
// choose: 충돌 때 물을 방법 (기본은 대화상자)
async function runSync(cfg, key, local, choose = askConflict) {
  let result;
  try {
    result = await sync(cfg, key, local, choose);
  } catch (e) {
    if (cfg === webdav && !/취소/.test(e.message)) {
      await store.recordSync(e.message);
      syncState = (await store.loadState()).syncState;
    }
    throw e;
  }
  const opened = (await decryptVault(result.vault.blob, key)).accounts;
  vault = result.vault;
  secret = key;
  accounts = opened;
  await store.saveVault(vault);
  await store.recordSync();
  syncState = { lastSync: Date.now() };
  return result.action;
}

// 로컬 변경: 다시 암호화해서 저장. 서버 모드면 백그라운드가 바로 서버에 올린다 (팝업이 닫혀도 계속).
// 실패하거나 양쪽이 모두 바뀌었으면 미동기화로 남고, 설정의 동기화 버튼에서 처리한다
// upload: false = 호출한 쪽이 직접 동기화한다 (QR·가져오기는 충돌을 물을 수 있게 팝업에서 올림)
async function commit(next, { upload = true } = {}) {
  const blob = await encryptVault({ accounts: next }, secret, vault.blob);
  vault = { ...vault, blob, dirty: mode === "server" };
  await store.saveVault(vault);
  accounts = next;
  renderList();
  if (mode === "server" && upload) chrome.runtime.sendMessage({ action: "syncNow" }).catch(() => {});
}

const SYNC_MESSAGES = {
  pulled: "서버에서 키를 가져왔습니다",
  pushed: "서버에 저장했습니다",
  created: "서버에 새 금고를 만들었습니다",
  unchanged: "이미 최신 상태입니다",
};

// ---------- 목록 ----------

function timerSvg() {
  return `<svg class="timer" viewBox="0 0 26 26"><circle class="track" cx="13" cy="13" r="10"/><circle class="bar" cx="13" cy="13" r="10" stroke-dasharray="62.83"/></svg>`;
}

function renderList() {
  const list = $("#list");
  list.replaceChildren();
  $("#empty").hidden = accounts.length > 0;
  renderSyncState();

  // 현재 탭에서 Alt+X 를 누르면 입력될 계정 = 현재 사이트와 일치하는 계정
  const here = new Set(pageHost ? findAccounts(accounts, pageHost).map((a) => a.id) : []);

  // 화면 순서: 현재 사이트 일치 계정 먼저(왼쪽 위), 그다음 이름순(서비스명 → 계정).
  // 영어 A–Z 다음 한글 가–하, 대소문자 무시. 저장 순서는 그대로 둔다
  const byName = new Intl.Collator("en", { sensitivity: "base", numeric: true });
  const sorted = [...accounts].sort(
    (x, y) =>
      here.has(y.id) - here.has(x.id) ||
      byName.compare(x.issuer || x.account, y.issuer || y.account) ||
      byName.compare(x.account, y.account)
  );

  for (const a of sorted) {
    const li = document.createElement("li");
    li.dataset.id = a.id;
    // 블록 전체가 복사 버튼 (안의 ▶ 🔗 휴지통 버튼은 제외)
    li.className = here.has(a.id) ? "entry here" : "entry";
    li.tabIndex = 0;
    const name = [a.issuer, a.account].filter(Boolean).join(" · ");
    // 2열 좁은 칸이라 잘린 전체 이름·자동 입력 사이트는 툴팁으로
    li.title = `${name}${a.domain ? `\n자동 입력 사이트: ${domainList(a.domain).join(", ")}` : ""}`;
    // 편집 모드에서는 타이머 자리에 🔗 휴지통 버튼
    const side = editing
      ? `<button class="site mini" title="자동 입력 사이트 지정">${icon("link")}</button><button class="del mini" title="삭제">${icon("trash")}</button>`
      : a.type === "hotp"
        ? `<button class="next mini" title="다음 코드">${icon("next")}</button>`
        : timerSvg();
    li.innerHTML = `
      <div class="info">
        <div class="issuer"></div>
        <span class="code">------</span>
      </div>
      ${side}`;
    li.querySelector(".issuer").textContent = name;
    li.addEventListener("click", (e) => {
      if (!e.target.closest("button")) copyCode(li, a);
    });
    li.addEventListener("keydown", (e) => {
      if (e.target === li && (e.key === "Enter" || e.key === " ")) {
        e.preventDefault();
        copyCode(li, a);
      }
    });
    li.querySelector(".next")?.addEventListener("click", () => nextHotp(a));
    li.querySelector(".site")?.addEventListener("click", () => setSite(a));
    li.querySelector(".del")?.addEventListener("click", () => removeAccount(a));
    list.append(li);
  }
  tick();
}

async function tick() {
  const now = Date.now();
  for (const a of accounts) {
    const li = $(`#list li[data-id="${a.id}"]`);
    if (!li) continue;
    const codeEl = li.querySelector(".code");
    try {
      codeEl.textContent = await generate(a, now);
    } catch {
      codeEl.textContent = "오류";
    }
    if (a.type === "totp") {
      const left = secondsLeft(a.period, now);
      const bar = li.querySelector(".bar");
      if (bar) bar.style.strokeDashoffset = String(62.83 * (1 - left / a.period));
      // 남은 시간이 적으면 코드와 원을 같이 빨간색으로
      li.classList.toggle("expiring", left <= 5);
    }
  }
}

// 클릭: 복사 + 현재 탭 입력칸에 입력. 입력되면 팝업을 닫고, 입력칸이 없으면 복사만 하고 남는다.
async function copyCode(li, a) {
  const code = li.querySelector(".code").textContent;
  await navigator.clipboard.writeText(code);
  li.classList.remove("copied");
  void li.offsetWidth; // 연속 클릭 시에도 효과가 다시 재생되도록
  li.classList.add("copied");

  const name = a.issuer || a.account;
  const tab = await currentTab().catch(() => null);
  const label = [a.issuer, a.account].filter(Boolean).join(" · ");
  const res = tab?.id && /^https?:/.test(tab.url || "")
    ? await chrome.runtime.sendMessage({ action: "fillTab", tabId: tab.id, code, label }).catch(() => null)
    : null;
  if (res?.filled) {
    // 이 사이트에서 Alt+X 가 이 계정을 못 찾는 상태면 현재 사이트를 계정에 저장 → 다음부터 Alt+X 로 바로 입력
    const host = new URL(tab.url).hostname;
    let saved = "";
    if (!findAccounts(accounts, host).some((x) => x.id === a.id)) {
      await commit(accounts.map((x) => (x.id === a.id ? { ...x, domain: addDomain(x.domain, host) } : x)));
      saved = ` · ${host} 저장`;
    }
    toast(`${name} 코드 복사·입력됨${saved}`);
    setTimeout(() => window.close(), saved ? 1200 : 400);
  } else {
    toast(`${name} 코드 복사됨 (입력칸 없음)`);
  }
}

function nextHotp(a) {
  busy(() => commit(accounts.map((x) => (x.id === a.id ? { ...x, counter: x.counter + 1 } : x))));
}

async function setSite(a) {
  const current = domainList(a.domain).join(", ") || (await currentHost()) || "";
  const input = prompt(
    `"${a.issuer || a.account}" 코드를 자동 입력할 사이트 도메인\n(여러 개는 쉼표로 구분, 하위 도메인 포함, 비우면 서비스명으로 추정)`,
    current
  );
  if (input === null) return;
  busy(() => commit(accounts.map((x) => (x.id === a.id ? { ...x, domain: joinDomains(input) } : x))));
}

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function currentHost() {
  try {
    const url = new URL((await currentTab()).url);
    return /^https?:$/.test(url.protocol) ? url.hostname : null;
  } catch {
    return null;
  }
}

function removeAccount(a) {
  const note = mode === "server" ? "\n서버에서도 삭제됩니다." : "";
  if (!confirm(`"${a.issuer || a.account}" 계정을 삭제할까요?${note}`)) return;
  busy(() => commit(accounts.filter((x) => x.id !== a.id)));
}

function addAccount(account) {
  return busy(async () => {
    await commit([...accounts, account]);
    toast("추가했습니다");
    show("main");
  });
}

const addFromQr = (text) => addIncoming(accountsFromQr(text));

// QR·가져오기로 들어온 계정: 중복 제외 후 저장, 서버 모드면 바로 WebDAV 업로드
async function addIncoming(incoming, note = "") {
  const { merged, added, skipped } = mergeAccounts(accounts, incoming);
  if (!added.length) return toast(`추가할 새 계정이 없습니다${skipped ? ` (중복 ${skipped}개)` : ""}${note}`);
  await commit(merged, { upload: false });
  await clearDraft(); // 추가 완료 → 계정 추가 입력 유지 해제
  let msg = `${added.length}개 추가${skipped ? ` (중복 ${skipped}개 제외)` : ""}${note}`;
  if (mode === "server") {
    try {
      await runSync(webdav, secret, vault);
      msg += " · 서버에 업로드했습니다";
    } catch (e) {
      renderList();
      show("main");
      return toast(`${msg} · 업로드 실패: ${e.message}`, true);
    }
  }
  show("main");
  toast(msg);
}

// ---------- 저장 방식 ----------

// 프로필 저장 모드로 시작/전환: 새 무작위 키로 다시 암호화. 처음 실행하면 묻지 않고 이걸로 시작한다
async function useLocal(list, message) {
  const localKey = newLocalKey();
  const blob = await encryptVault({ accounts: list }, localKey, null, { iterations: LOCAL_KEY_ITERATIONS });
  mode = "local";
  webdav = null;
  secret = localKey;
  vault = { blob, baseEtag: null, dirty: false };
  accounts = list;
  await store.saveState({ mode, webdav, localKey, vault });
  if (message) toast(message);
  show("main");
}

function openConnect() {
  const f = $("#form-connect").elements;
  f.url.value = webdav ? folderUrl(webdav.url) : "";
  f.username.value = webdav?.username || "";
  // 저장된 비밀번호는 화면에 다시 채우지 않는다. 비워 두면 그대로 쓴다
  f.password.value = "";
  f.password.required = !webdav?.password;
  f.password.placeholder = webdav?.password ? "변경하지 않으려면 비워 두세요" : "";
  show("connect");
}

// 연결 화면은 설정에서만 들어온다
$("#connect-back").addEventListener("click", () => show("settings"));

// 사용자가 입력한 서버 도메인 접근 권한을 요청 (이미 허용됐으면 창 없이 통과) (사용자 클릭 직후에 호출해야 함)
function requestHostPermission(url) {
  const covered = (chrome.runtime.getManifest().host_permissions || []).some((p) =>
    new RegExp(`^${p.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`).test(url)
  );
  if (covered) return Promise.resolve(true);
  return chrome.permissions.request({ origins: [`${new URL(url).origin}/*`] });
}

$("#form-connect").addEventListener("submit", (e) => {
  e.preventDefault();
  const f = e.target.elements;
  const cfg = { url: folderUrl(f.url.value), username: f.username.value.trim(), password: f.password.value || webdav?.password || "" };
  if (!cfg.username) return toast("아이디를 입력하세요", true);
  if (cfg.username.includes(":")) return toast("아이디에는 : 를 쓸 수 없습니다", true);
  if (!cfg.password) return toast("비밀번호를 입력하세요", true);
  try {
    assertSecureUrl(`${cfg.url}/`);
  } catch (err) {
    return toast(err.message, true);
  }
  // 처음 보는 서버면 Edge 가 권한 창을 띄우고 그 사이 팝업이 닫힐 수 있다 → 연결할 내용을 메모리(storage.session)에 남겨 두고
  // 다음에 팝업을 열 때 이어서 연결한다 (resumeConnect). 권한 요청은 클릭 직후에 해야 해서 기다리지 않고 바로 이어 부른다
  chrome.storage.session.set({ pendingConnect: { cfg, at: Date.now() } });
  connectWith(cfg, requestHostPermission(`${cfg.url}/`));
});

const PENDING_CONNECT_TTL = 10 * 60 * 1000;

function connectWith(cfg, permission) {
  return busy(async () => {
    const granted = await permission;
    await chrome.storage.session.remove("pendingConnect");
    if (!granted) throw new Error("서버 접근 권한이 거부되었습니다");
    const key = credentialSecret(cfg);
    let local = null;
    // 계정이 없는 금고(처음 실행 직후 등)면 서버 금고를 그대로 받는다 — 묻지 않음
    if (vault && accounts.length) {
      // 기존 금고(프로필 모드 또는 다른 접속 정보)를 이 서버에 연결: 새 키로 다시 암호화해 올릴 대상으로 본다.
      // 서버에도 금고가 있으면 sync 가 충돌로 묻는다.
      const blob = key === secret ? vault.blob : await encryptVault({ accounts }, key);
      local = { blob, dirty: true, baseEtag: mode === "server" && webdav && folderUrl(webdav.url) === cfg.url ? vault.baseEtag : null };
    }
    // 연결할 때 서버 금고가 비어 있으면 묻지 않고 이 기기 금고를 올린다 (이 기기가 비었으면 위에서 local = null → 서버 금고를 받음)
    const action = await runSync(cfg, key, local, (info) => (info.remoteEmpty ? "local" : askConflict(info)));
    mode = "server";
    webdav = cfg;
    await store.saveState({ mode, webdav, localKey: null });
    toast(SYNC_MESSAGES[action]);
    show("main");
  });
}

// 권한 창 때문에 팝업이 닫혀 끊긴 연결을 이어서 한다
async function resumeConnect() {
  const { pendingConnect: p } = await chrome.storage.session.get("pendingConnect");
  if (!p) return false;
  if (Date.now() - p.at > PENDING_CONNECT_TTL) {
    await chrome.storage.session.remove("pendingConnect");
    return false;
  }
  openConnect();
  const f = $("#form-connect").elements;
  f.url.value = p.cfg.url;
  f.username.value = p.cfg.username;
  toast("서버 연결을 이어서 진행합니다");
  await connectWith(p.cfg, chrome.permissions.contains({ origins: [`${new URL(p.cfg.url).origin}/*`] }));
  return true;
}

// ---------- 메인 ----------

$("#btn-sync").addEventListener("click", () => {
  if (!hasCredentials(webdav)) return reconnectNeeded();
  busy(async () => {
    const action = await runSync(webdav, secret, vault);
    renderSyncState();
    toast(SYNC_MESSAGES[action]);
  });
});

// 1.3.0 토큰 방식 설정: 금고는 이 기기에서 열리지만 서버 인증은 아이디·비밀번호로 다시 연결해야 한다
function reconnectNeeded() {
  openConnect();
  toast("서버 인증이 아이디·비밀번호 방식으로 바뀌었습니다. 접속 정보를 다시 입력하세요", true);
}

// ---------- 계정 추가 입력 유지 ----------
// 팝업은 다른 곳을 클릭하면 닫히므로, 계정 추가 화면과 입력값을 기억했다가 다시 열 때 복원한다.
// 시크릿 키가 들어갈 수 있어 디스크가 아닌 메모리(storage.session)에만, 최대 10분 보관.
// 추가를 마치거나 < 로 나가면 지운다.
const DRAFT_TTL = 10 * 60 * 1000;
const DRAFT_FIELDS = ["issuer", "account", "secret", "domain", "type", "algorithm", "digits", "period"];

function saveDraft() {
  const f = $("#form-add").elements;
  const draft = { at: Date.now(), uri: $("#form-uri").elements.uri.value, advanced: $("#view-add details").open };
  for (const k of DRAFT_FIELDS) draft[k] = f[k].value;
  chrome.storage.session.set({ addDraft: draft });
}

const clearDraft = () => chrome.storage.session.remove("addDraft");

async function loadDraft() {
  const { addDraft } = await chrome.storage.session.get("addDraft");
  if (addDraft && Date.now() - addDraft.at < DRAFT_TTL) return addDraft;
  if (addDraft) await clearDraft();
  return null;
}

async function openAdd(draft) {
  $("#form-uri").reset();
  $("#form-add").reset();
  $("#qr-hint").textContent = "";
  show("add");
  const f = $("#form-add").elements;
  if (draft) {
    $("#form-uri").elements.uri.value = draft.uri || "";
    for (const k of DRAFT_FIELDS) if (draft[k] != null) f[k].value = draft[k];
    $("#view-add details").open = !!draft.advanced;
  } else {
    f.domain.value = (await currentHost()) || "";
  }
  saveDraft(); // 아무것도 안 쓰고 닫아도 다시 열면 계정 추가 화면
}

$("#view-add").addEventListener("input", saveDraft);
$("#view-add").addEventListener("change", saveDraft);
$("#view-add details").addEventListener("toggle", saveDraft);
$("#view-add .back").addEventListener("click", clearDraft);

$("#btn-add").addEventListener("click", async () => openAdd(await loadDraft()));

function setEditing(on) {
  editing = on;
  $("#btn-edit").classList.toggle("active", on); // 편집 중임을 표시
}

$("#btn-edit").addEventListener("click", () => {
  setEditing(!editing);
  renderList();
});

// ---------- 추가 ----------

$("#btn-scan").addEventListener("click", async () => {
  await clearDraft(); // 화면 스캔하러 나가면 다음에 열 때 목록으로
  const tab = await currentTab();
  const res = await chrome.runtime.sendMessage({ action: "startScan", tabId: tab.id });
  if (res?.error) {
    $("#qr-hint").textContent = "이 페이지에서는 스캔할 수 없습니다 (edge:// 페이지, 스토어 등). QR 이미지를 저장해 'QR 이미지' 버튼으로 추가하세요.";
    return;
  }
  window.close(); // 팝업을 닫아야 페이지에서 영역을 드래그할 수 있다
});

$("#qr-file").addEventListener("change", (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;
  busy(async () => {
    const text = await decodeQr(file);
    if (!text) throw new Error("이미지에서 QR 코드를 찾지 못했습니다");
    await addFromQr(text);
  });
});

$("#form-uri").addEventListener("submit", (e) => {
  e.preventDefault();
  const text = e.target.elements.uri.value;
  busy(async () => {
    await addFromQr(text); // 실패하면 입력값을 남겨 둔다
    e.target.reset();
    await clearDraft();
  });
});

$("#form-add").addEventListener("submit", (e) => {
  e.preventDefault();
  try {
    const account = normalizeAccount(Object.fromEntries(new FormData(e.target)));
    addAccount(account).then(() => {
      if (!$("#view-add").hidden) return; // 저장 실패로 화면에 남아 있으면 입력값 유지
      e.target.reset();
      clearDraft();
    });
  } catch (err) {
    toast(err.message, true);
  }
});

// ---------- 설정 ----------

const timeText = (t) => new Date(t).toLocaleString("ko-KR", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" });

// 메인: 서버 저장 실패 원인 한 줄 / 설정: 저장 방식·마지막 동기화, 동기화 버튼(미동기화·오류면 빨간 점)
function renderSyncState() {
  const server = mode === "server";
  const error = server && syncState.error;
  $("#sync-error").textContent = error ? `서버 저장 실패: ${syncState.error} (설정에서 동기화)` : "";
  $("#sync-error").hidden = !error;
  $("#btn-sync").hidden = !server;
  $("#dirty-dot").hidden = !(server && (vault?.dirty || error));
  $("#mode-info").textContent = server
    ? `저장 방식: 서버 동기화 (WebDAV)
${folderUrl(webdav.url)}${webdav.username ? ` · ${webdav.username}` : ""}
${syncStatusText()}`
    : "저장 방식: 이 브라우저 프로필에만 저장";
}

function syncStatusText() {
  const last = syncState.lastSync ? `마지막 동기화 ${timeText(syncState.lastSync)}` : "아직 동기화 기록 없음";
  if (!syncState.error) return `${last}${vault?.dirty ? " · 서버에 올리지 않은 변경 있음" : ""}`;
  if (syncState.autoPaused) return `${last}\n자동 동기화 실패: ${syncState.error}\n동기화 버튼이 성공할 때까지 자동 동기화를 멈춥니다`;
  return `${last}\n동기화 실패: ${syncState.error}`;
}

$("#btn-settings").addEventListener("click", async () => {
  renderSyncState();
  $("#btn-connect").textContent = mode === "server" ? "서버 접속 정보 변경" : "서버(WebDAV) 동기화로 전환";
  $("#btn-to-local").hidden = mode !== "server";

  const list = $("#shortcut-list");
  list.replaceChildren();
  for (const c of await chrome.commands.getAll()) {
    const li = document.createElement("li");
    const kbd = document.createElement("kbd");
    kbd.textContent = c.shortcut || "지정 안 됨";
    li.append(kbd, ` ${c.description || "팝업 열기"}`);
    list.append(li);
  }
  show("settings");
});

$("#btn-connect").addEventListener("click", () => openConnect());

$("#btn-to-local").addEventListener("click", async () => {
  const warn = vault.dirty ? "\n\n주의: 서버에 올리지 않은 변경 사항은 이 기기에만 남습니다." : "";
  if (!confirm(`브라우저 저장으로 전환할까요?\n이 브라우저 프로필에만 저장하고 서버 연결을 끊습니다. 서버 파일은 그대로 남습니다.${warn}`)) return;
  busy(() => useLocal(accounts, "브라우저 저장으로 전환했습니다"));
});

// OTP 내보내기: otpauth URI 를 한 줄씩 담은 .txt 파일로 저장 (다른 OTP 앱으로 옮기거나 백업용)
$("#btn-export").addEventListener("click", () => {
  if (!accounts.length) return toast("내보낼 계정이 없습니다", true);
  const warning =
    "파일에는 시크릿 키가 암호화되지 않은 채 들어 있어, 파일을 가진 사람은 누구나 같은 코드를 만들 수 있습니다. 계속할까요?";
  if (!confirm(`계정 ${accounts.length}개를 파일로 내보냅니다.\n${warning}`)) return;
  const date = new Date().toISOString().slice(0, 10);
  const header = `# TapCode OTP 백업 ${date} — 시크릿 키 포함, 안전하게 보관하세요`;
  const text = [header, ...accounts.map(toOtpauthUri), ""].join("\n");
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  const link = Object.assign(document.createElement("a"), { href: url, download: `tapcode-backup-${date.replaceAll("-", "")}.txt` });
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
  toast(`${accounts.length}개 내보냄`);
});

// OTP 가져오기: 내보낸 파일 또는 otpauth URI 가 줄마다 들어 있는 텍스트 파일
$("#import-file").addEventListener("change", (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;
  busy(async () => {
    if (file.size > 1024 * 1024) throw new Error("파일이 너무 큽니다");
    const { accounts: incoming, failed } = accountsFromText(await file.text());
    if (!incoming.length) throw new Error(`가져올 OTP 가 없습니다${failed ? ` (읽지 못한 줄 ${failed}개)` : ""}`);
    await addIncoming(incoming, failed ? ` · 읽지 못한 줄 ${failed}개` : "");
  });
});

$("#btn-reset").addEventListener("click", async () => {
  const warn = vault?.dirty ? "\n\n주의: 서버에 올리지 않은 변경 사항이 있습니다. 삭제하면 사라집니다." : "";
  const where = mode === "server" ? " 서버 데이터는 유지됩니다." : " 프로필 저장 모드라 키가 완전히 사라집니다.";
  if (!confirm(`이 기기의 설정과 키를 모두 삭제할까요?${where}${warn}`)) return;
  await store.clearLocal();
  syncState = {};
  await useLocal([], "이 기기 데이터를 삭제했습니다");
});

// 백그라운드 자동 동기화가 금고·동기화 상태를 바꾸면 반영 (이 팝업이 저장한 것은 메모리와 같아서 무시된다)
chrome.storage.onChanged.addListener(async (changes, area) => {
  // 이벤트 순서가 뒤바뀔 수 있어 newValue 대신 저장소의 최신 값을 읽는다
  if (area !== "local" || !(changes.vault || changes.syncState) || !secret) return;
  const latest = await store.loadState();
  if (latest.mode !== mode) return; // 저장 방식을 바꾸는 중 — 그쪽 흐름이 처리
  syncState = latest.syncState;
  if (latest.vault && latest.vault.blob?.ct !== vault?.blob?.ct) {
    try {
      accounts = (await decryptVault(latest.vault.blob, secret)).accounts;
    } catch {
      return; // 다른 키로 바뀌는 중 (접속 정보 변경) — 그쪽 흐름이 처리
    }
  }
  if (latest.vault) vault = latest.vault; // 백그라운드가 올린 뒤 바뀐 baseEtag·dirty 도 반영
  if (!$("#view-main").hidden) renderList();
  else renderSyncState();
});

// ---------- 시작 ----------

(async () => {
  pageHost = await currentHost();
  const state = await store.loadState();
  ({ mode, webdav, vault, syncState } = state);
  secret = vaultSecret(state);
  try {
    if (!mode || !vault || !secret) throw null;
    accounts = (await decryptVault(vault.blob, secret)).accounts;
  } catch {
    // 처음 실행이거나 열 수 없는 데이터(이전 버전 형식 등): 묻지 않고 이 브라우저 프로필 저장으로 시작한다.
    // 서버(WebDAV) 동기화는 설정에서 연결. 저장소의 옛 데이터는 이때 덮어쓴다
    const hadData = !!vault;
    await useLocal([], hadData ? "이전 버전 데이터라 열 수 없어 새로 시작합니다. 서버를 쓰셨다면 설정에서 다시 연결하세요" : "");
  }
  if (await resumeConnect()) return; // 권한 창 때문에 끊긴 연결이 있으면 이어서
  const draft = await loadDraft();
  if (draft) await openAdd(draft); // 계정 추가 중에 닫혔으면 그대로 복원
  else show("main");
  // 마지막 동기화가 하루를 넘었으면 백그라운드가 동기화 (결과는 storage.onChanged 로 반영)
  if (mode === "server") chrome.runtime.sendMessage({ action: "autoSync" }).catch(() => {});
})();
