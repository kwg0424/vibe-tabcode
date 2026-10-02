// 페이지에 주입되는 QR 영역 선택 오버레이. 드래그로 영역 선택, 클릭만 하면 화면 전체, Esc 취소.
(() => {
  if (window.__syncotpScanning) return;
  window.__syncotpScanning = true;

  const Z = 2147483647;
  const overlay = document.createElement("div");
  overlay.style.cssText = `position:fixed;inset:0;z-index:${Z};cursor:crosshair;background:rgba(0,0,0,.35);user-select:none`;
  const box = document.createElement("div");
  box.style.cssText = "position:fixed;border:2px solid #2563eb;background:rgba(37,99,235,.12);display:none;pointer-events:none";
  const help = document.createElement("div");
  help.textContent = "QR 코드 영역을 드래그하세요 (클릭: 화면 전체, Esc: 취소)";
  help.style.cssText =
    "position:fixed;top:16px;left:50%;transform:translateX(-50%);padding:8px 14px;border-radius:8px;" +
    "background:#2563eb;color:#fff;font:13px/1.4 'Segoe UI','Malgun Gothic',sans-serif;pointer-events:none";
  overlay.append(box, help);
  document.documentElement.append(overlay);

  let start = null;
  let rect = null;

  const cleanup = () => {
    overlay.remove();
    removeEventListener("keydown", onKey, true);
    window.__syncotpScanning = false;
  };
  const onKey = (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      cleanup();
    }
  };
  addEventListener("keydown", onKey, true);

  overlay.addEventListener("mousedown", (e) => {
    e.preventDefault();
    start = { x: e.clientX, y: e.clientY };
    rect = { x: e.clientX, y: e.clientY, w: 0, h: 0 };
    box.style.display = "block";
    help.style.display = "none";
  });

  overlay.addEventListener("mousemove", (e) => {
    if (!start) return;
    rect = {
      x: Math.min(start.x, e.clientX),
      y: Math.min(start.y, e.clientY),
      w: Math.abs(e.clientX - start.x),
      h: Math.abs(e.clientY - start.y),
    };
    Object.assign(box.style, { left: `${rect.x}px`, top: `${rect.y}px`, width: `${rect.w}px`, height: `${rect.h}px` });
  });

  overlay.addEventListener("mouseup", async () => {
    if (!start) return;
    const area = rect.w < 10 || rect.h < 10 ? null : rect;
    cleanup();
    // 오버레이가 화면에서 사라진 뒤 캡처되도록 두 프레임 대기
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    let res;
    try {
      res = await chrome.runtime.sendMessage({ action: "scanArea", rect: area, viewportWidth: innerWidth });
    } catch (e) {
      res = { error: true, message: `TapCode: ${e.message}` };
    }
    toast(res.message, res.error);
  });

  function toast(message, isError) {
    const el = document.createElement("div");
    el.textContent = message;
    el.style.cssText =
      `position:fixed;z-index:${Z};top:16px;right:16px;max-width:360px;padding:10px 14px;` +
      "border-radius:8px;font:13px/1.4 'Segoe UI','Malgun Gothic',sans-serif;color:#fff;white-space:pre-line;" +
      `background:${isError ? "#c62828" : "#2563eb"};box-shadow:0 4px 12px rgba(0,0,0,.25)`;
    document.documentElement.append(el);
    setTimeout(() => el.remove(), 4000);
  }
})();
