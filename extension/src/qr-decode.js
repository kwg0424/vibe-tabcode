// 이미지(Blob) → QR 텍스트. 서비스워커와 팝업 양쪽에서 동작 (OffscreenCanvas)
import "../vendor/jsqr/jsQR.js"; // self.jsQR 등록 (Apache-2.0)

// crop: 이미지 픽셀 단위 { x, y, w, h } — 없으면 전체
export async function decodeQr(blob, crop) {
  const bitmap = await createImageBitmap(blob);
  const x = Math.max(0, Math.round(crop?.x ?? 0));
  const y = Math.max(0, Math.round(crop?.y ?? 0));
  const w = Math.min(bitmap.width - x, Math.round(crop?.w ?? bitmap.width));
  const h = Math.min(bitmap.height - y, Math.round(crop?.h ?? bitmap.height));
  if (w < 1 || h < 1) return null;

  // 영역을 꽉 채운 QR은 가장자리 여백(quiet zone)이 없어 인식이 안 되므로 흰 여백을 붙인다
  const pad = Math.round(Math.max(w, h) * 0.1) + 8;
  const canvas = new OffscreenCanvas(w + pad * 2, h + pad * 2);
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.fillStyle = "#fff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.drawImage(bitmap, x, y, w, h, pad, pad, w, h);
  bitmap.close();

  const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const result = self.jsQR(img.data, img.width, img.height, { inversionAttempts: "attemptBoth" });
  return result?.data || null;
}
