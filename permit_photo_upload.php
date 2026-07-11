<?php
/**
 * permit_photo_upload.php — Photo upload + crop interstitial
 *
 * Flow: security.php "Print permit" button links here first
 *   1. Security uploads a photo file OR captures one from a webcam
 *   2. Photo is shown in a live cropper, locked to portrait ratio
 *   3. On "Approve & Print", the cropped image (base64 PNG) is POSTed
 *      to permit_card.php, permit_slip.php, or permit_label.php as `photo_data`
 *   4. Nothing is saved to disk or DB — fresh upload/capture required every print
 *
 * Usage: permit_photo_upload.php?id=42&type=card
 *        permit_photo_upload.php?id=42&type=slip
 *        permit_photo_upload.php?id=42&type=label   (W103 A4 label sheet, pick 1 of 8 slots)
 *
 * Note: webcam capture uses getUserMedia(), which requires HTTPS (or localhost).
 */
session_start();
require_once __DIR__ . '/config.php';

if (empty($_SESSION['security_id']) && empty($_SESSION['admin_id'])) {
    header('Location: security.php?action=login'); exit;
}

$id   = (int)($_GET['id'] ?? 0);
$typeParam = $_GET['type'] ?? '';
$type = in_array($typeParam, ['card', 'label'], true) ? $typeParam : 'slip';
if (!$id) die('Missing ID');

$sp = db()->prepare("SELECT id, service_name, category, unique_code FROM service_providers WHERE id=? LIMIT 1");
$sp->execute([$id]);
$sp = $sp->fetch();
if (!$sp) die('Record not found');

// Crop ratio differs slightly between permit formats — all close to a
// passport portrait, so one ratio family works for all three.
$cropTargetW = ($type === 'card') ? 240 : (($type === 'label') ? 320 : 320);  // px, output resolution
$cropTargetH = ($type === 'card') ? 320 : (($type === 'label') ? 427 : 400);  // ~3:4 portrait ratio

$printAction = ($type === 'card') ? 'permit_card.php'
             : (($type === 'label') ? 'permit_label.php' : 'permit_slip.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GEMB Permit Photo — <?= htmlspecialchars($sp['service_name']) ?></title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    font-family: Arial, sans-serif;
    background: #f4f6f8;
    color: #1a1a1a;
    padding: 24px;
  }
  .wrap {
    max-width: 560px;
    margin: 0 auto;
    background: #fff;
    border: 1px solid #dde3e8;
    border-radius: 8px;
    overflow: hidden;
  }
  .header {
    background: #1a3c5e;
    color: #fff;
    padding: 16px 20px;
  }
  .header h1 { font-size: 16px; font-weight: bold; margin-bottom: 2px; }
  .header p { font-size: 12px; opacity: 0.85; }

  .body { padding: 20px; }

  .step { margin-bottom: 18px; }
  .step-label {
    font-size: 12px;
    font-weight: bold;
    color: #1a3c5e;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    margin-bottom: 8px;
  }

  input[type=file] {
    display: block;
    width: 100%;
    padding: 10px;
    border: 1px dashed #b7c2cc;
    border-radius: 6px;
    background: #fafbfc;
    font-size: 13px;
  }

  .btn-camera {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    width: 100%;
    white-space: nowrap;
    font-size: 14px;
    font-weight: bold;
    padding: 14px 18px;
    border-radius: 6px;
    border: none;
    background: #1a3c5e;
    color: #fff;
    cursor: pointer;
  }
  .btn-camera:hover { background: #142d47; }
  .btn-camera:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .upload-toggle {
    display: block;
    text-align: center;
    font-size: 12px;
    color: #6a7c8c;
    text-decoration: underline;
    cursor: pointer;
    margin-top: 10px;
  }
  .upload-toggle:hover { color: #1a3c5e; }

  .file-fallback {
    display: none;
    margin-top: 10px;
  }
  .file-fallback.active { display: block; }

  /* ── Webcam capture area ── */
  .webcam-area {
    display: none;
    margin-top: 14px;
  }
  .webcam-area.active { display: block; }

  .webcam-box {
    position: relative;
    width: 100%;
    max-width: 320px;
    margin: 0 auto;
    aspect-ratio: 4 / 3;
    background: #111;
    overflow: hidden;
    border-radius: 6px;
  }
  .webcam-box video {
    width: 100%;
    height: 100%;
    object-fit: cover;
    display: block;
    transform: scaleX(-1); /* mirror preview only — captured frame is not mirrored */
  }

  .webcam-controls {
    display: flex;
    gap: 10px;
    justify-content: center;
    margin-top: 12px;
    max-width: 320px;
    margin-left: auto;
    margin-right: auto;
  }

  .cropper-area {
    display: none;
    margin-top: 14px;
  }
  .cropper-area.active { display: block; }

  .cropper-box {
    position: relative;
    width: 100%;
    max-width: 320px;
    margin: 0 auto;
    aspect-ratio: 3 / 4;
    background: #222;
    overflow: hidden;
    border-radius: 6px;
    cursor: grab;
    touch-action: none;
  }
  .cropper-box.dragging { cursor: grabbing; }
  .cropper-box img {
    position: absolute;
    top: 0;
    left: 0;
    transform-origin: 0 0;
    max-width: none;
    user-select: none;
    -webkit-user-drag: none;
  }

  .zoom-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 12px;
    max-width: 320px;
    margin-left: auto;
    margin-right: auto;
  }
  .zoom-row label { font-size: 12px; color: #555; white-space: nowrap; }
  .zoom-row input[type=range] { flex: 1; }

  .preview-row {
    display: none;
    align-items: center;
    gap: 16px;
    margin-top: 18px;
  }
  .preview-row.active { display: flex; }
  .preview-row .thumb {
    width: 70px;
    height: 88px;
    border: 1px solid #1a3c5e;
    border-radius: 4px;
    overflow: hidden;
    flex-shrink: 0;
    background: #e8edf2;
  }
  .preview-row .thumb img { width: 100%; height: 100%; object-fit: cover; display: block; }
  .preview-row .meta { font-size: 12px; color: #555; line-height: 1.6; }
  .preview-row .meta b { color: #1a1a1a; }

  .sp-info {
    background: #f0f4f8;
    border-radius: 6px;
    padding: 10px 14px;
    font-size: 13px;
    margin-bottom: 18px;
  }
  .sp-info b { color: #1a3c5e; }

  /* ── Label sheet position picker ── */
  .sheet-picker {
    max-width: 220px;
    margin: 0 auto;
  }
  .sheet-picker .grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 6px;
    border: 2px solid #b7c2cc;
    border-radius: 6px;
    padding: 8px;
    background: #f4f6f8;
  }
  .sheet-picker label {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 44px;
    border: 2px solid #dde3e8;
    border-radius: 4px;
    background: #fff;
    font-size: 13px;
    font-weight: bold;
    color: #555;
    cursor: pointer;
    user-select: none;
  }
  .sheet-picker input[type=radio] {
    position: absolute;
    opacity: 0;
    width: 0;
    height: 0;
  }
  .sheet-picker input[type=radio]:checked + label {
    border-color: #1a3c5e;
    background: #1a3c5e;
    color: #fff;
  }
  .sheet-picker .slot { position: relative; }

  .actions {
    display: flex;
    gap: 10px;
    margin-top: 22px;
    justify-content: flex-end;
  }
  button {
    font-size: 13px;
    font-weight: bold;
    padding: 10px 18px;
    border-radius: 6px;
    border: none;
    cursor: pointer;
  }
  .btn-secondary {
    background: #e9edf1;
    color: #444;
  }
  .btn-secondary:hover { background: #dde3e8; }
  .btn-primary {
    background: #1a3c5e;
    color: #fff;
  }
  .btn-primary:disabled {
    background: #aab8c2;
    cursor: not-allowed;
  }
  .btn-primary:not(:disabled):hover { background: #142d47; }

  .hint { font-size: 11px; color: #888; margin-top: 6px; }
</style>
</head>
<body>

<div class="wrap">

  <div class="header">
    <h1>Permit photo</h1>
    <p>Upload a clear, front-facing photo before printing the
      <?= $type === 'card' ? 'permit card' : ($type === 'label' ? 'permit label' : 'permit slip') ?>
    </p>
  </div>

  <div class="body">

    <div class="sp-info">
      <b><?= htmlspecialchars($sp['service_name']) ?></b><br>
      Code: <?= htmlspecialchars($sp['unique_code']) ?>
    </div>

    <div class="step">
      <div class="step-label">1. Capture photo</div>
      <button type="button" class="btn-camera" id="webcamBtn">📷 Capture Photo</button>
      <span class="upload-toggle" id="uploadToggle">or upload a file instead</span>

      <div class="file-fallback" id="fileFallback">
        <input type="file" id="fileInput" accept="image/*">
        <div class="hint">JPG, PNG, GIF, or WEBP. Will be cropped to a portrait shape.</div>
      </div>

      <div class="webcam-area" id="webcamArea">
        <div class="webcam-box">
          <video id="webcamVideo" autoplay playsinline muted></video>
        </div>
        <div class="webcam-controls">
          <button type="button" class="btn-secondary" id="webcamCancelBtn">Cancel</button>
          <button type="button" class="btn-primary" id="webcamCaptureBtn">Capture</button>
        </div>
      </div>
    </div>

    <div class="cropper-area" id="cropperArea">
      <div class="step-label">2. Adjust crop</div>
      <div class="cropper-box" id="cropperBox">
        <img id="cropperImg" src="" alt="">
      </div>
      <div class="zoom-row">
        <label for="zoomSlider">Zoom</label>
        <input type="range" id="zoomSlider" min="1" max="3" step="0.01" value="1">
      </div>
      <div class="hint" style="text-align:center;">Drag to reposition, use slider to zoom</div>
    </div>

    <div class="preview-row" id="previewRow">
      <div class="thumb"><img id="previewImg" src="" alt=""></div>
      <div class="meta">
        <b>Preview ready</b><br>
        This is exactly how the photo will appear<br>on the printed permit.
      </div>
    </div>

    <form id="printForm" method="POST" action="<?= htmlspecialchars($printAction) ?>?id=<?= $id ?>">
      <input type="hidden" name="photo_data" id="photoDataField">

      <?php if ($type === 'label'): ?>
      <div class="step" style="margin-top:18px;">
        <div class="step-label">3. Label position on sheet</div>
        <div class="sheet-picker">
          <div class="grid">
            <?php for ($p = 1; $p <= 8; $p++): ?>
            <div class="slot">
              <input type="radio" name="pos" value="<?= $p ?>"
                     id="posSlot<?= $p ?>" <?= $p === 1 ? 'checked' : '' ?>>
              <label for="posSlot<?= $p ?>"><?= $p ?></label>
            </div>
            <?php endfor; ?>
          </div>
        </div>
        <div class="hint" style="text-align:center;">
          Matches the physical sheet layout — 2 across, 4 down.<br>
          Pick the next empty label.
        </div>
      </div>
      <?php endif; ?>

      <div class="actions">
        <button type="button" class="btn-secondary" onclick="closeOrRedirect();">Cancel</button>
        <button type="button" class="btn-primary" id="approveBtn" disabled onclick="submitPermit();">Approve &amp; print</button>
      </div>
    </form>

  </div>
</div>

<script>
const fileInput       = document.getElementById('fileInput');
const cropperArea     = document.getElementById('cropperArea');
const cropperBox      = document.getElementById('cropperBox');
const cropperImg      = document.getElementById('cropperImg');
const zoomSlider      = document.getElementById('zoomSlider');
const previewRow      = document.getElementById('previewRow');
const previewImg      = document.getElementById('previewImg');
const approveBtn      = document.getElementById('approveBtn');
const photoField      = document.getElementById('photoDataField');
const printForm       = document.getElementById('printForm');

const webcamBtn        = document.getElementById('webcamBtn');
const webcamArea       = document.getElementById('webcamArea');
const webcamVideo      = document.getElementById('webcamVideo');
const webcamCaptureBtn = document.getElementById('webcamCaptureBtn');
const webcamCancelBtn  = document.getElementById('webcamCancelBtn');
const uploadToggle     = document.getElementById('uploadToggle');
const fileFallback     = document.getElementById('fileFallback');

uploadToggle.addEventListener('click', () => {
  const showing = fileFallback.classList.toggle('active');
  uploadToggle.textContent = showing ? 'or capture from webcam instead' : 'or upload a file instead';
  if (showing) stopWebcam();
});

const TARGET_W = <?= (int)$cropTargetW ?>;
const TARGET_H = <?= (int)$cropTargetH ?>;
const TARGET_RATIO = TARGET_W / TARGET_H;

let img = new Image();
let naturalW = 0, naturalH = 0;
let baseScale = 1;   // scale to cover the box at zoom = 1
let scale = 1;
let offsetX = 0, offsetY = 0;
let boxW = 0, boxH = 0;
let dragging = false, dragStartX = 0, dragStartY = 0, startOffX = 0, startOffY = 0;
let webcamStream = null;

// ── Shared entry point: both file upload and webcam capture feed into this ──
function loadImageFromDataUrl(dataUrl) {
  img = new Image();
  img.onload = () => {
    naturalW = img.naturalWidth;
    naturalH = img.naturalHeight;
    cropperImg.src = dataUrl;
    cropperArea.classList.add('active');
    previewRow.classList.remove('active');
    approveBtn.disabled = true;
    initCropper();
  };
  img.src = dataUrl;
}

fileInput.addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (ev) => loadImageFromDataUrl(ev.target.result);
  reader.readAsDataURL(file);
});

// ── Webcam capture ──
webcamBtn.addEventListener('click', startWebcam);
webcamCancelBtn.addEventListener('click', stopWebcam);
webcamCaptureBtn.addEventListener('click', captureWebcamFrame);

async function startWebcam() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    alert('Webcam capture is not supported in this browser. Use the file picker instead.');
    return;
  }
  try {
    webcamStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'user', width: { ideal: 1280 }, height: { ideal: 720 } },
      audio: false
    });
    webcamVideo.srcObject = webcamStream;
    webcamArea.classList.add('active');
    webcamBtn.disabled = true;
    fileFallback.classList.remove('active');
    uploadToggle.textContent = 'or upload a file instead';
  } catch (err) {
    alert('Could not access webcam:\n\n' + err.message
      + '\n\nCheck that a camera is connected and that this site has camera permission.');
  }
}

function stopWebcam() {
  if (webcamStream) {
    webcamStream.getTracks().forEach(t => t.stop());
    webcamStream = null;
  }
  webcamVideo.srcObject = null;
  webcamArea.classList.remove('active');
  webcamBtn.disabled = false;
}

function captureWebcamFrame() {
  const vw = webcamVideo.videoWidth;
  const vh = webcamVideo.videoHeight;
  if (!vw || !vh) {
    alert('Camera is still starting up — try again in a moment.');
    return;
  }
  // Draw the raw video frame (NOT the mirrored CSS preview) to a canvas.
  const canvas = document.createElement('canvas');
  canvas.width  = vw;
  canvas.height = vh;
  canvas.getContext('2d').drawImage(webcamVideo, 0, 0, vw, vh);
  const dataUrl = canvas.toDataURL('image/jpeg', 0.92);

  stopWebcam();
  loadImageFromDataUrl(dataUrl);
}

function initCropper() {
  const rect = cropperBox.getBoundingClientRect();
  boxW = rect.width;
  boxH = rect.height;

  const coverScale = Math.max(boxW / naturalW, boxH / naturalH);
  baseScale = coverScale;
  scale = 1;
  zoomSlider.value = 1;

  offsetX = (boxW - naturalW * baseScale) / 2;
  offsetY = (boxH - naturalH * baseScale) / 2;

  applyTransform();
  updatePreview();
}

function applyTransform() {
  const s = baseScale * scale;
  cropperImg.style.width = naturalW + 'px';
  cropperImg.style.height = naturalH + 'px';
  cropperImg.style.transform = `translate(${offsetX}px, ${offsetY}px) scale(${s})`;
}

function clampOffsets() {
  const s = baseScale * scale;
  const dispW = naturalW * s;
  const dispH = naturalH * s;
  const minX = boxW - dispW;
  const minY = boxH - dispH;
  offsetX = Math.min(0, Math.max(minX, offsetX));
  offsetY = Math.min(0, Math.max(minY, offsetY));
}

zoomSlider.addEventListener('input', () => {
  scale = parseFloat(zoomSlider.value);
  clampOffsets();
  applyTransform();
  updatePreview();
});

cropperBox.addEventListener('pointerdown', (e) => {
  dragging = true;
  cropperBox.classList.add('dragging');
  dragStartX = e.clientX;
  dragStartY = e.clientY;
  startOffX = offsetX;
  startOffY = offsetY;
  cropperBox.setPointerCapture(e.pointerId);
});
cropperBox.addEventListener('pointermove', (e) => {
  if (!dragging) return;
  offsetX = startOffX + (e.clientX - dragStartX);
  offsetY = startOffY + (e.clientY - dragStartY);
  clampOffsets();
  applyTransform();
});
cropperBox.addEventListener('pointerup', (e) => {
  dragging = false;
  cropperBox.classList.remove('dragging');
  updatePreview();
});
cropperBox.addEventListener('pointercancel', () => {
  dragging = false;
  cropperBox.classList.remove('dragging');
});

function updatePreview() {
  const canvas = document.createElement('canvas');
  canvas.width = TARGET_W;
  canvas.height = TARGET_H;
  const ctx = canvas.getContext('2d');

  const s = baseScale * scale;
  const sx = -offsetX / s;
  const sy = -offsetY / s;
  const sw = boxW / s;
  const sh = boxH / s;

  ctx.drawImage(img, sx, sy, sw, sh, 0, 0, TARGET_W, TARGET_H);

  const dataUrl = canvas.toDataURL('image/jpeg', 0.88);
  previewImg.src = dataUrl;
  photoField.value = dataUrl;
  previewRow.classList.add('active');
  approveBtn.disabled = false;
}

// Detect Edge on Android — needs special handling
function isEdgeAndroid() {
  const ua = navigator.userAgent || '';
  return /EdgA/i.test(ua) && /Android/i.test(ua);
}

function submitPermit() {
  // Regenerate the cropped image fresh at submit time.
  const canvas = document.createElement('canvas');
  canvas.width  = TARGET_W;
  canvas.height = TARGET_H;
  const ctx = canvas.getContext('2d');
  const s   = baseScale * scale;
  ctx.drawImage(img, -offsetX / s, -offsetY / s, boxW / s, boxH / s,
                0, 0, TARGET_W, TARGET_H);
  photoField.value = canvas.toDataURL('image/jpeg', 0.88);

  if (!photoField.value || photoField.value.length < 100) {
    alert('Photo data is missing. Please re-select or re-capture the photo and try again.');
    return;
  }

  approveBtn.disabled    = true;
  approveBtn.textContent = 'Generating PDF\u2026';

  if (isEdgeAndroid()) {
    // Edge on Android intercepts binary responses from form.submit() as failed
    // navigations. Instead: POST via fetch, receive the PDF blob, create an
    // object URL, open it in a new tab — Edge Android handles blob URLs correctly.
    const formData = new FormData(printForm);
    fetch(printForm.action, { method: 'POST', body: formData })
      .then(res => {
        if (!res.ok) throw new Error('Server returned ' + res.status);
        return res.blob();
      })
      .then(blob => {
        const blobUrl = URL.createObjectURL(blob);
        // Open blob URL in new tab — Edge Android handles this without a download prompt
        const win = window.open(blobUrl, '_blank');
        if (!win) {
          // Popup blocked — fall back to same-tab navigation
          window.location.href = blobUrl;
        }
        approveBtn.disabled    = false;
        approveBtn.textContent = 'Approve & print';
      })
      .catch(err => {
        approveBtn.disabled    = false;
        approveBtn.textContent = 'Approve & print';
        alert('Could not generate permit PDF.\n\n' + err.message);
      });
  } else {
    // All other browsers: plain synchronous POST to the same tab.
    // Most compatible across desktop Edge/Chrome, Chrome Android, Safari iOS.
    printForm.submit();
  }
}

function closeOrRedirect() {
  stopWebcam();
  window.close();
  setTimeout(() => {
    window.location.href = 'security.php?action=approvals';
  }, 150);
}

// Stop the camera if the user navigates away mid-capture
window.addEventListener('beforeunload', stopWebcam);

// Prevent accidental native submit (e.g. Enter key)
printForm.addEventListener('submit', (e) => { e.preventDefault(); });
</script>

</body>
</html>