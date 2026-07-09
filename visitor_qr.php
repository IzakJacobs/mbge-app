<?php
/**
 * visitor_qr.php  — GEMB Visitor Pass display (visitor's phone)
 * Code format:  3XXXXX  (digit 3 + 5 digits, e.g. 368652)
 * QR payload:   https://gemb.co.za/visitor_qr_verify.php?code=368652
 */
session_start();
require 'config.php';
date_default_timezone_set('Africa/Johannesburg');

/* ── validate: must start with 3, exactly 6 digits ── */
$code = trim($_GET['code'] ?? '');
if (!preg_match('/^3\d{5}$/', $code)) {
    http_response_code(400);
    exit('⛔ Invalid visitor code.');
}

/* ── fetch visitor record ──
   visitors links to residents via resident_name (no erfno FK)       */
$stmt = $conn->prepare(
    "SELECT v.*, r.address
     FROM visitors v
     LEFT JOIN residents r ON v.resident_name = r.resident_name
     WHERE v.code = ?
     LIMIT 1"
);
$stmt->bind_param('s', $code);
$stmt->execute();
$visitor = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$visitor) {
    http_response_code(404);
    exit('⛔ Visitor pass not found.');
}

/* ── column name fallbacks ── */
$visitFrom = $visitor['visit_date']    ?? date('Y-m-d');
$visitTo   = $visitor['visit_date_to'] ?? $visitFrom;

/* ── date validity ── */
$now   = new DateTime();
$start = new DateTime($visitFrom . ' 00:00:00');
$end   = new DateTime($visitTo   . ' 23:59:59');

if ($now < $start) {
    $access      = false;
    $statusClass = 'early';
    $headline    = '🕐 Not Yet Active';
    $subline     = 'Valid from ' . date('d M Y', strtotime($visitFrom));
} elseif ($now > $end) {
    $access      = false;
    $statusClass = 'expired';
    $headline    = '⛔ Pass Expired';
    $subline     = 'Expired ' . date('d M Y', strtotime($visitTo));
} else {
    $access      = true;
    $statusClass = 'valid';
    $headline    = '✅ Valid Pass';
    $subline     = 'Present to guard on arrival.';

    /* log first arrival */
    if (empty($visitor['arrival'])) {
        $conn->query("ALTER TABLE visitors ADD COLUMN IF NOT EXISTS arrival DATETIME DEFAULT NULL");
        $arr = $now->format('Y-m-d H:i:s');
        $u   = $conn->prepare("UPDATE visitors SET arrival = ? WHERE code = ?");
        if ($u) { $u->bind_param('ss', $arr, $code); $u->execute(); $u->close(); }
        $visitor['arrival'] = $arr;
    }
}

/* ── QR code ── */
$verifyUrl = 'https://gemb.co.za/visitor_qr_verify.php?code=' . urlencode($code);
$qrImgTag  = '';

$qrLib = __DIR__ . '/phpqrcode/qrlib.php';
if (file_exists($qrLib)) {
    require_once $qrLib;
    $tempDir = __DIR__ . '/temp';
    if (!is_dir($tempDir)) @mkdir($tempDir, 0755, true);
    $qrFile = $tempDir . '/' . $code . '.png';
    if (!file_exists($qrFile)) {
        QRcode::png($verifyUrl, $qrFile, QR_ECLEVEL_M, 6, 2);
    }
    if (file_exists($qrFile)) {
        $b64      = base64_encode(file_get_contents($qrFile));
        $qrImgTag = '<img src="data:image/png;base64,' . $b64 . '" '
                  . 'width="180" height="180" alt="QR code" '
                  . 'style="border:3px solid #0f2744;border-radius:10px;">';
    }
}
if (!$qrImgTag) {
    $gcUrl    = 'https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=' . urlencode($verifyUrl);
    $qrImgTag = '<img src="' . htmlspecialchars($gcUrl) . '" '
              . 'width="180" height="180" alt="QR code" '
              . 'style="border:3px solid #0f2744;border-radius:10px;">';
}

/* ── display values ── */
$fmtFrom      = date('d M Y', strtotime($visitFrom));
$fmtTo        = date('d M Y', strtotime($visitTo));
$visitorName  = $visitor['visitor_name']  ?? '—';
$residentName = $visitor['resident_name'] ?? '—';
$address      = $visitor['address']       ?? '';
$vehicleReg   = $visitor['plate']         ?? $visitor['vehicle_reg'] ?? '';

/* ── navigation map links ── */
$hasNav     = !empty($address);
$navQuery   = urlencode($address . ', Mossel Bay, South Africa');
$googleUrl  = 'https://www.google.com/maps/dir/?api=1&destination=' . $navQuery;
$wazeUrl    = 'https://waze.com/ul?q=' . $navQuery . '&navigate=yes';
$appleUrl   = 'https://maps.apple.com/?daddr=' . $navQuery;
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
  <title>GEMB Visitor Pass</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
      background: #0f2744;
      min-height: 100vh;
      display: flex;
      align-items: flex-start;
      justify-content: center;
      padding: 24px 16px 40px;
    }
    .card {
      background: #fff;
      border-radius: 20px;
      width: 100%;
      max-width: 420px;
      overflow: hidden;
      box-shadow: 0 8px 40px rgba(0,0,0,0.35);
    }
    .card-header {
      background: #0f2744;
      color: #fff;
      text-align: center;
      padding: 20px 24px 18px;
      border-bottom: 3px solid #c8a84b;
    }
    .card-header .logo { font-size: 2.2rem; margin-bottom: 4px; }
    .card-header h1   { font-size: 1.2rem; font-weight: 700; letter-spacing: 0.05em; }
    .card-header p    { font-size: 0.8rem; opacity: 0.7; margin-top: 2px; }
    .status-banner {
      margin: 20px 20px 0;
      border-radius: 12px;
      padding: 16px 20px;
      text-align: center;
    }
    .status-banner.valid   { background: #e8f8ee; border: 2px solid #2ecc71; }
    .status-banner.expired { background: #fdecea; border: 2px solid #e74c3c; }
    .status-banner.early   { background: #fff8e1; border: 2px solid #f39c12; }
    .status-headline { font-size: 1.05rem; font-weight: 700; color: #1a1a1a; }
    .status-sub      { font-size: 0.85rem; color: #555; margin-top: 4px; }
    .qr-block        { text-align: center; padding: 20px 20px 8px; }
    .qr-caption      { font-size: 0.75rem; color: #888; margin-top: 6px; }
    .code-chip {
      margin: 8px 20px 0;
      background: #f5f7fa;
      border: 2px solid #dde3ea;
      border-radius: 10px;
      padding: 12px;
      text-align: center;
      font-family: 'Courier New', monospace;
      font-size: 1.9rem;
      font-weight: 800;
      letter-spacing: 0.25em;
      color: #0f2744;
    }
    .details { padding: 14px 20px 0; }
    .detail-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      padding: 10px 0;
      border-bottom: 1px solid #eef0f3;
      font-size: 0.95rem;
    }
    .detail-row:last-child { border-bottom: none; }
    .detail-label { color: #666; font-weight: 600; flex-shrink: 0; min-width: 95px; }
    .detail-value { text-align: right; color: #1a1a1a; font-weight: 500;
                    word-break: break-word; max-width: 58%; }

    /* ── Navigation section ── */
    .nav-divider {
      margin: 16px 20px 0;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .nav-divider::before,
    .nav-divider::after {
      content: '';
      flex: 1;
      height: 1px;
      background: linear-gradient(to right, transparent, #c8a84b, transparent);
    }
    .nav-divider span {
      font-size: .72rem;
      font-weight: 700;
      color: #c8a84b;
      text-transform: uppercase;
      letter-spacing: .8px;
      white-space: nowrap;
    }
    .nav-section { padding: 16px 20px 20px; }
    .nav-heading {
      text-align: center;
      margin-bottom: 14px;
    }
    .nav-heading .pin  { font-size: 1.8rem; margin-bottom: 4px; }
    .nav-heading h3    { font-size: 1rem; font-weight: 700; color: #0f2744; }
    .nav-heading .addr {
      font-size: .82rem; color: #555; margin-top: 5px;
      line-height: 1.5; font-style: italic;
    }
    .nav-btn {
      display: flex;
      align-items: center;
      gap: 14px;
      padding: 14px 16px;
      border-radius: 12px;
      text-decoration: none;
      border: 2px solid #eee;
      margin-bottom: 10px;
      background: #fff;
      color: #1a1a1a;
      font-weight: 600;
      font-size: .95rem;
      box-shadow: 0 1px 4px rgba(0,0,0,.06);
      transition: border-color .15s, background .15s;
    }
    .nav-btn:last-of-type { margin-bottom: 0; }
    .nav-btn:active { background: #f5f7fa; border-color: #c8a84b; }
    .nav-btn .nav-icon  { font-size: 1.4rem; width: 28px; text-align: center; flex-shrink: 0; }
    .nav-btn .nav-label { flex: 1; }
    .nav-btn .nav-arrow { font-size: 1.1rem; color: #c8a84b; }
    .nav-hint {
      font-size: .72rem; color: #bbb; text-align: center;
      margin-top: 12px; line-height: 1.5;
    }

    .card-footer {
      margin: 16px 20px 20px;
      text-align: center;
      font-size: 0.72rem;
      color: #aaa;
      line-height: 1.6;
    }
  </style>
</head>
<body>
<div class="card">

  <div class="card-header">
    <div class="logo">🏌️</div>
    <h1>GEMB Visitor Pass</h1>
    <p>Mossel Bay Golf Estate</p>
  </div>

  <div class="status-banner <?= $statusClass ?>">
    <div class="status-headline"><?= htmlspecialchars($headline) ?></div>
    <div class="status-sub"><?= htmlspecialchars($subline) ?></div>
  </div>

  <?php if ($access): ?>
  <div class="qr-block">
    <?= $qrImgTag ?>
    <div class="qr-caption">Guard scans this QR to open the gate</div>
  </div>
  <?php endif; ?>

  <div class="code-chip"><?= htmlspecialchars($code) ?></div>

  <div class="details">
    <div class="detail-row">
      <span class="detail-label">Visitor</span>
      <span class="detail-value"><?= htmlspecialchars($visitorName) ?></span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Visiting</span>
      <span class="detail-value"><?= htmlspecialchars($residentName) ?></span>
    </div>
    <?php if ($address): ?>
    <div class="detail-row">
      <span class="detail-label">Address</span>
      <span class="detail-value"><?= htmlspecialchars($address) ?></span>
    </div>
    <?php endif; ?>
    <div class="detail-row">
      <span class="detail-label">Visit Date</span>
      <span class="detail-value"><?= $fmtFrom ?></span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Until</span>
      <span class="detail-value"><?= $fmtTo ?></span>
    </div>
    <?php if ($vehicleReg): ?>
    <div class="detail-row">
      <span class="detail-label">Vehicle</span>
      <span class="detail-value"><?= htmlspecialchars(strtoupper($vehicleReg)) ?></span>
    </div>
    <?php endif; ?>
    <?php if (!empty($visitor['arrival'])): ?>
    <div class="detail-row">
      <span class="detail-label">Arrived</span>
      <span class="detail-value"><?= date('d M Y H:i', strtotime($visitor['arrival'])) ?></span>
    </div>
    <?php endif; ?>
  </div>

  <?php
  /* ── WhatsApp send button (shown after pass creation) ── */
  $isNew        = !empty($_GET['new']);
  $visitorPhone = $visitor['visitor_phone'] ?? '';
  if ($access && ($isNew || $visitorPhone)):
      $waMsg  = "🏡 GEMB Visitor Pass\n\n"
              . "Your access pass for Mossel Bay Golf Estate:\n\n"
              . "📅 Valid: {$fmtFrom} – {$fmtTo}\n"
              . "🏠 Visiting: {$residentName}\n"
              . "🔑 Gate code: {$code}\n\n"
              . "👇 Open your pass:\n"
              . "https://gemb.co.za/visitor_qr.php?code={$code}\n\n"
              . "Show the QR to the guard or give them your 6-digit code.";
      $phone  = preg_replace('/\D/', '', $visitorPhone);
      if (substr($phone, 0, 1) === '0') $phone = '27' . substr($phone, 1);
      elseif (substr($phone, 0, 2) !== '27') $phone = '27' . $phone;
      $waLink = 'https://wa.me/' . $phone . '?text=' . rawurlencode($waMsg);
  ?>
  <div style="padding: 0 20px 16px;">
    <a href="<?= htmlspecialchars($waLink) ?>"
       style="display:block; width:100%; padding:16px; background:#25D366; color:#fff;
              border-radius:12px; text-align:center; font-size:1.05rem; font-weight:800;
              text-decoration:none; margin-bottom:10px;">
      📲 Send Pass via WhatsApp
    </a>
    <?php if ($visitorPhone): ?>
    <a href="sms:<?= preg_replace('/\D/','',$visitorPhone) ?>?body=<?= rawurlencode("GEMB Visitor Pass — open your pass: https://gemb.co.za/visitor_qr.php?code={$code}") ?>"
       style="display:block; width:100%; padding:14px; background:#f5f7fa; color:#0f2744;
              border:2px solid #dde3ea; border-radius:12px; text-align:center;
              font-size:0.95rem; font-weight:700; text-decoration:none;">
      💬 Send via SMS instead
    </a>
    <?php endif; ?>
  </div>
  <?php endif; ?>

  <!-- ── GPS Navigation ── -->
  <?php if ($hasNav): ?>
  <div class="nav-divider"><span>Get Directions</span></div>

  <div class="nav-section">
    <div class="nav-heading">
      <div class="pin">📍</div>
      <h3>Navigate to Resident's Home</h3>
      <div class="addr"><?= htmlspecialchars($address) ?></div>
    </div>

    <a href="<?= htmlspecialchars($googleUrl) ?>" target="_blank" rel="noopener"
       class="nav-btn">
      <span class="nav-icon">🗺️</span>
      <span class="nav-label">Google Maps</span>
      <span class="nav-arrow">›</span>
    </a>

    <a href="<?= htmlspecialchars($wazeUrl) ?>" target="_blank" rel="noopener"
       class="nav-btn">
      <span class="nav-icon">🚗</span>
      <span class="nav-label">Waze</span>
      <span class="nav-arrow">›</span>
    </a>

    <a href="<?= htmlspecialchars($appleUrl) ?>" target="_blank" rel="noopener"
       class="nav-btn">
      <span class="nav-icon">🍎</span>
      <span class="nav-label">Apple Maps</span>
      <span class="nav-arrow">›</span>
    </a>

    <div class="nav-hint">
      Show your pass to the guard at the estate entrance first,<br>
      then follow navigation to the resident's home.
    </div>
  </div>
  <?php endif; ?>

  <div class="card-footer">
    Present this screen to the guard on arrival.<br>
    GEMB &nbsp;|&nbsp; POPIA Act 4 of 2013
  </div>

</div>
</body>
</html>
