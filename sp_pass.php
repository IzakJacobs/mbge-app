<?php
// ============================================================
// GEMB Access Control — sp_pass.php (public)
// Displays a Service Provider's invite pass, sent via WhatsApp/
// SMS/e-mail from visitor.php?action=sp_invite. Shown by the SP
// to the Security Officer to complete registration and collect
// their access permit (domestic / resident_worker / delivery —
// contractor_lead is routed to application_form.php instead, see
// spInviteContent() in visitor.php).
// URL: sp_pass.php?code={unique_code}
// ============================================================
require_once __DIR__ . '/layout.php';

$code = preg_replace('/[^0-9]/', '', (string)($_GET['code'] ?? ''));

if ($code === '' || !preg_match('/^\d{6}$/', $code)) {
    http_response_code(404); exit('Invalid or missing reference code.');
}

$sp = db()->prepare("SELECT * FROM service_providers WHERE unique_code=? LIMIT 1");
$sp->execute([$code]);
$sp = $sp->fetch();

if (!$sp) {
    http_response_code(404); exit('This invite could not be found. It may have expired, or the code was mistyped.');
}

$spCategories = [
    'domestic'        => ['icon' => '🏠', 'label' => 'Domestic Worker'],
    'resident_worker' => ['icon' => '🔧', 'label' => 'Resident Worker'],
    'contractor_lead' => ['icon' => '👷', 'label' => 'Contractor Lead'],
    'delivery'        => ['icon' => '📦', 'label' => 'Delivery'],
];
$cat = $spCategories[$sp['category']] ?? ['icon' => '🔧', 'label' => ucfirst((string)$sp['category'])];

if (!empty($sp['expired'])) {
    $statusInfo = ['text' => 'Expired', 'color' => '#6c757d'];
} else {
    $statusInfo = [
        'invited'  => ['text' => 'Invited — visit the Security Office', 'color' => '#17a2b8'],
        'pending'  => ['text' => 'Pending review',                      'color' => '#ffc107'],
        'approved' => ['text' => 'Approved',                            'color' => '#28a745'],
        'revoked'  => ['text' => 'Revoked',                             'color' => '#dc3545'],
    ][$sp['status']] ?? ['text' => ucfirst((string)$sp['status']), 'color' => '#6c757d'];
}

// ── QR code — encodes a full human-readable summary (not just the
//    bare code) so a guard's scanner shows everything at a glance:
//    Name / Resident / Erf / Valid dates / Hours / Category / Code.
//    Written to /temp/, same proven pattern as generateQrForVisitor().
$qrLines = [$sp['service_name']];
$qrLines[] = 'Resident: ' . (string)($sp['resident_name'] ?? '');
if (!empty($sp['resident_erfno'])) $qrLines[] = 'Erf: ' . $sp['resident_erfno'];
if (!empty($sp['start_date']) && !empty($sp['end_date'])) {
    $qrLines[] = 'Valid: ' . date('d M Y', strtotime($sp['start_date'])) . ' – ' . date('d M Y', strtotime($sp['end_date']));
}
$hoursBits = [];
if (!empty($sp['access_days']))  $hoursBits[] = $sp['access_days'];
if (!empty($sp['access_start']) && !empty($sp['access_end'])) {
    $hoursBits[] = substr($sp['access_start'], 0, 5) . '–' . substr($sp['access_end'], 0, 5);
}
if ($hoursBits) $qrLines[] = 'Hours: ' . implode(' ', $hoursBits);
$qrLines[] = $cat['label'];
$qrLines[] = $sp['unique_code'];
$qrText = implode("\n", $qrLines);

$qrUrl = '';
$qrLib = __DIR__ . '/phpqrcode/qrlib.php';
if (file_exists($qrLib)) {
    require_once $qrLib;
    $tempDir  = __DIR__ . '/temp';
    if (!is_dir($tempDir)) @mkdir($tempDir, 0755, true);
    $qrFile   = $tempDir . '/sp_' . $code . '.png';
    if (!file_exists($qrFile)) {
        QRcode::png($qrText, $qrFile, QR_ECLEVEL_M, 6, 2);
    }
    if (file_exists($qrFile)) {
        $qrUrl = '/temp/sp_' . $code . '.png';
    }
}

function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= h($cat['label']) ?> Pass — GEMB</title>
<style>
:root { --navy:#1a2f5a; --teal:#1a8a8a; --bg:#f5f7fa; --line:#d7dee8; }
* { box-sizing:border-box; }
body { font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); margin:0; color:#222; }
.wrap { max-width:420px; margin:0 auto; padding:16px; }
header.gemb { background:var(--navy); color:#fff; padding:18px 16px; text-align:center; }
header.gemb h1 { margin:0; font-size:1.15rem; }
header.gemb .sub { font-size:.8rem; opacity:.85; margin-top:2px; }
.card { background:#fff; border:1px solid var(--line); border-radius:12px; padding:22px; margin:16px 0; text-align:center; }
.qr { margin:14px auto; }
.qr img { width:200px; height:200px; }
.code { font-size:1.6rem; font-weight:800; letter-spacing:.15em; color:var(--navy); margin:10px 0; }
.badge { display:inline-block; padding:5px 14px; border-radius:20px; color:#fff; font-size:.8rem; font-weight:700; margin-bottom:10px; }
.field { text-align:left; font-size:.9rem; margin:8px 0; border-bottom:1px solid #eee; padding-bottom:8px; }
.field .label { color:#888; font-size:.75rem; text-transform:uppercase; }
.note { font-size:.82rem; color:#555; background:#eef6f6; border-left:4px solid var(--teal); border-radius:0 8px 8px 0; padding:12px 14px; margin-top:16px; text-align:left; line-height:1.5; }
</style>
</head>
<body>
<header class="gemb">
  <h1><?= $cat['icon'] ?> <?= h($cat['label']) ?> Pass</h1>
  <div class="sub">Mossel Bay Golf Estate HOA</div>
</header>
<div class="wrap">
  <div class="card">
    <span class="badge" style="background:<?= $statusInfo['color'] ?>"><?= h($statusInfo['text']) ?></span>

    <?php if ($qrUrl): ?>
    <div class="qr"><img src="<?= h($qrUrl) ?>" alt="QR code"></div>
    <?php endif; ?>

    <div class="code"><?= h($sp['unique_code']) ?></div>

    <div class="field"><div class="label">Name</div><?= h($sp['service_name']) ?></div>
    <?php if (!empty($sp['company_name'])): ?>
    <div class="field"><div class="label">Company</div><?= h($sp['company_name']) ?></div>
    <?php endif; ?>
    <div class="field"><div class="label">Invited by</div><?= h((string)($sp['resident_name'] ?? '')) ?><?= !empty($sp['resident_erfno']) ? ' (Erf ' . h($sp['resident_erfno']) . ')' : '' ?></div>
    <?php if (!empty($sp['start_date']) && !empty($sp['end_date'])): ?>
    <div class="field"><div class="label">Valid</div><?= h(date('d M Y', strtotime($sp['start_date']))) ?> – <?= h(date('d M Y', strtotime($sp['end_date']))) ?></div>
    <?php endif; ?>
    <?php if (!empty($sp['notes'])): ?>
    <div class="field"><div class="label">Work</div><?= h($sp['notes']) ?></div>
    <?php endif; ?>

    <?php if ($sp['status'] === 'invited' && empty($sp['expired'])): ?>
    <div class="note">
      Please visit the <strong>GEMB Security Office</strong> with your ID document
      to complete registration and collect your access permit. Show this screen —
      or your reference code above — to the Security Officer.
    </div>
    <?php elseif ($sp['status'] === 'approved'): ?>
    <div class="note">Your access permit is active.</div>
    <?php elseif ($sp['status'] === 'revoked'): ?>
    <div class="note">This access has been revoked. Please contact the resident who invited you.</div>
    <?php elseif (!empty($sp['expired'])): ?>
    <div class="note">This invite has expired. Please ask the resident to send a new one.</div>
    <?php endif; ?>
  </div>
</div>
</body>
</html>