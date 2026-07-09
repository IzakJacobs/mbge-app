<?php
/**
 * permit_card.php — GEMB Credit Card Permit (85×54mm)
 * For: domestic, resident_worker, contractor_lead
 * Called by: security.php?action=print_permit&id=XX
 *
 * Requires: Dompdf (already installed for export files)
 * Usage: permit_card.php?id=42
 *
 * v2 — adds photo support (sp.photo column, stored as filename or base64)
 */
session_start();
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/vendor/autoload.php';

use Dompdf\Dompdf;
use Dompdf\Options;

// Auth — security or admin only
if (empty($_SESSION['security_id']) && empty($_SESSION['admin_id'])) {
    header('Location: security.php?action=login'); exit;
}

$id = (int)($_GET['id'] ?? 0);
if (!$id) die('Missing ID');

$sp = db()->prepare("SELECT * FROM service_providers WHERE id=? LIMIT 1");
$sp->execute([$id]);
$sp = $sp->fetch();
if (!$sp) die('Record not found');

// ── Photo ────────────────────────────────────────────────
// Priority:
//   1. $_POST['photo_data'] — a fresh upload from permit_photo_upload.php
//      (data URI, not persisted — used once for this print only)
//   2. sp.photo — a stored filename or base64 string (legacy / future use)
//   3. empty — show a placeholder silhouette
$photoTag = '';
if (!empty($_POST['photo_data']) && str_starts_with($_POST['photo_data'], 'data:image/')) {
    $photoTag = '<img src="' . htmlspecialchars($_POST['photo_data']) . '">';
} elseif (!empty($sp['photo'])) {
    $raw = $sp['photo'];
    if (str_starts_with($raw, 'data:image/')) {
        // Already a data URI
        $photoTag = '<img src="' . htmlspecialchars($raw) . '">';
    } else {
        // Treat as filename
        $photoPath = __DIR__ . '/uploads/sp_photos/' . basename($raw);
        if (file_exists($photoPath)) {
            $mime      = mime_content_type($photoPath);
            $photoB64  = base64_encode(file_get_contents($photoPath));
            $photoTag  = '<img src="data:' . $mime . ';base64,' . $photoB64 . '">';
        }
    }
}
// Placeholder SVG silhouette when no photo
if (!$photoTag) {
    $photoTag = '<svg viewBox="0 0 60 80" xmlns="http://www.w3.org/2000/svg"
        style="width:100%;height:100%;display:block;">
      <rect width="60" height="80" fill="#e8edf2"/>
      <circle cx="30" cy="26" r="14" fill="#a0afc0"/>
      <ellipse cx="30" cy="72" rx="22" ry="16" fill="#a0afc0"/>
    </svg>';
}

// ── QR Code ──────────────────────────────────────────────
$qrLib = __DIR__ . '/phpqrcode/qrlib.php';
if (file_exists($qrLib)) {
    require_once $qrLib;
    $tempDir  = __DIR__ . '/temp';
    if (!is_dir($tempDir)) @mkdir($tempDir, 0755, true);
    $qrFile   = $tempDir . '/' . $sp['unique_code'] . '.png';
    $verifyUrl = SITE_URL . '/service_qr_verify.php?code='
               . urlencode($sp['unique_code']);
    if (!file_exists($qrFile)) {
        QRcode::png($verifyUrl, $qrFile, QR_ECLEVEL_M, 8, 2);
    }
    $qrBase64 = file_exists($qrFile)
        ? base64_encode(file_get_contents($qrFile)) : '';
} else {
    $qrBase64 = '';
}

if ($qrBase64) {
    $qrTag = '<img src="data:image/png;base64,' . $qrBase64 . '">';
} else {
    $qrUrl = 'https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl='
           . urlencode(SITE_URL . '/service_qr_verify.php?code=' . $sp['unique_code']);
    $qrTag = '<img src="' . $qrUrl . '">';
}

$catLabels = [
    'domestic'          => 'Domestic Worker',
    'resident_worker'   => 'Resident Worker',
    'contractor_lead'   => 'Contractor Lead',
    'contractor_worker' => 'Contractor Worker',
    'delivery'          => 'Delivery',
];
$catLabel  = $catLabels[$sp['category'] ?? 'domestic'] ?? 'Service Provider';
$validFrom = date('d M Y', strtotime($sp['start_date']));
$validTo   = date('d M Y', strtotime($sp['end_date']));

// ── HTML (85×54mm credit card) ───────────────────────────
$html = '<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family: Arial, sans-serif; background:#fff; }

  .page-table {
    width: 100%;
  }
  .page-table td {
    padding: 20 4mm 8mm 25;
    vertical-align: top;
  }

  /* 85×54mm card */
  .card {
    width: 85mm;
    height: 54mm;
    border: 0.5mm solid #1a3c5e;
    border-radius: 3mm;
    overflow: hidden;
    position: relative;
    background: #fff;
    page-break-inside: avoid;
  }

  /* Header band */
  .card-header-table {
    width: 100%;
    height: 8mm;
    background: #1a3c5e;
  }
  .card-header-table td {
    padding: 1.5mm 2mm 1mm;
    vertical-align: middle;
  }
  .estate {
    font-size: 5pt;
    font-weight: bold;
    letter-spacing: 0.3pt;
    text-transform: uppercase;
  }
  .cat {
    font-size: 4.5pt;
    background: #c8a84b;
    color: #000;
    padding: 0.5mm 1.5mm;
    border-radius: 1mm;
    font-weight: bold;
    white-space: nowrap;
  }

  /* Body: photo | details | QR — table layout for Dompdf reliability */
  .card-body-table {
    width: 100%;
    height: calc(54mm - 8mm - 6mm);
    border-collapse: collapse;
  }
  .card-body-table td {
    padding: 1.5mm;
    vertical-align: middle;
  }

  /* Photo strip — left */
  .card-photo {
    width: 18mm;
    height: 24mm;
    border: 0.3mm solid #d0d8e0;
    border-radius: 1mm;
    overflow: hidden;
    background: #e8edf2;
  }
  .card-photo img, .card-photo svg {
    width: 100%;
    height: 100%;
    object-fit: cover;
    display: block;
  }

  /* Details — centre */
  .card-details {
    min-width: 0;
  }
  .card-details .name {
    font-size: 6.5pt;
    font-weight: bold;
    color: #1a3c5e;
    line-height: 1.2;
    margin-bottom: 1mm;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .card-details .row {
    font-size: 5pt;
    color: #333;
    line-height: 1.5;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .card-details .row span { color: #888; }

  /* QR — right */
  .card-qr {
    width: 22mm;
    text-align: center;
  }
  .card-qr img {
    width: 20mm;
    height: 20mm;
  }
  .card-qr .code {
    font-size: 4.5pt;
    font-weight: bold;
    font-family: monospace;
    color: #1a3c5e;
    letter-spacing: 0.5pt;
    margin-top: 0.5mm;
    text-align: center;
  }

  /* Footer */
  .card-footer-table {
    position: absolute;
    bottom: 0;
    left: 0;
    right: 0;
    width: 100%;
    background: #f5f5f5;
    border-top: 0.3mm solid #ddd;
    height: 6mm;
  }
  .card-footer-table td {
    padding: 0.8mm 2mm;
    font-size: 4pt;
    color: #888;
    vertical-align: middle;
  }
</style>
</head><body><table class="page-table"><tr>';

for ($copy = 1; $copy <= 2; $copy++):
$html .= '
<td>
<div class="card">
  <table class="card-header-table"><tr>
    <td style="text-align:left;"><span class="estate" style="color:#fff;">MOSSEL BAY GOLF ESTATE</span></td>
    <td style="text-align:right;"><span class="cat">' . htmlspecialchars($catLabel) . '</span></td>
  </tr></table>

  <table class="card-body-table"><tr>

    <!-- Photo -->
    <td style="width:18mm;">
      <div class="card-photo">
        ' . $photoTag . '
      </div>
    </td>

    <!-- Details -->
    <td class="card-details">
      <div class="name">' . htmlspecialchars($sp['service_name']) . '</div>
      ' . ($sp['id_number'] ? '
      <div class="row"><span>ID: </span>' . htmlspecialchars($sp['id_number']) . '</div>' : '') . '
      ' . ($sp['company_name'] ? '
      <div class="row"><span>Co: </span>' . htmlspecialchars($sp['company_name']) . '</div>' : '') . '
      <div class="row"><span>Resident: </span>' . htmlspecialchars($sp['resident_name']) . '</div>
      <div class="row"><span>Erf: </span>' . htmlspecialchars($sp['resident_erfno']) . '</div>
      <div class="row"><span>Valid: </span>' . $validFrom . ' – ' . $validTo . '</div>
      <div class="row"><span>Hours: </span>'
        . htmlspecialchars($sp['access_days'] ?? 'Mon–Sat')
        . ' '
        . substr($sp['access_start'] ?? '07:00:00', 0, 5)
        . '–'
        . substr($sp['access_end']   ?? '17:00:00', 0, 5) . '
      </div>
    </td>

    <!-- QR -->
    <td class="card-qr">
      ' . $qrTag . '
      <div class="code">' . htmlspecialchars($sp['unique_code']) . '</div>
    </td>

  </tr></table>

  <table class="card-footer-table"><tr>
    <td style="text-align:left;">GEMB</td>
    <td style="text-align:right;">POPIA Act 4 of 2013</td>
  </tr></table>
</div>
</td>';
endfor;

$html .= '</tr></table></body></html>';

$opt = new Options();
$opt->set('isRemoteEnabled', true);
$pdf = new Dompdf($opt);
$pdf->loadHtml($html);
$pdf->setPaper('A4', 'portrait');
$pdf->render();
$output = $pdf->output();

// ── Audit log: save PDF to disk and record the print event ──
try {
    $monthDir = __DIR__ . '/uploads/permits/' . date('Y-m');
    if (!is_dir($monthDir)) @mkdir($monthDir, 0755, true);

    $filename = 'card_' . $sp['unique_code'] . '_' . date('YmdHis') . '.pdf';
    $filePath = $monthDir . '/' . $filename;
    $relPath  = '/uploads/permits/' . date('Y-m') . '/' . $filename;

    file_put_contents($filePath, $output);

    $purgeAfter = date('Y-m-d', strtotime($sp['end_date'] . ' +30 days'));

    db()->prepare("
        INSERT INTO permit_print_log
            (sp_id, unique_code, permit_type, printed_by_id, printed_by_name, printed_at, pdf_path, purge_after)
        VALUES (?, ?, 'card', ?, ?, NOW(), ?, ?)
    ")->execute([
        $sp['id'],
        $sp['unique_code'],
        $_SESSION['security_id']   ?? 0,
        $_SESSION['security_name'] ?? 'Security',
        $relPath,
        $purgeAfter,
    ]);
} catch (Exception $e) {
    error_log('permit_print_log save failed: ' . $e->getMessage());
}

// ── Stream PDF to browser ─────────────────────────────────
header('Content-Type: application/pdf');
header('Content-Disposition: inline; filename="permit_card_' . $sp['unique_code'] . '.pdf"');
header('Content-Length: ' . strlen($output));
header('Cache-Control: private, max-age=0, must-revalidate');
echo $output;
exit;
