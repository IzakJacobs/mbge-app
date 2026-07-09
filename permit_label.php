<?php
/**
 * permit_label.php — GEMB Permit Card for W103 A4 label sheets
 * Label stock: TOWER W103 (8up), 101 x 70mm, 2 columns x 4 rows per A4 sheet
 * For: domestic, resident_worker, contractor_lead
 * Called by: permit_photo_upload.php (type=label)
 *
 * Requires: Dompdf (already installed for export files)
 * Usage: permit_label.php?id=42&pos=1   (pos 1-8, POSTed photo_data optional)
 *
 * ── CALIBRATION ──────────────────────────────────────────
 * Nobody publishes exact margin/pitch specs for this label stock, so the
 * four constants below are a starting estimate (labels butted edge-to-edge,
 * symmetric side margins) derived purely from label size vs A4 dimensions.
 * Print ONE test sheet on plain paper, hold it up against a real label
 * sheet, and nudge these numbers by 1-3mm until the print lines up.
 * This is standard practice for label printing, not a GEMB-specific issue.
 * ──────────────────────────────────────────────────────────
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

// Position on the sheet — reads left-to-right, top-to-bottom (1-8)
$pos = (int)($_POST['pos'] ?? $_GET['pos'] ?? 1);
if ($pos < 1 || $pos > 8) $pos = 1;

$sp = db()->prepare("SELECT * FROM service_providers WHERE id=? LIMIT 1");
$sp->execute([$id]);
$sp = $sp->fetch();
if (!$sp) die('Record not found');

// ════════════════════════════════════════════════════════
// CALIBRATION CONSTANTS — adjust after a test print
// ════════════════════════════════════════════════════════
const LABEL_W       = 101;   // mm — physical label width  (landscape)
const LABEL_H       = 70;    // mm — physical label height
const SHEET_COLS    = 2;
const SHEET_ROWS    = 4;
const MARGIN_LEFT   = 4.0;   // mm — distance from sheet's left edge to first column
const MARGIN_TOP    = 8.5;   // mm — distance from sheet's top edge to first row
const COL_GUTTER    = 0.0;   // mm — gap between the two columns
const ROW_GUTTER    = 0.0;   // mm — gap between rows

$col = ($pos - 1) % SHEET_COLS;
$row = intdiv($pos - 1, SHEET_COLS);
$offsetX = MARGIN_LEFT + $col * (LABEL_W + COL_GUTTER);
$offsetY = MARGIN_TOP  + $row * (LABEL_H + ROW_GUTTER);

// ── Photo ────────────────────────────────────────────────
// Same priority order as permit_card.php:
//   1. $_POST['photo_data'] — fresh upload from permit_photo_upload.php
//   2. sp.photo — stored filename or base64 (legacy / future use)
//   3. placeholder silhouette
$photoTag = '';
if (!empty($_POST['photo_data']) && str_starts_with($_POST['photo_data'], 'data:image/')) {
    $photoTag = '<img src="' . htmlspecialchars($_POST['photo_data']) . '">';
} elseif (!empty($sp['photo'])) {
    $raw = $sp['photo'];
    if (str_starts_with($raw, 'data:image/')) {
        $photoTag = '<img src="' . htmlspecialchars($raw) . '">';
    } else {
        $photoPath = __DIR__ . '/uploads/sp_photos/' . basename($raw);
        if (file_exists($photoPath)) {
            $mime     = mime_content_type($photoPath);
            $photoB64 = base64_encode(file_get_contents($photoPath));
            $photoTag = '<img src="data:' . $mime . ';base64,' . $photoB64 . '">';
        }
    }
}
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

// ── HTML — single 101x70mm card, absolutely positioned on an
//    A4 canvas to land on label slot $pos of the W103 sheet ──
$html = '<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family: Arial, sans-serif; background:#fff; }

  /* A4 canvas — the card below is positioned absolutely within this */
  .sheet {
    position: relative;
    width: 210mm;
    height: 297mm;
  }

  .card {
    position: absolute;
    top: ' . $offsetY . 'mm;
    left: ' . $offsetX . 'mm;
    width: ' . LABEL_W . 'mm;
    height: ' . LABEL_H . 'mm;
    border: 0.5mm solid #1a3c5e;
    border-radius: 3mm;
    overflow: hidden;
    background: #fff;
  }

  /* Header band */
  .card-header-table {
    width: 100%;
    height: 10mm;
    background: #1a3c5e;
  }
  .card-header-table td {
    padding: 2mm 2.5mm 1.5mm;
    vertical-align: middle;
  }
  .estate {
    font-size: 10.5pt;
    font-weight: bold;
    letter-spacing: 0.3pt;
    text-transform: uppercase;
  }
  .cat {
    font-size: 8.5pt;
    background: #c8a84b;
    color: #000;
    padding: 0.9mm 2.4mm;
    border-radius: 1mm;
    font-weight: bold;
    white-space: nowrap;
  }

  /* Body: photo | details | QR */
  .card-body-table {
    width: 100%;
    table-layout: fixed;
    height: calc(' . LABEL_H . 'mm - 10mm - 7mm);
    border-collapse: collapse;
  }
  .card-body-table td {
    padding: 2mm;
    vertical-align: middle;
  }

  .card-photo {
    width: 24mm;
    height: 32mm;
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

  .card-details {
    width: 48mm;
    min-width: 0;
  }
  .card-details .name {
    font-size: 12.5pt;
    font-weight: bold;
    color: #1a3c5e;
    line-height: 1.15;
    margin-bottom: 1.2mm;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .card-details .row {
    font-size: 9.5pt;
    color: #333;
    line-height: 1.35;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .card-details .row span { color: #888; }

  .card-qr {
    width: 27mm;
    text-align: center;
  }
  .card-qr img {
    width: 24mm;
    height: 24mm;
  }
  .card-qr .code {
    font-size: 8.5pt;
    font-weight: bold;
    font-family: monospace;
    color: #1a3c5e;
    letter-spacing: 0.5pt;
    margin-top: 0.6mm;
    text-align: center;
  }

  .card-footer-table {
    position: absolute;
    bottom: 0;
    left: 0;
    right: 0;
    width: 100%;
    background: #f5f5f5;
    border-top: 0.3mm solid #ddd;
    height: 7mm;
  }
  .card-footer-table td {
    padding: 1mm 2.5mm;
    font-size: 7.5pt;
    color: #888;
    vertical-align: middle;
  }
</style>
</head><body>
<div class="sheet">
  <div class="card">
    <table class="card-header-table"><tr>
      <td style="text-align:left;"><span class="estate" style="color:#fff;">GEMB ESTATE</span></td>
      <td style="text-align:right;"><span class="cat">' . htmlspecialchars($catLabel) . '</span></td>
    </tr></table>

    <table class="card-body-table"><tr>

      <td style="width:24mm;">
        <div class="card-photo">
          ' . $photoTag . '
        </div>
      </td>

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
</div>
</body></html>';

$opt = new Options();
$opt->set('isRemoteEnabled', true);
$pdf = new Dompdf($opt);
$pdf->loadHtml($html);
$pdf->setPaper('A4', 'portrait');
$pdf->render();
$output = $pdf->output();

// ── Audit log — reuses permit_type='card' (no schema change) ──
try {
    $monthDir = __DIR__ . '/uploads/permits/' . date('Y-m');
    if (!is_dir($monthDir)) @mkdir($monthDir, 0755, true);

    $filename = 'label_' . $sp['unique_code'] . '_pos' . $pos . '_' . date('YmdHis') . '.pdf';
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
header('Content-Disposition: inline; filename="permit_label_' . $sp['unique_code'] . '.pdf"');
header('Content-Length: ' . strlen($output));
header('Cache-Control: private, max-age=0, must-revalidate');
echo $output;
exit;