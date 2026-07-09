<?php
/**
 * permit_slip.php — GEMB Paper Slip Permit (A5)
 * For: contractor_worker (and any slip-type SP)
 * Shows: personal details + photo + QR + must present with ID at gate
 *
 * v2 — adds photo support (sp.photo column, stored as filename or base64)
 */
session_start();
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/vendor/autoload.php';

use Dompdf\Dompdf;
use Dompdf\Options;

if (empty($_SESSION['security_id']) && empty($_SESSION['admin_id'])) {
    header('Location: security.php?action=login'); exit;
}

$id = (int)($_GET['id'] ?? 0);
if (!$id) die('Missing ID');

$sp = db()->prepare("
    SELECT sp.*,
           (SELECT service_name FROM service_providers
            WHERE id = sp.lead_id) AS lead_name,
           (SELECT company_name FROM service_providers
            WHERE id = sp.lead_id) AS lead_company
    FROM service_providers sp
    WHERE sp.id = ? LIMIT 1
");
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
    $photoTag = '<img src="' . htmlspecialchars($_POST['photo_data']) . '" class="photo-img">';
} elseif (!empty($sp['photo'])) {
    $raw = $sp['photo'];
    if (str_starts_with($raw, 'data:image/')) {
        $photoTag = '<img src="' . htmlspecialchars($raw) . '" class="photo-img">';
    } else {
        $photoPath = __DIR__ . '/uploads/sp_photos/' . basename($raw);
        if (file_exists($photoPath)) {
            $mime     = mime_content_type($photoPath);
            $b64      = base64_encode(file_get_contents($photoPath));
            $photoTag = '<img src="data:' . $mime . ';base64,' . $b64 . '" class="photo-img">';
        }
    }
}
if (!$photoTag) {
    // SVG silhouette placeholder
    $photoTag = '<svg viewBox="0 0 80 100" xmlns="http://www.w3.org/2000/svg" class="photo-img">
      <rect width="80" height="100" fill="#e8edf2"/>
      <circle cx="40" cy="32" r="18" fill="#a0afc0"/>
      <ellipse cx="40" cy="90" rx="28" ry="20" fill="#a0afc0"/>
    </svg>';
}

// ── QR Code ──────────────────────────────────────────────
$qrLib = __DIR__ . '/phpqrcode/qrlib.php';
if (file_exists($qrLib)) {
    require_once $qrLib;
    $tempDir   = __DIR__ . '/temp';
    if (!is_dir($tempDir)) @mkdir($tempDir, 0755, true);
    $qrFile    = $tempDir . '/' . $sp['unique_code'] . '.png';
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

$qrTag = $qrBase64
    ? '<img src="data:image/png;base64,' . $qrBase64 . '" class="qr-img">'
    : '<img src="https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl='
      . urlencode(SITE_URL . '/service_qr_verify.php?code=' . $sp['unique_code'])
      . '" class="qr-img">';

$validFrom = date('d M Y', strtotime($sp['start_date']));
$validTo   = date('d M Y', strtotime($sp['end_date']));
$printDate = date('d M Y H:i');

$catLabels = [
    'domestic'          => 'Domestic Worker',
    'delivery'          => 'Delivery',
    'resident_worker'   => 'Resident Worker',
    'contractor_lead'   => 'Contractor Lead',
    'contractor_worker' => 'Contractor Worker',
];
$catLabel = $catLabels[$sp['category'] ?? 'contractor_worker'] ?? 'Service Provider';

$html = '<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family: Arial, sans-serif; font-size: 10pt;
         background:#fff; padding:12mm; }

  .slip {
    width: 186mm;
    border: 0.5mm solid #1a3c5e;
    border-radius: 3mm;
    overflow: hidden;
  }

  /* Header */
  .slip-header-table {
    width: 100%;
    background: #1a3c5e;
  }
  .slip-header-table td {
    padding: 3mm 5mm;
    vertical-align: middle;
    color: #fff;
  }
  .slip-header-table h1 { font-size: 11pt; letter-spacing: 0.3pt; color: #fff; }
  .slip-header-table .type {
    font-size: 8pt;
    background: #c8a84b;
    color: #000;
    padding: 1mm 2.5mm;
    border-radius: 2mm;
    font-weight: bold;
    white-space: nowrap;
  }

  /* Body: left column (photo + QR) | right column (details) — table layout for Dompdf reliability */
  .slip-body-table {
    width: 100%;
    border-collapse: collapse;
  }
  .slip-body-table > tbody > tr > td {
    padding: 4mm 5mm;
    vertical-align: top;
  }

  /* Left column cell */
  .slip-left-cell {
    width: 46mm;
    text-align: center;
  }

  /* Photo box */
  .photo-box {
    width: 42mm;
    height: 52mm;
    border: 0.4mm solid #1a3c5e;
    border-radius: 2mm;
    overflow: hidden;
    background: #e8edf2;
    margin: 0 auto;
  }
  .photo-img {
    width: 100%;
    height: 100%;
    object-fit: cover;
    display: block;
  }
  .photo-label {
    font-size: 6pt;
    color: #888;
    text-align: center;
    margin-top: 1mm;
  }

  /* QR box */
  .qr-box {
    text-align: center;
    margin-top: 3mm;
  }
  .qr-img { width: 40mm; height: 40mm; display: block; margin: 0 auto; }
  .qr-code {
    font-size: 7pt;
    font-weight: bold;
    font-family: monospace;
    color: #1a3c5e;
    letter-spacing: 2pt;
    margin-top: 1.5mm;
  }
  .qr-hint {
    font-size: 5.5pt;
    color: #888;
    margin-top: 0.5mm;
  }

  /* Right column cell — details */
  .slip-details-cell { padding-left: 0; }
  .slip-details table { width: 100%; border-collapse: collapse; }
  .slip-details td {
    padding: 1.5mm 2mm;
    font-size: 8.5pt;
    vertical-align: top;
    border-bottom: 0.2mm solid #eee;
    word-break: break-word;
  }
  .slip-details td:first-child {
    color: #666;
    width: 30mm;
    font-size: 7.5pt;
    white-space: nowrap;
  }
  .slip-details td:last-child {
    font-weight: 600;
    color: #1a1a1a;
  }
  .name-row td {
    font-size: 11pt;
    font-weight: bold;
    color: #1a3c5e;
    border-bottom: 0.4mm solid #1a3c5e;
    padding-bottom: 2.5mm;
    padding-top: 1mm;
  }

  /* Warning */
  .slip-warning {
    background: #fff3cd;
    border-top: 0.4mm solid #ffc107;
    padding: 2.5mm 5mm;
    font-size: 7.5pt;
    color: #856404;
    font-weight: bold;
    text-align: center;
  }

  /* Footer */
  .slip-footer-table {
    width: 100%;
    background: #f5f5f5;
    border-top: 0.3mm solid #ddd;
  }
  .slip-footer-table td {
    padding: 1.5mm 5mm;
    font-size: 6.5pt;
    color: #888;
  }
</style>
</head><body>

<div class="slip">

  <table class="slip-header-table"><tr>
    <td style="text-align:left;"><h1>GEMB TEMPORARY ACCESS PERMIT</h1></td>
    <td style="text-align:right;"><span class="type">' . $catLabel . '</span></td>
  </tr></table>

  <table class="slip-body-table"><tbody><tr>

    <!-- Left: Photo + QR stacked -->
    <td class="slip-left-cell">

      <div class="photo-box">
        ' . $photoTag . '
      </div>
      <div class="photo-label">PERMIT HOLDER PHOTO</div>

      <div class="qr-box">
        ' . $qrTag . '
        <div class="qr-code">' . htmlspecialchars($sp['unique_code']) . '</div>
        <div class="qr-hint">Scan at gate for entry</div>
      </div>

    </td>

    <!-- Right: Details -->
    <td class="slip-details-cell">
      <div class="slip-details">
      <table>
        <tr class="name-row">
          <td colspan="2">' . htmlspecialchars($sp['service_name']) . '</td>
        </tr>
        ' . ($sp['id_number'] ? '
        <tr>
          <td>ID Number</td>
          <td>' . htmlspecialchars($sp['id_number']) . '</td>
        </tr>' : '') . '
        ' . ($sp['category'] ? '
        <tr>
          <td>Category</td>
          <td>' . htmlspecialchars($catLabel) . '</td>
        </tr>' : '') . '
        ' . ($sp['lead_name'] ? '
        <tr>
          <td>Under Lead</td>
          <td>' . htmlspecialchars($sp['lead_name'])
              . ($sp['lead_company'] ? ' (' . htmlspecialchars($sp['lead_company']) . ')' : '')
              . '</td>
        </tr>' : '') . '
        ' . ($sp['company_name'] ? '
        <tr>
          <td>Company</td>
          <td>' . htmlspecialchars($sp['company_name']) . '</td>
        </tr>' : '') . '
        <tr>
          <td>Resident</td>
          <td>' . htmlspecialchars($sp['resident_name']) . '</td>
        </tr>
        <tr>
          <td>Erf / Address</td>
          <td>' . htmlspecialchars($sp['resident_erfno']) . '</td>
        </tr>
        ' . ($sp['notes'] ? '
        <tr>
          <td>Work</td>
          <td>' . htmlspecialchars($sp['notes']) . '</td>
        </tr>' : '') . '
        <tr>
          <td>Valid Period</td>
          <td>' . $validFrom . ' – ' . $validTo . '</td>
        </tr>
        <tr>
          <td>Access Hours</td>
          <td>'
          . htmlspecialchars($sp['access_days'] ?? 'Mon–Fri')
          . '&nbsp;&nbsp;'
          . substr($sp['access_start'] ?? '07:00:00', 0, 5)
          . ' – '
          . substr($sp['access_end'] ?? '17:00:00', 0, 5)
          . '</td>
        </tr>
        <tr>
          <td>Issued</td>
          <td>' . $printDate . ' — '
              . htmlspecialchars($_SESSION['security_name'] ?? 'Security') . '</td>
        </tr>
      </table>
      </div>
    </td>

  </tr></tbody></table>

  <div class="slip-warning">
    THIS PERMIT MUST BE PRESENTED TOGETHER WITH A PERSONAL IDENTITY DOCUMENT AT THE GATE
  </div>

  <table class="slip-footer-table"><tr>
    <td style="text-align:left;">GEMB</td>
    <td style="text-align:right;">POPIA Act 4 of 2013</td>
  </tr></table>

</div>

</body></html>';

$opt = new Options();
$opt->set('isRemoteEnabled', true);
$pdf = new Dompdf($opt);
$pdf->loadHtml($html);
$pdf->setPaper('A4', 'portrait');
$pdf->render();
$output = $pdf->output();

// ── Audit log: save PDF to disk and record the print event ──
try {
    // Monthly subfolders keep the directory manageable
    $monthDir = __DIR__ . '/uploads/permits/' . date('Y-m');
    if (!is_dir($monthDir)) @mkdir($monthDir, 0755, true);

    $filename = 'slip_' . $sp['unique_code'] . '_' . date('YmdHis') . '.pdf';
    $filePath = $monthDir . '/' . $filename;
    $relPath  = '/uploads/permits/' . date('Y-m') . '/' . $filename;

    file_put_contents($filePath, $output);

    // purge_after = SP end_date + 30 days, consistent with POPIA retention policy
    $purgeAfter = date('Y-m-d', strtotime($sp['end_date'] . ' +30 days'));

    db()->prepare("
        INSERT INTO permit_print_log
            (sp_id, unique_code, permit_type, printed_by_id, printed_by_name, printed_at, pdf_path, purge_after)
        VALUES (?, ?, 'slip', ?, ?, NOW(), ?, ?)
    ")->execute([
        $sp['id'],
        $sp['unique_code'],
        $_SESSION['security_id']   ?? 0,
        $_SESSION['security_name'] ?? 'Security',
        $relPath,
        $purgeAfter,
    ]);
} catch (Exception $e) {
    // Never block permit printing on a log failure
    error_log('permit_print_log save failed: ' . $e->getMessage());
}

// ── Stream PDF to browser ─────────────────────────────────
header('Content-Type: application/pdf');
header('Content-Disposition: inline; filename="permit_slip_' . $sp['unique_code'] . '.pdf"');
header('Content-Length: ' . strlen($output));
header('Cache-Control: private, max-age=0, must-revalidate');
echo $output;
exit;
