<?php
/**
 * gemB - Owner electronic co-signature page.
 * The registered owner receives an e-mailed link:
 *   application_cosign.php?token={owner_sign_token}
 * On confirmation, owner acknowledgements are recorded and the application
 * transitions submitted -> pending_verification.
 */
declare(strict_types=1);
require_once __DIR__ . '/application_lib.php';

$csrf = app_csrf_token();
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

$token = app_clean((string)($_REQUEST['token'] ?? ''), 64);
if (!preg_match('/^[a-f0-9]{64}$/', $token)) { http_response_code(404); exit('Invalid link.'); }

$stmt = $conn->prepare(
    "SELECT id, app_ref, app_type, status, applicant_name, erf_no, owner_name, owner_signed_at, type_data
     FROM applications WHERE owner_sign_token = ? LIMIT 1");
$stmt->bind_param('s', $token);
$stmt->execute();
$app = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$app) { http_response_code(404); exit('Link expired or invalid.'); }
$cfg = APP_TYPES[$app['app_type']];
$done = $app['owner_signed_at'] !== null;
$err = '';

/* Owner-side clauses per type */
$ownerClauses = [
    'tenant' => [
        'owner_tenant_responsibility' => 'As registered owner I confirm this tenant registration, acknowledge that I am responsible for the registration of my tenants (clause 4.1), and that I remain liable for their compliance with the MOI and Rules.',
    ],
    'pet' => [
        'owner_pet_permission' => 'As registered owner I hereby grant permission to the tenant for keeping the animal as applied for.',
    ],
];
$clauses = $ownerClauses[$app['app_type']] ?? [];
$clauses['owner_popia'] = 'I consent to the processing of my information for this registration (POPIA).';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$done) {
    if (!app_csrf_check($_POST['csrf'] ?? null)) {
        $err = 'Security token invalid. Please reload the page.';
    } elseif (!app_rate_limit($conn, 'cosign', 10, 3600)) {
        $err = 'Too many attempts. Please try again later.';
    } else {
        foreach ($clauses as $code => $text) {
            if (empty($_POST['ack'][$code])) { $err = 'All confirmations must be ticked.'; break; }
        }
        if ($err === '' && $app['status'] === 'submitted') {
            $conn->begin_transaction();
            try {
                foreach ($clauses as $code => $text) {
                    app_record_ack($conn, (int)$app['id'], $code, $text, 'owner');
                }
                $stmt = $conn->prepare("UPDATE applications SET owner_signed_at = NOW() WHERE id = ?");
                $id = (int)$app['id'];
                $stmt->bind_param('i', $id);
                $stmt->execute();
                $stmt->close();
                app_set_status($conn, $id, 'pending_verification', 'owner', null, 'owner co-signed');
                $conn->commit();
                $done = true;
            } catch (Throwable $e) {
                $conn->rollback();
                $err = 'Could not record your confirmation. Please try again.';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Owner Confirmation - gemB</title>
<style>
:root { --navy:#1a2f5a; --teal:#1a8a8a; --line:#d7dee8; }
body { font-family:'Segoe UI',system-ui,sans-serif; background:#f5f7fa; margin:0; color:#222; }
.wrap { max-width:640px; margin:0 auto; padding:16px; }
header.gemb { background:var(--navy); color:#fff; padding:16px; }
.card { background:#fff; border:1px solid var(--line); border-radius:10px; padding:20px; margin:16px 0; }
label { display:flex; gap:10px; align-items:flex-start; font-size:.92rem; margin:12px 0; cursor:pointer; }
button { background:var(--navy); color:#fff; border:none; border-radius:8px; padding:14px 28px; font-size:1rem; cursor:pointer; width:100%; }
.ok { background:#eaf7ee; border:1px solid #1a7a3a; color:#1a7a3a; border-radius:8px; padding:16px; text-align:center; }
.err { background:#fdecec; border:1px solid #b00020; color:#b00020; border-radius:8px; padding:12px; }
dl { display:grid; grid-template-columns:140px 1fr; gap:4px 12px; font-size:.9rem; }
dt { color:#666; } dd { margin:0; }
</style>
</head>
<body>
<header class="gemb"><div class="wrap"><h1 style="margin:0;font-size:1.15rem">Owner Confirmation &mdash; <?= h($app['app_ref']) ?></h1></div></header>
<div class="wrap">
<div class="card">
  <dl>
    <dt>Application</dt><dd><?= h($cfg['label']) ?></dd>
    <dt>Applicant</dt><dd><?= h($app['applicant_name']) ?></dd>
    <dt>Erf</dt><dd><?= h((string)$app['erf_no']) ?></dd>
  </dl>
</div>

<?php if ($done): ?>
  <div class="ok">Thank you. Your confirmation has been recorded and the application has been sent to the site manager for verification.</div>
<?php else: ?>
  <?php if ($err): ?><div class="err"><?= h($err) ?></div><?php endif; ?>
  <form method="post">
    <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
    <input type="hidden" name="token" value="<?= h($token) ?>">
    <div class="card">
      <?php foreach ($clauses as $code => $text): ?>
        <label><input type="checkbox" name="ack[<?= h($code) ?>]" value="1" required> <?= h($text) ?></label>
      <?php endforeach; ?>
    </div>
    <button type="submit">Confirm as Registered Owner</button>
  </form>
<?php endif; ?>
</div>
</body>
</html>
