<?php
/**
 * gemB - Site Manager application verification portal
 * Unified queue for all application types + per-application checklist screen.
 *
 * Access control: requires an authenticated security/site-manager session,
 * consistent with security.php. Adjust the session guard below to match
 * the live gemB session variable names.
 */
declare(strict_types=1);
require_once __DIR__ . '/application_lib.php';

/* ---------- Session guard (align with existing security portal) ---------- */
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_set_cookie_params(['httponly' => true, 'secure' => true, 'samesite' => 'Strict']);
    session_start();
}
if (empty($_SESSION['security_user_id']) || ($_SESSION['security_role'] ?? '') !== 'site_manager') {
    http_response_code(403);
    exit('Access denied. Site manager login required.');
}
$managerId = (int)$_SESSION['security_user_id'];
$csrf = app_csrf_token();

function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

/* ---------- POST actions ---------- */
$flash = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!app_csrf_check($_POST['csrf'] ?? null)) { http_response_code(403); exit('CSRF token invalid.'); }
    $appId  = (int)($_POST['app_id'] ?? 0);
    $action = app_clean((string)($_POST['action'] ?? ''), 30);

    if ($action === 'save_checks') {
        // Save checklist results
        foreach (($_POST['check'] ?? []) as $checkId => $result) {
            $checkId = (int)$checkId;
            if (!in_array($result, ['pending', 'pass', 'fail', 'n_a'], true)) continue;
            $comment = app_clean((string)($_POST['comment'][$checkId] ?? ''), 500);
            $stmt = $conn->prepare(
                "UPDATE application_checklist
                 SET result = ?, comment = ?, checked_by = ?, checked_at = NOW()
                 WHERE id = ? AND application_id = ?");
            $stmt->bind_param('ssiii', $result, $comment, $managerId, $checkId, $appId);
            $stmt->execute();
            $stmt->close();
        }
        // Payment verification flag
        if (isset($_POST['payment_verified'])) {
            $pv = (int)(bool)$_POST['payment_verified'];
            $stmt = $conn->prepare(
                "UPDATE application_payments
                 SET verified = ?, verified_by = IF(?=1, ?, NULL), verified_at = IF(?=1, NOW(), NULL)
                 WHERE application_id = ?");
            $stmt->bind_param('iiiii', $pv, $pv, $managerId, $pv, $appId);
            $stmt->execute();
            $stmt->close();
        }
        $flash = 'Checklist saved.';
    }

    if ($action === 'verify') {
        if (!app_checklist_complete($conn, $appId)) {
            $flash = 'Cannot verify: outstanding checklist items remain (all must be Pass or N/A).';
        } else {
            // Determine post-verify path from type config
            $stmt = $conn->prepare("SELECT app_type FROM applications WHERE id = ?");
            $stmt->bind_param('i', $appId);
            $stmt->execute();
            $stmt->bind_result($appType);
            $stmt->fetch();
            $stmt->close();
            $next = APP_TYPES[$appType]['post_verify_status'] ?? 'approved';
            if (app_set_status($conn, $appId, 'verified', 'site_manager', $managerId, 'checklist complete')) {
                if ($next === 'induction_scheduled') {
                    app_set_status($conn, $appId, 'induction_scheduled', 'site_manager', $managerId, 'induction to be arranged');
                    $flash = 'Verified. Status set to induction scheduled - contact person to be e-mailed for the induction session.';
                } else {
                    // Direct approval path
                    $conditions = app_clean((string)($_POST['approval_conditions'] ?? ''), 2000);
                    $stmt = $conn->prepare(
                        "UPDATE applications SET approved_by = ?, approved_at = NOW(),
                         approval_conditions = NULLIF(?, ''),
                         valid_until = NULLIF(JSON_UNQUOTE(JSON_EXTRACT(type_data, '$.rental_to')), 'null')
                         WHERE id = ?");
                    $stmt->bind_param('isi', $managerId, $conditions, $appId);
                    $stmt->execute();
                    $stmt->close();
                    app_set_status($conn, $appId, 'approved', 'site_manager', $managerId, 'approved after verification');
                    $flash = 'Application verified and approved.';
                }
            }
        }
    }

    if ($action === 'approve_after_induction') {
        // contractor path: induction_scheduled -> approved
        if (app_set_status($conn, $appId, 'approved', 'site_manager', $managerId, 'induction completed')) {
            $stmt = $conn->prepare("UPDATE applications SET approved_by = ?, approved_at = NOW() WHERE id = ?");
            $stmt->bind_param('ii', $managerId, $appId);
            $stmt->execute();
            $stmt->close();
            $flash = 'Induction confirmed - application approved. Access cards may be issued.';
            // Hook: push approved workers into live service-provider tables + issue QR/UHF here.
        }
    }

    if ($action === 'return') {
        $reason = app_clean((string)($_POST['return_reason'] ?? ''), 2000);
        if ($reason === '') {
            $flash = 'A reason is required when returning an application.';
        } else {
            $stmt = $conn->prepare("UPDATE applications SET return_reason = ? WHERE id = ?");
            $stmt->bind_param('si', $reason, $appId);
            $stmt->execute();
            $stmt->close();
            app_set_status($conn, $appId, 'returned', 'site_manager', $managerId, 'returned: ' . mb_substr($reason, 0, 200));
            $flash = 'Application returned to applicant with deficiencies listed.';
            // Hook: e-mail applicant the resume link application_form.php?resume={resume_token}
        }
    }

    if ($action === 'reject') {
        $reason = app_clean((string)($_POST['reject_reason'] ?? ''), 2000);
        if ($reason === '') {
            $flash = 'A reason is required when rejecting an application.';
        } else {
            app_set_status($conn, $appId, 'rejected', 'site_manager', $managerId, 'rejected: ' . mb_substr($reason, 0, 200));
            $flash = 'Application rejected.';
        }
    }

    if ($action === 'withdraw_approval') {
        // e.g. pet rule 1.3, to_let clause 6
        $reason = app_clean((string)($_POST['withdraw_reason'] ?? ''), 2000);
        app_set_status($conn, $appId, 'withdrawn', 'site_manager', $managerId, 'approval withdrawn: ' . mb_substr($reason, 0, 200));
        $flash = 'Approval withdrawn.';
    }
}

/* ---------- Detail view? ---------- */
$detailId = (int)($_GET['id'] ?? 0);
$detail = null;
if ($detailId) {
    $stmt = $conn->prepare("SELECT * FROM applications WHERE id = ?");
    $stmt->bind_param('i', $detailId);
    $stmt->execute();
    $detail = $stmt->get_result()->fetch_assoc();
    $stmt->close();
}

/* ---------- Queue query ---------- */
$statusFilter = app_clean((string)($_GET['status'] ?? 'pending_verification'), 30);
$validStatuses = array_merge(array_keys(APP_TRANSITIONS), ['all']);
if (!in_array($statusFilter, $validStatuses, true)) $statusFilter = 'pending_verification';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Applications - Site Manager - gemB</title>
<style>
:root { --navy:#1a2f5a; --teal:#1a8a8a; --bg:#f5f7fa; --line:#d7dee8; --err:#b00020; --ok:#1a7a3a; --warn:#a86a00; }
* { box-sizing:border-box; }
body { font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); margin:0; color:#222; }
.wrap { max-width:1000px; margin:0 auto; padding:16px; }
header.gemb { background:var(--navy); color:#fff; padding:16px; }
header.gemb h1 { margin:0; font-size:1.2rem; }
.filters a { display:inline-block; padding:6px 12px; margin:12px 6px 0 0; border-radius:16px; background:#fff; border:1px solid var(--line); color:var(--navy); text-decoration:none; font-size:.85rem; }
.filters a.active { background:var(--teal); color:#fff; border-color:var(--teal); }
table.queue { width:100%; border-collapse:collapse; background:#fff; border:1px solid var(--line); border-radius:8px; overflow:hidden; margin-top:12px; }
table.queue th, table.queue td { padding:10px 12px; text-align:left; font-size:.88rem; border-bottom:1px solid var(--line); }
table.queue th { background:var(--navy); color:#fff; }
table.queue tr:hover td { background:#f0f6f6; }
.badge { display:inline-block; padding:2px 10px; border-radius:12px; font-size:.75rem; color:#fff; }
.b-pending_verification { background:var(--warn); } .b-submitted { background:#888; }
.b-verified,.b-induction_scheduled { background:var(--teal); } .b-approved { background:var(--ok); }
.b-returned { background:#c77; } .b-rejected,.b-withdrawn,.b-expired { background:var(--err); }
.card { background:#fff; border:1px solid var(--line); border-radius:10px; padding:18px; margin:16px 0; }
.card h2 { color:var(--navy); font-size:1.05rem; margin:0 0 10px; border-bottom:2px solid var(--teal); padding-bottom:6px; }
dl { display:grid; grid-template-columns:220px 1fr; gap:4px 12px; font-size:.9rem; margin:0; }
dt { color:#666; } dd { margin:0; }
table.checks { width:100%; border-collapse:collapse; font-size:.87rem; }
table.checks td, table.checks th { padding:8px; border-bottom:1px solid var(--line); vertical-align:top; }
select.res { padding:6px; border-radius:6px; border:1px solid var(--line); }
select.res.pass { background:#eaf7ee; } select.res.fail { background:#fdecec; }
input.cmt { width:100%; padding:6px; border:1px solid var(--line); border-radius:6px; }
.btnrow { display:flex; gap:10px; flex-wrap:wrap; margin-top:14px; }
button.b { border:none; border-radius:8px; padding:12px 20px; font-size:.92rem; cursor:pointer; color:#fff; }
.b-save { background:var(--navy); } .b-verify { background:var(--ok); } .b-return { background:var(--warn); } .b-reject { background:var(--err); }
textarea { width:100%; min-height:70px; border:1px solid var(--line); border-radius:6px; padding:8px; font-family:inherit; }
.flash { background:#eef6f6; border-left:4px solid var(--teal); padding:10px 14px; margin:12px 0; font-size:.9rem; }
.doclink { font-size:.85rem; }
.note { font-size:.8rem; color:#666; }
</style>
</head>
<body>
<header class="gemb"><div class="wrap"><h1>Application Verification &mdash; Site Manager</h1></div></header>
<div class="wrap">
<?php if ($flash): ?><div class="flash"><?= h($flash) ?></div><?php endif; ?>

<?php if (!$detail): /* ================= QUEUE VIEW ================= */ ?>

<div class="filters">
<?php foreach (['pending_verification' => 'Pending', 'submitted' => 'Awaiting co-sign', 'induction_scheduled' => 'Induction', 'returned' => 'Returned', 'approved' => 'Approved', 'all' => 'All'] as $s => $lbl): ?>
  <a href="?status=<?= h($s) ?>" class="<?= $statusFilter === $s ? 'active' : '' ?>"><?= h($lbl) ?></a>
<?php endforeach; ?>
</div>

<table class="queue">
<tr><th>Ref</th><th>Type</th><th>Applicant / Company</th><th>Erf</th><th>Submitted</th><th>Status</th><th></th></tr>
<?php
if ($statusFilter === 'all') {
    $stmt = $conn->prepare("SELECT id, app_ref, app_type, applicant_name, company_name, erf_no, submitted_at, status FROM applications ORDER BY submitted_at DESC LIMIT 200");
} else {
    $stmt = $conn->prepare("SELECT id, app_ref, app_type, applicant_name, company_name, erf_no, submitted_at, status FROM applications WHERE status = ? ORDER BY submitted_at ASC LIMIT 200");
    $stmt->bind_param('s', $statusFilter);
}
$stmt->execute();
$rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();
if (!$rows) echo '<tr><td colspan="7" style="text-align:center;color:#888">No applications in this view.</td></tr>';
foreach ($rows as $r): ?>
<tr>
  <td><?= h($r['app_ref']) ?></td>
  <td><?= h(APP_TYPES[$r['app_type']]['label'] ?? $r['app_type']) ?></td>
  <td><?= h($r['company_name'] ?: $r['applicant_name']) ?></td>
  <td><?= h((string)$r['erf_no']) ?></td>
  <td><?= h((string)$r['submitted_at']) ?></td>
  <td><span class="badge b-<?= h($r['status']) ?>"><?= h(str_replace('_', ' ', $r['status'])) ?></span></td>
  <td><a href="?id=<?= (int)$r['id'] ?>">Open</a></td>
</tr>
<?php endforeach; ?>
</table>

<?php else: /* ================= DETAIL / CHECKLIST VIEW ================= */
$cfg = APP_TYPES[$detail['app_type']];
$typeData = $detail['type_data'] ? json_decode($detail['type_data'], true) : [];

$stmt = $conn->prepare("SELECT * FROM application_items WHERE application_id = ? ORDER BY item_type, id");
$stmt->bind_param('i', $detailId);
$stmt->execute();
$items = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();

$stmt = $conn->prepare("SELECT * FROM application_documents WHERE application_id = ?");
$stmt->bind_param('i', $detailId);
$stmt->execute();
$docs = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();
$docsByItem = [];
foreach ($docs as $d) $docsByItem[$d['item_id'] ?? 0][] = $d;

$stmt = $conn->prepare("SELECT * FROM application_checklist WHERE application_id = ? ORDER BY item_id IS NULL DESC, item_id, id");
$stmt->bind_param('i', $detailId);
$stmt->execute();
$checks = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();

$stmt = $conn->prepare("SELECT * FROM application_payments WHERE application_id = ?");
$stmt->bind_param('i', $detailId);
$stmt->execute();
$payment = $stmt->get_result()->fetch_assoc();
$stmt->close();

$stmt = $conn->prepare("SELECT ack_code, acknowledged_by, acknowledged_at FROM application_acknowledgements WHERE application_id = ? ORDER BY id");
$stmt->bind_param('i', $detailId);
$stmt->execute();
$acks = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();

$itemNames = [];
foreach ($items as $it) {
    $itemNames[$it['id']] = trim(($it['first_name'] ?? '') . ' ' . ($it['surname'] ?? ''))
        ?: ($it['vehicle_reg'] ?? '')
        ?: ($it['pet_species'] ? $it['pet_species'] . ' (' . $it['pet_breed'] . ')' : '')
        ?: ('#' . $it['id']);
}
?>
<p><a href="application_admin.php">&larr; Back to queue</a></p>

<div class="card">
  <h2><?= h($detail['app_ref']) ?> &mdash; <?= h($cfg['label']) ?>
      <span class="badge b-<?= h($detail['status']) ?>"><?= h(str_replace('_', ' ', $detail['status'])) ?></span></h2>
  <dl>
    <dt>Applicant</dt><dd><?= h($detail['applicant_name']) ?> (<?= h((string)$detail['applicant_email']) ?>, <?= h((string)$detail['applicant_phone']) ?>)</dd>
    <?php if ($detail['company_name']): ?>
      <dt>Company</dt><dd><?= h($detail['company_name']) ?> &middot; <?= h((string)$detail['company_type']) ?> &middot; Reg: <?= h((string)$detail['company_reg_no']) ?> &middot; Owner: <?= h((string)$detail['company_owner']) ?></dd>
    <?php endif; ?>
    <?php if ($detail['erf_no']): ?><dt>Erf</dt><dd><?= h($detail['erf_no']) ?></dd><?php endif; ?>
    <?php if ($detail['reg_type']): ?><dt>Registration type</dt><dd><?= h($cfg['reg_types'][$detail['reg_type']] ?? $detail['reg_type']) ?></dd><?php endif; ?>
    <?php foreach ($typeData as $k => $v): ?>
      <dt><?= h($cfg['type_fields'][$k] ?? $k) ?></dt><dd><?= h((string)$v) ?></dd>
    <?php endforeach; ?>
    <?php if ($detail['owner_name']): ?>
      <dt>Owner (co-sign)</dt><dd><?= h($detail['owner_name']) ?> &mdash; <?= $detail['owner_signed_at'] ? 'signed ' . h($detail['owner_signed_at']) : '<strong style="color:var(--warn)">not yet signed</strong>' ?></dd>
    <?php endif; ?>
    <?php if ($detail['linked_app_id']): ?><dt>Linked to-let app</dt><dd>#<?= (int)$detail['linked_app_id'] ?></dd><?php endif; ?>
    <dt>Submitted</dt><dd><?= h((string)$detail['submitted_at']) ?></dd>
  </dl>
</div>

<?php if ($items): ?>
<div class="card">
  <h2>Items</h2>
  <?php foreach ($items as $it): ?>
    <p><strong><?= h(ucfirst($it['item_type'])) ?>:</strong> <?= h($itemNames[$it['id']]) ?>
    <?php if ($it['id_number']): ?> &middot; ID: <?= h($it['id_number']) ?><?= $it['id_is_passport'] ? ' (passport)' : '' ?><?= $it['is_asylum'] ? ' &middot; <strong>asylum seeker</strong>' : '' ?><?php endif; ?>
    <?php if ($it['pet_adult_weight_kg'] !== null): ?> &middot; Adult weight: <?= h((string)$it['pet_adult_weight_kg']) ?> kg<?php endif; ?>
    </p>
    <?php foreach ($docsByItem[$it['id']] ?? [] as $d): ?>
      <p class="doclink">&mdash; <?= h($d['doc_type']) ?>: <a href="application_doc.php?id=<?= (int)$d['id'] ?>" target="_blank"><?= h($d['orig_filename']) ?></a>
      (<?= number_format($d['file_size'] / 1024) ?> KB<?= $d['doc_date'] ? ', issued ' . h($d['doc_date']) : '' ?>)</p>
    <?php endforeach; ?>
  <?php endforeach; ?>
</div>
<?php endif; ?>

<?php if (!empty($docsByItem[0])): ?>
<div class="card">
  <h2>Application Documents</h2>
  <?php foreach ($docsByItem[0] as $d): ?>
    <p class="doclink">&mdash; <?= h($d['doc_type']) ?>: <a href="application_doc.php?id=<?= (int)$d['id'] ?>" target="_blank"><?= h($d['orig_filename']) ?></a> (<?= number_format($d['file_size'] / 1024) ?> KB)</p>
  <?php endforeach; ?>
</div>
<?php endif; ?>

<div class="card">
  <h2>Acknowledgements (<?= count($acks) ?> recorded)</h2>
  <p class="note"><?php foreach ($acks as $a): ?><?= h($a['ack_code']) ?> (<?= h($a['acknowledged_by']) ?>, <?= h($a['acknowledged_at']) ?>)<br><?php endforeach; ?></p>
</div>

<form method="post">
<input type="hidden" name="csrf" value="<?= h($csrf) ?>">
<input type="hidden" name="app_id" value="<?= (int)$detailId ?>">

<?php if ($payment): ?>
<div class="card">
  <h2>Payment</h2>
  <p>Amount due: <strong>R<?= number_format((float)$payment['amount_due'], 2) ?></strong> (<?= h((string)$payment['amount_basis']) ?>)</p>
  <label><input type="checkbox" name="payment_verified" value="1" <?= $payment['verified'] ? 'checked' : '' ?>> Payment received and verified against bank statement</label>
</div>
<?php endif; ?>

<div class="card">
  <h2>Verification Checklist</h2>
  <table class="checks">
  <tr><th style="width:38%">Check</th><th style="width:16%">Result</th><th>Comment (required on Fail)</th></tr>
  <?php foreach ($checks as $c): ?>
    <tr>
      <td><?= $c['item_id'] ? '<em>' . h($itemNames[$c['item_id']] ?? '#') . ':</em> ' : '' ?><?= h($c['check_label']) ?></td>
      <td>
        <select class="res <?= h($c['result']) ?>" name="check[<?= (int)$c['id'] ?>]">
          <?php foreach (['pending' => '— pending —', 'pass' => 'Pass', 'fail' => 'Fail', 'n_a' => 'N/A'] as $v => $l): ?>
            <option value="<?= $v ?>" <?= $c['result'] === $v ? 'selected' : '' ?>><?= $l ?></option>
          <?php endforeach; ?>
        </select>
      </td>
      <td><input class="cmt" name="comment[<?= (int)$c['id'] ?>]" value="<?= h((string)$c['comment']) ?>" maxlength="500"></td>
    </tr>
  <?php endforeach; ?>
  </table>

  <?php if (!empty($cfg['approval_conditions_field'])): ?>
    <label style="display:block;margin-top:12px;font-size:.85rem;color:#444">Approval remarks / conditions (recorded on the approval)</label>
    <textarea name="approval_conditions"><?= h((string)$detail['approval_conditions']) ?></textarea>
  <?php endif; ?>

  <div class="btnrow">
    <button class="b b-save" name="action" value="save_checks">Save checklist</button>
    <?php if ($detail['status'] === 'pending_verification'): ?>
      <button class="b b-verify" name="action" value="verify"
        onclick="return confirm('Confirm: all checklist items pass and this application is verified?')">Verify<?= $cfg['post_verify_status'] === 'approved' ? ' &amp; Approve' : '' ?></button>
    <?php endif; ?>
    <?php if ($detail['status'] === 'induction_scheduled'): ?>
      <button class="b b-verify" name="action" value="approve_after_induction"
        onclick="return confirm('Confirm induction completed and approve for access card issue?')">Induction done &rarr; Approve</button>
    <?php endif; ?>
  </div>
</div>

<?php if (in_array($detail['status'], ['pending_verification'], true)): ?>
<div class="card">
  <h2>Return or Reject</h2>
  <label style="font-size:.85rem;color:#444">Reason (sent to the applicant)</label>
  <textarea name="return_reason" placeholder="List the specific deficiencies, e.g. Worker 2: police clearance older than 6 months."></textarea>
  <input type="hidden" name="reject_reason" value="">
  <div class="btnrow">
    <button class="b b-return" name="action" value="return"
      onclick="this.form.reject_reason.value=''; return confirm('Return this application for correction?')">Return for correction</button>
    <button class="b b-reject" name="action" value="reject"
      onclick="this.form.reject_reason.value=this.form.return_reason.value; return confirm('Permanently reject this application?')">Reject</button>
  </div>
</div>
<?php endif; ?>

<?php if ($detail['status'] === 'approved'): ?>
<div class="card">
  <h2>Withdraw Approval</h2>
  <p class="note">Use for breach of conditions (e.g. pet rule 1.3, letting clause 6).</p>
  <textarea name="withdraw_reason" placeholder="Reason for withdrawal"></textarea>
  <div class="btnrow">
    <button class="b b-reject" name="action" value="withdraw_approval"
      onclick="return confirm('Withdraw this approval? This cannot be undone.')">Withdraw approval</button>
  </div>
</div>
<?php endif; ?>
</form>

<?php endif; ?>
</div>
</body>
</html>
