<?php
// ============================================================
// GEMB Access Control — application_admin.php
// Site Manager verification portal for the Application Engine.
// Conventions identical to security.php: requireSecurity(),
// csrfField()/verifyCsrfToken(), setFlash()/getFlash(),
// pageHeader()/renderHeader()/pageFooter(), PDO via db().
// Session: $_SESSION['security_id'], $_SESSION['security_name'].
// ============================================================
require_once __DIR__ . '/application_lib.php';
if (session_status() === PHP_SESSION_NONE) session_start();

requireSecurity();   // same guard as every security.php action

$managerId   = (int)($_SESSION['security_id'] ?? 0);
$managerName = $_SESSION['security_name'] ?? 'Unknown';

// ════════════════════════════════════════════════════════
// POST ACTIONS
// ════════════════════════════════════════════════════════
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken();
    $appId  = (int)($_POST['app_id'] ?? 0);
    $action = $_POST['app_action'] ?? '';

    // ── Save checklist results + payment verification ─────
    if ($action === 'save_checks') {
        $upd = db()->prepare(
            "UPDATE application_checklist
             SET result=?, comment=?, checked_by=?, checked_at=NOW()
             WHERE id=? AND application_id=?"
        );
        foreach (($_POST['check'] ?? []) as $checkId => $result) {
            if (!in_array($result, ['pending', 'pass', 'fail', 'n_a'], true)) continue;
            $comment = appClean($_POST['comment'][(int)$checkId] ?? '', 500);
            $upd->execute([$result, $comment, $managerId, (int)$checkId, $appId]);
        }
        $pv = isset($_POST['payment_verified']) ? 1 : 0;
        db()->prepare(
            "UPDATE application_payments
             SET verified=?, verified_by=IF(?=1, ?, NULL), verified_at=IF(?=1, NOW(), NULL)
             WHERE application_id=?"
        )->execute([$pv, $pv, $managerId, $pv, $appId]);
        setFlash('success', 'Checklist saved.');
        header('Location: application_admin.php?id=' . $appId); exit;
    }

    // ── Verify (blocked until every check is Pass or N/A) ──
    if ($action === 'verify') {
        if (!appChecklistComplete($appId)) {
            setFlash('error', 'Cannot verify — outstanding checklist items remain. Every check must be Pass or N/A.');
            header('Location: application_admin.php?id=' . $appId); exit;
        }
        $stmt = db()->prepare("SELECT app_type FROM applications WHERE id=? LIMIT 1");
        $stmt->execute([$appId]);
        $appType = $stmt->fetchColumn();
        $next = APP_TYPES[$appType]['post_verify_status'] ?? 'approved';

        if (appSetStatus($appId, 'verified', 'site_manager', $managerId, 'checklist complete')) {
            if ($next === 'induction_scheduled') {
                // Contractor path — induction session before card issue
                appSetStatus($appId, 'induction_scheduled', 'site_manager', $managerId, 'induction to be arranged');
                // ── MAILER HOOK (induction): notify the contact person to
                //    arrange the induction session, per the Status-Mark procedure.
                //    Wire your existing mail routine here, e.g.:
                //    appMailInduction($appId);
                setFlash('success', 'Verified. Status: induction scheduled — arrange the induction session with the contact person.');
            } else {
                // Direct approval path (to_let / tenant / pet)
                $conditions = appClean($_POST['approval_conditions'] ?? '', 2000);
                db()->prepare(
                    "UPDATE applications
                     SET approved_by=?, approved_at=NOW(),
                         approval_conditions=NULLIF(?, ''),
                         valid_until=NULLIF(JSON_UNQUOTE(JSON_EXTRACT(type_data, '$.rental_to')), 'null')
                     WHERE id=?"
                )->execute([$managerId, $conditions, $appId]);
                appSetStatus($appId, 'approved', 'site_manager', $managerId, 'approved after verification');

                // ═══ LIVE-TABLE BRIDGES (wired) ═══
                if ($appType === 'tenant') {
                    [$tenantId, $residentId, $vehicles] = appBridgeTenantToLive($appId, $managerName);
                    if ($tenantId > 0) {
                        setFlash('success', "Tenant approved and bridged to live records: tenants #{$tenantId}"
                            . ($residentId > 0 ? ", resident occupant record created" : ", NOTE: no occupant code available on this erf — create the resident manually")
                            . ", {$vehicles} vehicle(s) whitelisted for LPR.");
                    } else {
                        setFlash('success', 'Tenant application approved. (Live records already existed for this application; nothing duplicated.)');
                    }
                } elseif ($appType === 'pet') {
                    $petId = appBridgePetToLive($appId, $managerName);
                    setFlash('success', $petId > 0
                        ? "Pet approved and recorded in the live pets register (#{$petId})."
                        : 'Pet application approved. (Live record already existed; nothing duplicated.)');
                } else {
                    setFlash('success', 'Application verified and approved.');
                }
            }
        } else {
            setFlash('error', 'Status change not permitted from the current state.');
        }
        header('Location: application_admin.php?id=' . $appId); exit;
    }

    // ── Contractor: induction done → approve + BRIDGE to live SPs ──
    if ($action === 'approve_after_induction') {
        if (appSetStatus($appId, 'approved', 'site_manager', $managerId, 'induction completed')) {
            db()->prepare("UPDATE applications SET approved_by=?, approved_at=NOW() WHERE id=?")
                ->execute([$managerId, $appId]);

            // ═══ APPROVAL BRIDGE (wired, type-aware) ═══
            $stmtT = db()->prepare("SELECT app_type FROM applications WHERE id=? LIMIT 1");
            $stmtT->execute([$appId]);
            $bridgeType = $stmtT->fetchColumn();

            // Contractor: 1 lead (card) + 1 worker (slip) per verified worker
            [$leadId, $workerCount] = appBridgeContractorToSp($appId, $managerName);
            if ($leadId > 0) {
                setFlash('success', "Induction confirmed — application approved. Bridged to live records: 1 contractor lead + {$workerCount} worker(s) created with QR codes. Print the permits below.");
            } else {
                setFlash('success', 'Induction confirmed — application approved. (Live SP records already existed for this application; nothing duplicated.)');
            }
        } else {
            setFlash('error', 'Status change not permitted from the current state.');
        }
        header('Location: application_admin.php?id=' . $appId); exit;
    }

    // ── Return for correction ──────────────────────────────
    if ($action === 'return') {
        $reason = appClean($_POST['return_reason'] ?? '', 2000);
        if ($reason === '') {
            setFlash('error', 'A reason is required when returning an application.');
        } else {
            db()->prepare("UPDATE applications SET return_reason=? WHERE id=?")->execute([$reason, $appId]);
            appSetStatus($appId, 'returned', 'site_manager', $managerId, 'returned: ' . mb_substr($reason, 0, 200));

            // ── MAILER HOOK (return): e-mail the applicant the deficiencies
            //    plus their resume link. Token is already on the row:
            //    $t = db()->prepare("SELECT applicant_email, resume_token FROM applications WHERE id=?");
            //    $t->execute([$appId]); $row = $t->fetch();
            //    Resume URL: SITE_URL . '/application_form.php?resume=' . $row['resume_token']
            //    (full gemb.co.za URL — never through a shortener; token must arrive unmodified)
            setFlash('success', 'Application returned to the applicant with the deficiencies listed.');
        }
        header('Location: application_admin.php?id=' . $appId); exit;
    }

    // ── Reject ─────────────────────────────────────────────
    if ($action === 'reject') {
        $reason = appClean($_POST['return_reason'] ?? '', 2000);
        if ($reason === '') {
            setFlash('error', 'A reason is required when rejecting an application.');
        } else {
            appSetStatus($appId, 'rejected', 'site_manager', $managerId, 'rejected: ' . mb_substr($reason, 0, 200));
            setFlash('success', 'Application rejected.');
        }
        header('Location: application_admin.php?id=' . $appId); exit;
    }

    // ── Withdraw an approval (pet rule 1.3 / letting clause 6) ──
    if ($action === 'withdraw_approval') {
        $reason = appClean($_POST['withdraw_reason'] ?? '', 2000);
        if (appSetStatus($appId, 'withdrawn', 'site_manager', $managerId, 'approval withdrawn: ' . mb_substr($reason, 0, 200))) {
            // ═══ DEACTIVATION BRIDGE (wired) ═══ closes the linked live
            // records too: tenants/pets → denied(+reason); tenant's resident
            // row → inactive; their vehicles → active=0; contractor SPs → revoked.
            appDeactivateBridged($appId, $reason !== '' ? $reason : 'Approval withdrawn by site manager');
            setFlash('success', 'Approval withdrawn and linked live records deactivated.');
        } else {
            setFlash('error', 'Status change not permitted from the current state.');
        }
        header('Location: application_admin.php'); exit;
    }

    header('Location: application_admin.php'); exit;
}

// ════════════════════════════════════════════════════════
// DETAIL VIEW?
// ════════════════════════════════════════════════════════
$detailId = filter_var($_GET['id'] ?? 0, FILTER_VALIDATE_INT);
$detail = null;
if ($detailId) {
    $stmt = db()->prepare("SELECT * FROM applications WHERE id=? LIMIT 1");
    $stmt->execute([$detailId]);
    $detail = $stmt->fetch();
    if ($detail && $detail['app_type'] !== 'contractor') {
        http_response_code(403);
        exit('This application type is approved in the admin portal (Board delegation, MOI Art. 20.5.3).');
    }
}

// ════════════════════════════════════════════════════════
// QUEUE VIEW
// ════════════════════════════════════════════════════════
if (!$detail) {

    // Whitelist status filter — same pattern as security.php logs/approvals
    $filter = $_GET['status'] ?? 'pending_verification';
    if (!in_array($filter, array_merge(array_keys(APP_TRANSITIONS), ['all']), true)) {
        $filter = 'pending_verification';
    }

    if ($filter === 'all') {
        $apps = db()->query(
            "SELECT id, app_ref, app_type, applicant_name, company_name, erf_no, submitted_at, status
             FROM applications WHERE app_type = 'contractor'
             ORDER BY submitted_at DESC LIMIT 200"
        )->fetchAll();
    } else {
        // Oldest first for work queues — first received = first served
        $stmt = db()->prepare(
            "SELECT id, app_ref, app_type, applicant_name, company_name, erf_no, submitted_at, status
             FROM applications WHERE status=? AND app_type = 'contractor'
             ORDER BY submitted_at ASC LIMIT 200"
        );
        $stmt->execute([$filter]);
        $apps = $stmt->fetchAll();
    }

    pageHeader('Applications', 'security');
    renderHeader('📋 Application Verification', 'security.php?action=menu');
    ?>
    <div class="container">
      <?= getFlash() ?>

      <div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;">
        <?php foreach ([
            'pending_verification' => '⏳ Pending',
            'submitted'            => '✍️ Awaiting Co-sign',
            'induction_scheduled'  => '🎓 Induction',
            'returned'             => '↩️ Returned',
            'approved'             => '✅ Approved',
            'all'                  => '📋 All',
        ] as $s => $label): ?>
        <a href="application_admin.php?status=<?= $s ?>"
           class="btn btn-sm <?= $filter === $s ? 'btn-primary' : 'btn-secondary' ?>"><?= $label ?></a>
        <?php endforeach; ?>
      </div>

      <?php if (empty($apps)): ?>
        <div class="card"><p style="color:#666;">No applications in this category.</p></div>
      <?php endif; ?>

      <?php foreach ($apps as $a):
        $cfg = APP_TYPES[$a['app_type']] ?? null;
        $statusColors = [
            'pending_verification' => '#ffc107', 'submitted' => '#888',
            'verified' => '#17a2b8', 'induction_scheduled' => '#17a2b8',
            'approved' => '#28a745', 'returned' => '#e67e22',
            'rejected' => '#dc3545', 'withdrawn' => '#dc3545', 'expired' => '#aaa',
        ];
        $col = $statusColors[$a['status']] ?? '#999';
      ?>
      <div class="card" style="border-left:4px solid <?= $col ?>">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
          <div>
            <strong><?= $cfg ? $cfg['icon'] : '' ?> <?= htmlspecialchars($a['company_name'] ?: $a['applicant_name']) ?></strong>
            <span style="color:#666;font-size:.82rem;margin-left:6px;"><?= htmlspecialchars($cfg['label'] ?? $a['app_type']) ?></span>
            <div style="font-size:.8rem;color:#999;margin-top:2px;font-family:monospace;">
              <?= htmlspecialchars($a['app_ref']) ?>
              <?= $a['erf_no'] ? ' &nbsp;|&nbsp; Erf ' . htmlspecialchars($a['erf_no']) : '' ?>
              &nbsp;|&nbsp; <?= $a['submitted_at'] ? date('d M Y H:i', strtotime($a['submitted_at'])) : '—' ?>
            </div>
          </div>
          <div style="display:flex;gap:6px;align-items:center;">
            <span class="badge badge-<?= in_array($a['status'], ['approved']) ? 'success' : (in_array($a['status'], ['rejected', 'withdrawn', 'expired']) ? 'danger' : 'warning') ?>">
              <?= str_replace('_', ' ', $a['status']) ?>
            </span>
            <?php if ($a['status'] === 'approved' && in_array($a['app_type'], ['contractor', 'estate_agent'], true)): ?>
            <a href="application_admin.php?id=<?= $a['id'] ?>" class="btn btn-success btn-sm">🪪 Permits</a>
            <?php endif; ?>
            <a href="application_admin.php?id=<?= $a['id'] ?>" class="btn btn-primary btn-sm">Open</a>
          </div>
        </div>
      </div>
      <?php endforeach; ?>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end queue

// ════════════════════════════════════════════════════════
// DETAIL / CHECKLIST VIEW
// ════════════════════════════════════════════════════════
$cfg      = APP_TYPES[$detail['app_type']];
$typeData = $detail['type_data'] ? json_decode($detail['type_data'], true) : [];

$stmt = db()->prepare("SELECT * FROM application_items WHERE application_id=? ORDER BY item_type, id");
$stmt->execute([$detailId]);
$items = $stmt->fetchAll();

$stmt = db()->prepare("SELECT * FROM application_documents WHERE application_id=?");
$stmt->execute([$detailId]);
$docs = $stmt->fetchAll();
$docsByItem = [];
foreach ($docs as $d) $docsByItem[$d['item_id'] ?? 0][] = $d;

$stmt = db()->prepare("SELECT * FROM application_checklist WHERE application_id=? ORDER BY item_id IS NULL DESC, item_id, id");
$stmt->execute([$detailId]);
$checks = $stmt->fetchAll();

$stmt = db()->prepare("SELECT * FROM application_payments WHERE application_id=? LIMIT 1");
$stmt->execute([$detailId]);
$payment = $stmt->fetch();

$stmt = db()->prepare("SELECT ack_code, acknowledged_by, acknowledged_at FROM application_acknowledgements WHERE application_id=? ORDER BY id");
$stmt->execute([$detailId]);
$acks = $stmt->fetchAll();

$itemNames = [];
foreach ($items as $it) {
    $n = trim(($it['first_name'] ?? '') . ' ' . ($it['surname'] ?? ''));
    if ($n === '') $n = $it['vehicle_reg'] ?? '';
    if ($n === '' && !empty($it['pet_name'])) $n = $it['pet_name'] . ' — ' . ($it['pet_species'] ?? '') . ' (' . ($it['pet_breed'] ?? '') . ')';
    if ($n === '') $n = $it['pet_species'] ? $it['pet_species'] . ' (' . ($it['pet_breed'] ?? '') . ')' : '';
    $itemNames[$it['id']] = $n !== '' ? $n : ('#' . $it['id']);
}

// ── Bridged live access records (approved contractor applications):
//    the lead + workers created in service_providers by the approval
//    bridge, so permits can be printed directly from this screen.
$bridgedSps = [];
if ($detail['status'] === 'approved' && in_array($detail['app_type'], ['contractor', 'estate_agent'], true)) {
    try {
        $bs = db()->prepare(
            "SELECT id, category, service_name, permit_type, unique_code, expired
             FROM service_providers
             WHERE notes LIKE ? AND notes NOT LIKE '%Superseded%'
             ORDER BY FIELD(category,'contractor_lead','estate_agent','contractor_worker'), id"
        );
        $bs->execute(['%[gemB ' . $detail['app_ref'] . ']%']);
        $bridgedSps = $bs->fetchAll();
    } catch (Exception $e) {
        $bridgedSps = [];
    }
}

pageHeader('Application ' . $detail['app_ref'], 'security');
renderHeader($cfg['icon'] . ' ' . htmlspecialchars($detail['app_ref']), 'application_admin.php');
?>
<div class="container">
  <?= getFlash() ?>

  <!-- ── Application summary ─────────────────────────── -->
  <div class="card">
    <div class="card-title"><?= htmlspecialchars($cfg['label']) ?>
      <span class="badge badge-<?= $detail['status'] === 'approved' ? 'success' : (in_array($detail['status'], ['rejected', 'withdrawn', 'expired']) ? 'danger' : 'warning') ?>" style="margin-left:8px;">
        <?= str_replace('_', ' ', $detail['status']) ?>
      </span>
    </div>
    <div class="table-wrap"><table>
      <tr><td style="min-width:180px;color:#666;">Applicant</td>
          <td><?= htmlspecialchars($detail['applicant_name']) ?> — <?= htmlspecialchars($detail['applicant_email'] ?? '') ?>, <?= htmlspecialchars($detail['applicant_phone'] ?? '') ?></td></tr>
      <?php if ($detail['company_name']): ?>
      <tr><td style="color:#666;">Company</td>
          <td><?= htmlspecialchars($detail['company_name']) ?> · <?= htmlspecialchars($detail['company_type'] ?? '') ?> · Reg: <?= htmlspecialchars($detail['company_reg_no'] ?? '') ?> · Owner: <?= htmlspecialchars($detail['company_owner'] ?? '') ?></td></tr>
      <?php endif; ?>
      <?php if ($detail['erf_no']): ?>
      <tr><td style="color:#666;">Erf</td><td><?= htmlspecialchars($detail['erf_no']) ?></td></tr>
      <?php endif; ?>
      <?php if ($detail['reg_type']): ?>
      <tr><td style="color:#666;">Registration type</td><td><?= htmlspecialchars($cfg['reg_types'][$detail['reg_type']] ?? $detail['reg_type']) ?></td></tr>
      <?php endif; ?>
      <?php foreach ($typeData as $k => $v): ?>
      <tr><td style="color:#666;"><?= htmlspecialchars($cfg['type_fields'][$k] ?? $k) ?></td><td><?= htmlspecialchars((string)$v) ?></td></tr>
      <?php endforeach; ?>
      <?php if ($detail['owner_name']): ?>
      <tr><td style="color:#666;">Owner (co-sign)</td>
          <td><?= htmlspecialchars($detail['owner_name']) ?> —
          <?= $detail['owner_signed_at']
              ? '<span style="color:#28a745;">✅ signed ' . htmlspecialchars($detail['owner_signed_at']) . '</span>'
              : '<strong style="color:#e67e22;">⏳ not yet signed</strong>' ?></td></tr>
      <?php endif; ?>
      <?php if ($detail['linked_app_id']): ?>
      <tr><td style="color:#666;">Linked to-let application</td><td>#<?= (int)$detail['linked_app_id'] ?></td></tr>
      <?php endif; ?>
      <tr><td style="color:#666;">Submitted</td><td><?= htmlspecialchars($detail['submitted_at'] ?? '—') ?></td></tr>
      <?php if ($detail['return_reason']): ?>
      <tr><td style="color:#666;">Last return reason</td><td style="color:#e67e22;"><?= htmlspecialchars($detail['return_reason']) ?></td></tr>
      <?php endif; ?>
    </table></div>
  </div>

<?php if ($bridgedSps): ?>
  <!-- ── Access records & permit printing (bridged live SPs) ─── -->
  <div class="card" style="border-left:4px solid #28a745;">
    <div class="card-title">🪪 Access Records &amp; Permits</div>
    <p style="font-size:.85rem;color:#666;margin-top:0;">Created in the live access system by this application's approval. Print each permit here (photo is taken/uploaded on the print screen).</p>
    <div class="table-wrap"><table>
      <tr><th>Name</th><th>Type</th><th>Code</th><th>Permit</th></tr>
      <?php foreach ($bridgedSps as $b): ?>
      <tr>
        <td><?= htmlspecialchars($b['service_name']) ?></td>
        <td><?= $b['category'] === 'contractor_lead' ? '👷 Contractor Lead' : ($b['category'] === 'estate_agent' ? '🏢 Estate Agent' : '🪖 Contractor Worker') ?></td>
        <td style="font-family:monospace;"><strong><?= htmlspecialchars($b['unique_code']) ?></strong></td>
        <td>
          <?php if (!$b['expired']): ?>
          <?php
            // "Card" permits are wearable plastic and are actually printed
            // via the W103 label sheet, not the old permit_card.php path —
            // see security.php's approved-SP print button, which this
            // mirrors. The stored permit_type value stays 'card' (no
            // schema change); only the print destination is 'label'.
            $printType  = ($b['permit_type'] === 'card') ? 'label' : 'slip';
            $printLabel = ($b['permit_type'] === 'card') ? 'Print Card' : 'Print Slip';
          ?>
          <a href="permit_photo_upload.php?id=<?= (int)$b['id'] ?>&type=<?= $printType ?>"
             target="_blank" class="btn btn-primary btn-sm">
            🖨️ <?= $printLabel ?>
          </a>
          <?php else: ?>
          <span class="badge badge-muted">revoked</span>
          <?php endif; ?>
        </td>
      </tr>
      <?php endforeach; ?>
    </table></div>
  </div>
<?php endif; ?>

  <!-- ── Items + per-item documents ──────────────────── -->
  <?php if (!empty($items)): ?>
  <div class="card">
    <div class="card-title">Items</div>
    <?php foreach ($items as $it): ?>
    <div style="padding:8px 0;border-bottom:1px solid #eee;">
      <strong><?= htmlspecialchars(ucfirst($it['item_type'])) ?>:</strong>
      <?= htmlspecialchars($itemNames[$it['id']]) ?>
      <?php if ($it['id_number']): ?>
        <span style="font-size:.85rem;color:#666;">· ID: <?= htmlspecialchars($it['id_number']) ?><?= $it['id_is_passport'] ? ' (passport)' : '' ?></span>
        <?php if ($it['is_asylum']): ?><span class="badge badge-warning" style="font-size:.72rem;">ASYLUM — HA verification required</span><?php endif; ?>
      <?php endif; ?>
      <?php if ($it['pet_adult_weight_kg'] !== null): ?>
        <span style="font-size:.85rem;color:#666;">· Adult weight: <?= htmlspecialchars((string)$it['pet_adult_weight_kg']) ?> kg</span>
      <?php endif; ?>
      <?php foreach ($docsByItem[$it['id']] ?? [] as $d): ?>
        <div style="font-size:.85rem;margin-top:3px;">
          📎 <?= htmlspecialchars($d['doc_type']) ?>:
          <a href="application_doc.php?id=<?= (int)$d['id'] ?>" target="_blank"><?= htmlspecialchars($d['orig_filename']) ?></a>
          <span style="color:#999;">(<?= number_format($d['file_size'] / 1024) ?> KB<?= $d['doc_date'] ? ', issued ' . htmlspecialchars($d['doc_date']) : '' ?>)</span>
        </div>
      <?php endforeach; ?>
    </div>
    <?php endforeach; ?>
  </div>
  <?php endif; ?>

  <?php if (!empty($docsByItem[0])): ?>
  <div class="card">
    <div class="card-title">Application Documents</div>
    <?php foreach ($docsByItem[0] as $d): ?>
      <div style="font-size:.88rem;padding:4px 0;">
        📎 <?= htmlspecialchars($d['doc_type']) ?>:
        <a href="application_doc.php?id=<?= (int)$d['id'] ?>" target="_blank"><?= htmlspecialchars($d['orig_filename']) ?></a>
        <span style="color:#999;">(<?= number_format($d['file_size'] / 1024) ?> KB)</span>
      </div>
    <?php endforeach; ?>
  </div>
  <?php endif; ?>

  <div class="card">
    <div class="card-title">Acknowledgements (<?= count($acks) ?> recorded)</div>
    <div style="font-size:.8rem;color:#666;">
      <?php foreach ($acks as $a): ?>
        ✔ <?= htmlspecialchars($a['ack_code']) ?>
        <span style="color:#999;">(<?= htmlspecialchars($a['acknowledged_by']) ?>, <?= htmlspecialchars($a['acknowledged_at']) ?>)</span><br>
      <?php endforeach; ?>
    </div>
  </div>

  <!-- ── Checklist + actions ─────────────────────────── -->
  <form method="POST" action="application_admin.php">
    <?= csrfField() ?>
    <input type="hidden" name="app_id" value="<?= (int)$detailId ?>">

    <?php if ($payment): ?>
    <div class="card">
      <div class="card-title">Payment</div>
      <p style="font-size:.9rem;">Amount due: <strong>R<?= number_format((float)$payment['amount_due'], 2) ?></strong>
         <span style="color:#666;">(<?= htmlspecialchars($payment['amount_basis'] ?? '') ?>)</span></p>
      <label style="display:flex;align-items:center;gap:8px;font-size:.9rem;cursor:pointer;">
        <input type="checkbox" name="payment_verified" value="1" <?= $payment['verified'] ? 'checked' : '' ?>>
        Payment received and verified against the bank statement
      </label>
    </div>
    <?php endif; ?>

    <div class="card">
      <div class="card-title">Verification Checklist</div>
      <div class="table-wrap"><table>
        <tr><th style="width:42%;">Check</th><th style="width:16%;">Result</th><th>Comment (required on Fail)</th></tr>
        <?php foreach ($checks as $c): ?>
        <tr>
          <td style="font-size:.87rem;">
            <?= $c['item_id'] ? '<em>' . htmlspecialchars($itemNames[$c['item_id']] ?? '#') . ':</em> ' : '' ?>
            <?= htmlspecialchars($c['check_label']) ?>
          </td>
          <td>
            <select name="check[<?= (int)$c['id'] ?>]"
                    style="padding:6px;border:1px solid #dee2e6;border-radius:6px;
                           background:<?= $c['result'] === 'pass' ? '#e8f8ee' : ($c['result'] === 'fail' ? '#fdecec' : '#fff') ?>;">
              <?php foreach (['pending' => '— pending —', 'pass' => '✅ Pass', 'fail' => '❌ Fail', 'n_a' => 'N/A'] as $v => $l): ?>
                <option value="<?= $v ?>" <?= $c['result'] === $v ? 'selected' : '' ?>><?= $l ?></option>
              <?php endforeach; ?>
            </select>
          </td>
          <td><input type="text" name="comment[<?= (int)$c['id'] ?>]"
                     value="<?= htmlspecialchars($c['comment'] ?? '') ?>" maxlength="500"
                     style="width:100%;padding:6px;border:1px solid #dee2e6;border-radius:6px;font-size:.85rem;"></td>
        </tr>
        <?php endforeach; ?>
      </table></div>

      <?php if (!empty($cfg['approval_conditions_field'])): ?>
      <div class="form-group" style="margin-top:12px;">
        <label>Approval remarks / conditions (recorded on the approval, per the pet form)</label>
        <textarea name="approval_conditions" rows="2"
                  style="width:100%;padding:8px;border:1px solid #dee2e6;border-radius:6px;"><?= htmlspecialchars($detail['approval_conditions'] ?? '') ?></textarea>
      </div>
      <?php endif; ?>

      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:14px;">
        <button type="submit" name="app_action" value="save_checks" class="btn btn-primary">💾 Save Checklist</button>
        <?php if ($detail['status'] === 'pending_verification'): ?>
        <button type="submit" name="app_action" value="verify" class="btn btn-success"
                onclick="return confirm('Confirm: all checklist items pass and this application is verified?')">
          ✅ Verify<?= $cfg['post_verify_status'] === 'approved' ? ' & Approve' : '' ?>
        </button>
        <?php endif; ?>
        <?php if ($detail['status'] === 'induction_scheduled'): ?>
        <button type="submit" name="app_action" value="approve_after_induction" class="btn btn-success"
                onclick="return confirm('Confirm induction completed? This approves the application and creates the live contractor lead + worker records with QR codes.')">
          🎓 Induction Done → Approve & Create Access Records
        </button>
        <?php endif; ?>
      </div>
    </div>

    <?php if ($detail['status'] === 'pending_verification'): ?>
    <div class="card" style="border-left:4px solid #e67e22;">
      <div class="card-title">↩️ Return or ❌ Reject</div>
      <div class="form-group">
        <label>Reason (sent to the applicant)</label>
        <textarea name="return_reason" rows="3"
                  placeholder="List the specific deficiencies, e.g. Worker 2: police clearance older than 6 months."
                  style="width:100%;padding:8px;border:1px solid #dee2e6;border-radius:6px;"></textarea>
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;">
        <button type="submit" name="app_action" value="return" class="btn btn-warning"
                onclick="return confirm('Return this application for correction?')">↩️ Return for Correction</button>
        <button type="submit" name="app_action" value="reject" class="btn btn-danger"
                onclick="return confirm('Permanently reject this application?')">❌ Reject</button>
      </div>
    </div>
    <?php endif; ?>

    <?php if ($detail['status'] === 'approved'): ?>
    <div class="card" style="border-left:4px solid #dc3545;">
      <div class="card-title">🚫 Withdraw Approval</div>
      <p style="font-size:.85rem;color:#666;">For breach of conditions (pet rule 1.3, letting clause 6).</p>
      <div class="form-group">
        <textarea name="withdraw_reason" rows="2" placeholder="Reason for withdrawal"
                  style="width:100%;padding:8px;border:1px solid #dee2e6;border-radius:6px;"></textarea>
      </div>
      <button type="submit" name="app_action" value="withdraw_approval" class="btn btn-danger"
              onclick="return confirm('Withdraw this approval? This cannot be undone.')">Withdraw Approval</button>
    </div>
    <?php endif; ?>
  </form>

  <div class="popia-notice">Verification actions are permanently logged per POPIA §11.</div>
</div>
<?php pageFooter(); ?>
