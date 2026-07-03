<?php
// ============================================================
// GEMB Access Control — agent_invite.php (resident-facing)
// A resident invites an Estate Agent to complete their OWN
// registration via application_form.php?resume={token}.
// Conventions: PDO via db(), requireResident(), pageHeader()/
// renderHeader()/pageFooter(), csrfField()/verifyCsrfToken(),
// getFlash()/setFlash() — all from layout.php, same as resident.php.
// ============================================================
require_once __DIR__ . '/application_lib.php';   // pulls in layout.php + smtp_mail.php
requireResident();

$rid   = $_SESSION['resident_id'];
$rname = $_SESSION['resident_name'];
$rerf  = $_SESSION['resident_erf'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken();

    $agentName  = appClean($_POST['agent_name'] ?? '', 120);
    $agentEmail = filter_var((string)($_POST['agent_email'] ?? ''), FILTER_VALIDATE_EMAIL) ?: '';
    $agencyName = appClean($_POST['agency_name'] ?? '', 150);

    if ($agentName === '') {
        setFlash('error', 'The agent\'s full name is required.');
    } elseif ($agentEmail === '') {
        setFlash('error', 'A valid e-mail address for the agent is required.');
    } else {
        $result = appCreateEstateAgentInvite($rerf, $rname, $agentName, $agentEmail, $agencyName);
        setFlash('success', 'Invitation sent to ' . htmlspecialchars($agentEmail) . '. Reference: ' . htmlspecialchars($result['app_ref']));
    }
    header('Location: agent_invite.php'); exit;
}

// ── My previous invitations — erf_no carries "invited by" for this type ──
$invites = db()->prepare(
    "SELECT app_ref, applicant_name, applicant_email, company_name, status, created_at
     FROM applications
     WHERE app_type = 'estate_agent' AND erf_no = ?
     ORDER BY created_at DESC LIMIT 20"
);
$invites->execute([$rerf]);
$invites = $invites->fetchAll();

$statusBadge = [
    'draft'                => ['label' => 'Awaiting agent',        'class' => 'warning'],
    'submitted'             => ['label' => 'Submitted for review',  'class' => 'info'],
    'pending_verification'  => ['label' => 'Under review',          'class' => 'info'],
    'returned'              => ['label' => 'Returned to agent',     'class' => 'warning'],
    'verified'              => ['label' => 'Verified',              'class' => 'info'],
    'induction_scheduled'   => ['label' => 'Induction scheduled',   'class' => 'info'],
    'approved'              => ['label' => 'Approved',              'class' => 'success'],
    'rejected'              => ['label' => 'Rejected',              'class' => 'danger'],
    'withdrawn'             => ['label' => 'Withdrawn',             'class' => 'muted'],
    'expired'               => ['label' => 'Expired',               'class' => 'muted'],
];

pageHeader('Invite an Estate Agent', 'resident');
renderHeader('🏢 Invite an Estate Agent', 'resident.php?action=menu');
?>
<div class="container">
  <?= getFlash() ?>

  <div class="card">
    <div class="card-title">Send an Invitation</div>
    <p style="font-size:.88rem;color:#444;margin-bottom:14px;">
      If you're bringing in an estate agent to market or show your property, invite them here.
      They'll receive an e-mail with a link to their own registration form — you don't need to
      supply their Fidelity Fund Certificate, employment letter or agency details on their behalf.
    </p>
    <form method="POST">
      <?= csrfField() ?>
      <div class="form-group">
        <label>Agent's full name *</label>
        <input type="text" name="agent_name" required maxlength="120">
      </div>
      <div class="form-group">
        <label>Agent's e-mail address *</label>
        <input type="email" name="agent_email" required maxlength="150">
      </div>
      <div class="form-group">
        <label>Agency name (optional, if you know it)</label>
        <input type="text" name="agency_name" maxlength="150">
      </div>
      <button type="submit" class="btn btn-primary btn-block">Send Invitation</button>
    </form>
  </div>

  <?php if (!empty($invites)): ?>
  <div class="card">
    <div class="card-title">My Invitations</div>
    <div class="table-wrap">
      <table>
        <tr><th>Agent</th><th>Agency</th><th>Status</th><th>Sent</th><th>Ref</th></tr>
        <?php foreach ($invites as $inv):
              $b = $statusBadge[$inv['status']] ?? ['label' => ucfirst($inv['status']), 'class' => 'muted']; ?>
        <tr>
          <td><?= htmlspecialchars($inv['applicant_name']) ?><br>
              <span style="font-size:.78rem;color:#888;"><?= htmlspecialchars($inv['applicant_email']) ?></span></td>
          <td><?= htmlspecialchars($inv['company_name'] ?? '') ?></td>
          <td><span class="badge badge-<?= $b['class'] ?>"><?= htmlspecialchars($b['label']) ?></span></td>
          <td><?= date('d M Y', strtotime($inv['created_at'])) ?></td>
          <td style="font-size:.8rem;color:#888;"><?= htmlspecialchars($inv['app_ref']) ?></td>
        </tr>
        <?php endforeach; ?>
      </table>
    </div>
  </div>
  <?php endif; ?>
</div>
<?php pageFooter(); ?>
