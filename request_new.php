<?php
// ============================================================
// GEMB Access Control — request_new.php
// Resident entry point for new requests.
// ------------------------------------------------------------
// Tenant registrations, PERMANENT pet applications and Member
// Registration to Let are handled by the gemB Application Engine
// (application_form.php): per-clause undertakings with a POPIA
// audit trail, mandatory pet photo + 15 kg rule, one-pet-per-erf,
// owner e-co-signature for tenants, the Conduct Rule 15.2 to-let
// prerequisite, and site manager checklist verification.
//
// VISITOR pets (max 7 days, Conduct Rule 1.4) keep the original
// lightweight flow below — a short stay does not require the
// full Board application.
// ============================================================
require_once __DIR__ . '/layout.php';
if (session_status() === PHP_SESSION_NONE) session_start();
requireResident();

$resident_erfno = $_SESSION['resident_erf'];
$resident_name  = $_SESSION['resident_name'] ?? null;

$type = $_GET['type'] ?? null;

// ── Engine-handled types: redirect (covers old links/bookmarks) ──
if ($type === 'tenant')  { header('Location: application_form.php?type=tenant');  exit; }
if ($type === 'to_let')  { header('Location: application_form.php?type=to_let');  exit; }
if ($type === 'pet')     { header('Location: application_form.php?type=pet');     exit; }
// Visitor pets stay here:
// request_new.php?type=pet_visitor

// ── Visitor pet submission (Conduct Rule 1.4 — max 7 days) ──────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['type'] ?? '') === 'pet_visitor') {
    verifyCsrfToken();
    try {
        $pet_name    = trim($_POST['pet_name'] ?? '');
        $breed       = trim($_POST['breed'] ?? '');
        $weight      = ($_POST['weight_kg'] ?? '') !== '' ? (float)$_POST['weight_kg'] : null;
        $visit_start = $_POST['visit_start'] ?? '';
        $visit_end   = $_POST['visit_end'] ?? '';

        if (!$pet_name) {
            throw new Exception("Please enter the pet's name.");
        }
        if (!$visit_start || !$visit_end) {
            throw new Exception('Please provide visit start and end dates.');
        }
        $days = (strtotime($visit_end) - strtotime($visit_start)) / 86400;
        if ($days < 0 || $days > 7) {
            throw new Exception('Visitor pet stays may not exceed 7 days (Conduct Rule 1.4).');
        }

        db()->prepare("INSERT INTO pets
            (resident_erfno, resident_name, pet_type, pet_name, breed, weight_kg, visit_start, visit_end, status)
            VALUES (?, ?, 'visitor', ?, ?, ?, ?, ?, 'pending')"
        )->execute([$resident_erfno, $resident_name, $pet_name, $breed, $weight, $visit_start, $visit_end]);

        setFlash('success', 'Visitor pet request submitted. You will be notified once it has been reviewed.');
        header('Location: request_new.php'); exit;
    } catch (Exception $e) {
        setFlash('error', $e->getMessage());
        header('Location: request_new.php?type=pet_visitor'); exit;
    }
}

pageHeader('New Request', 'resident');
renderHeader('📝 New Request', 'resident.php?action=menu');
?>
<div class="container">
  <?= getFlash() ?>

  <?php if (!$type): ?>
    <div class="menu-grid">
      <a href="application_form.php?type=tenant" class="menu-btn">
        <span class="icon">🏠</span>Register a Tenant
      </a>
      <a href="application_form.php?type=to_let" class="menu-btn">
        <span class="icon">🔑</span>Register to Let
      </a>
      <a href="application_form.php?type=pet" class="menu-btn">
        <span class="icon">🐾</span>Register a Pet
      </a>
      <a href="request_new.php?type=pet_visitor" class="menu-btn">
        <span class="icon">🐕‍🦺</span>Visitor's Pet <small style="font-size:.72rem;color:#888;">(max 7 days)</small>
      </a>
    </div>
    <p style="text-align:center;margin-top:16px;">
      <a href="my_requests.php">View my submitted requests &rarr;</a>
    </p>
    <div class="popia-notice" style="margin-top:14px;">
      Tenant registration requires a current "Register to Let" on your erf (Conduct Rule 15.2).
      Permanent pet applications require a photo of the pet and acceptance of the Annexure C conditions.
    </div>
  <?php endif; ?>

  <?php if ($type === 'pet_visitor'): ?>
    <div class="card">
      <div class="card-title">🐕‍🦺 Visitor's Pet (max 7 days — Conduct Rule 1.4)</div>
      <form method="POST">
        <?= csrfField() ?>
        <input type="hidden" name="type" value="pet_visitor">

        <div class="form-group"><label>Pet name *</label>
          <input type="text" name="pet_name" required>
        </div>
        <div class="form-group"><label>Breed</label>
          <input type="text" name="breed">
        </div>
        <div class="form-group"><label>Adult weight (kg)</label>
          <input type="number" name="weight_kg" step="0.1" min="0">
        </div>
        <div class="form-group"><label>Visit start date *</label>
          <input type="date" name="visit_start" required>
        </div>
        <div class="form-group"><label>Visit end date * <small style="color:#888;">(max 7 days)</small></label>
          <input type="date" name="visit_end" required>
        </div>
        <button type="submit" class="btn btn-primary btn-block">Submit Visitor Pet Request</button>
      </form>
      <div class="popia-notice">For a permanent pet, please use <a href="application_form.php?type=pet">the pet application</a> instead.</div>
    </div>
  <?php endif; ?>

</div>
<?php pageFooter(); ?>
