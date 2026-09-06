<?php
// ============================================================
// GEMB Access Control — forgot.php
// Self-service password / PIN reset via email OTP.
// Roles: admin | resident | security   (NOT guard — guards are
// reset by an admin or security officer.)
//
// Flow:  identify  ->  otp  ->  reset
//   identify : enter username (admin/security) or erf+code (resident)
//   otp      : 6-digit code sent to the account's email on file
//   reset    : set a new password (admin/security) or PIN (resident)
//
// Security:
//   - generic "if an account exists…" messaging (no enumeration)
//   - OTP is single-use, 5-minute expiry (twilio_helper)
//   - OTP attempts capped per session
//   - on success: clears the brute-force lock, resets device token,
//     stamps password_changed_at (admin/security) for rotation
// ============================================================
require_once __DIR__ . '/layout.php';
require_once __DIR__ . '/twilio_helper.php';
if (session_status() === PHP_SESSION_NONE) session_start();

// ── Role configuration (fixed whitelist — never from user input) ──
$ROLES = [
    'admin' => [
        'table'    => 'admins',
        'pwcol'    => 'password',
        'stamp'    => true,            // track password_changed_at
        'credKind' => 'password',      // min 8 chars
        'title'    => 'Administrator',
        'accent'   => 'admin',
        'icon'     => '⚙️',
        'login'    => 'admin.php?action=login',
        'idBy'     => 'username',
    ],
    'security' => [
        'table'    => 'security_users',
        'pwcol'    => 'pin',
        'stamp'    => true,
        'credKind' => 'password',
        'title'    => 'Security Officer',
        'accent'   => 'security',
        'icon'     => '🛡️',
        'login'    => 'security.php?action=login',
        'idBy'     => 'username',
    ],
    'resident' => [
        'table'    => 'residents',
        'pwcol'    => 'pin_hash',
        'stamp'    => false,
        'credKind' => 'pin',           // exactly 4 digits
        'title'    => 'Resident',
        'accent'   => 'resident',
        'icon'     => '🏠',
        'login'    => 'resident.php?action=login',
        'idBy'     => 'erf',
    ],
];

// ── Resolve role (GET on entry, else carried in session) ──
$role = $_GET['role'] ?? ($_SESSION['fp_role'] ?? '');
if (!isset($ROLES[$role])) { header('Location: AS-menu.php'); exit; }
$cfg = $ROLES[$role];

// ── Cancel / restart ──
if (isset($_GET['cancel'])) {
    foreach (['fp_role','fp_step','fp_id','fp_email','fp_identifier','fp_otp_tries'] as $k) {
        unset($_SESSION[$k]);
    }
    header('Location: forgot.php?role=' . urlencode($role)); exit;
}

// If the role changed via GET, restart the flow for that role
if (isset($_GET['role']) && ($_SESSION['fp_role'] ?? '') !== $role) {
    foreach (['fp_step','fp_id','fp_email','fp_identifier','fp_otp_tries'] as $k) {
        unset($_SESSION[$k]);
    }
    $_SESSION['fp_role'] = $role;
}

$step  = $_SESSION['fp_step'] ?? 'identify';
$error = '';
$info  = '';

// ════════════════════════════════════════════════════════
// POST handling
// ════════════════════════════════════════════════════════
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken();

    // ── Step 1: identify the account ──
    if ($step === 'identify') {
        $found = null;
        $identifier = '';

        if ($cfg['idBy'] === 'username') {
            $username = trim($_POST['username'] ?? '');
            $identifier = $username;
            if ($username !== '') {
                $q = db()->prepare(
                    "SELECT id, email FROM {$cfg['table']} WHERE username = ? LIMIT 1"
                );
                $q->execute([$username]);
                $found = $q->fetch();
            }
        } else { // resident: erf + occupant code
            $erf  = strtoupper(preg_replace('/[^A-Z0-9]/i', '', trim($_POST['erf_number'] ?? '')));
            $code = strtoupper(trim($_POST['occupant_code'] ?? 'A'));
            if (!preg_match('/^[A-Z]$/', $code)) $code = 'A';
            $identifier = $erf . $code;
            if ($erf !== '') {
                $q = db()->prepare(
                    "SELECT id, email FROM residents
                     WHERE UPPER(resident_erfno) = ? AND UPPER(occupant_code) = ?
                       AND status = 'active' LIMIT 1"
                );
                $q->execute([$erf, $code]);
                $found = $q->fetch();
            }
        }

        // Always advance to the OTP step with a generic message.
        // Only actually send a code if the account exists AND has an email.
        $_SESSION['fp_id']         = $found['id']  ?? 0;
        $_SESSION['fp_email']      = ($found && !empty($found['email'])) ? $found['email'] : '';
        $_SESSION['fp_identifier'] = $identifier;
        $_SESSION['fp_otp_tries']  = 0;

        $sendOk = false;

if ($found && !empty($found['email'])) {
    $sendOk = generateEmailOtp(
        (string)$found['email']
    );
}

/*
 * Preserve generic behaviour for unknown accounts,
 * but do not put a real account onto a dead OTP screen
 * when delivery failed.
 */
if ($found && !empty($found['email']) && !$sendOk) {

    error_log(
        'GEMB forgot-password OTP delivery failed'
    );

    $error =
        'Unable to send the verification code. ' .
        'Please wait briefly and try again.';

    /*
     * Stay on identify step.
     */
    $_SESSION['fp_step'] = 'identify';
    $step = 'identify';

} else {

    $_SESSION['fp_step'] = 'otp';

    header(
        'Location: forgot.php?role=' .
        urlencode($role)
    );

    exit;
}

    } // ── Step 2: verify the OTP ──
    elseif ($step === 'otp') {
        $otp   = preg_replace('/\D/', '', trim($_POST['otp'] ?? ''));
        $email = $_SESSION['fp_email'] ?? '';
        $tries = (int)($_SESSION['fp_otp_tries'] ?? 0) + 1;
        $_SESSION['fp_otp_tries'] = $tries;

        if ($tries > 5) {
            foreach (['fp_step','fp_id','fp_email','fp_identifier','fp_otp_tries'] as $k) {
                unset($_SESSION[$k]);
            }
            $_SESSION['fp_role'] = $role;
            setFlash('error', 'Too many attempts. Please start again.');
            header('Location: forgot.php?role=' . urlencode($role)); exit;
        }

        if (strlen($otp) !== 6) {
            $error = 'The code must be 6 digits.';
        } elseif ($email === '' || !verifyEmailOtp($email, $otp)) {
            $error = 'Invalid or expired code. Please check and try again.';
        } else {
            $_SESSION['fp_step'] = 'reset';
            header('Location: forgot.php?role=' . urlencode($role)); exit;
        }
    }

    // ── Step 3: set the new credential ──
    elseif ($step === 'reset') {
        $id = (int)($_SESSION['fp_id'] ?? 0);
        if (!$id) {
            $error = 'Session expired. Please start again.';
            $step  = 'identify';
            $_SESSION['fp_step'] = 'identify';
        } else {
            $new = trim($_POST['new_cred'] ?? '');
            $con = trim($_POST['confirm_cred'] ?? '');

            $valid = true;
            if ($cfg['credKind'] === 'pin') {
                if (!preg_match('/^\d{4}$/', $new)) {
                    $error = 'PIN must be exactly 4 digits.'; $valid = false;
                }
            } else {
                if (strlen($new) < 8) {
                    $error = 'Password must be at least 8 characters.'; $valid = false;
                }
            }
            if ($valid && $new !== $con) {
                $error = ($cfg['credKind'] === 'pin' ? 'PINs' : 'Passwords') . ' do not match.';
                $valid = false;
            }

            if ($valid) {
                $sql = "UPDATE {$cfg['table']} SET {$cfg['pwcol']} = ?, device_token = NULL"
                     . ($cfg['stamp'] ? ", password_changed_at = NOW()" : "")
                     . " WHERE id = ?";
                db()->prepare($sql)->execute([
                    password_hash($new, PASSWORD_BCRYPT),
                    $id,
                ]);

                // Clear any brute-force lock on this account
                $ident = $_SESSION['fp_identifier'] ?? '';
                if ($ident !== '') {
                    bfClearAttempts($role, $ident);
                }

                // Clean up the flow
                foreach (['fp_role','fp_step','fp_id','fp_email','fp_identifier','fp_otp_tries'] as $k) {
                    unset($_SESSION[$k]);
                }
                setFlash('success',
                    ($cfg['credKind'] === 'pin' ? 'PIN' : 'Password')
                    . ' updated. You can now log in.');
                header('Location: ' . $cfg['login']); exit;
            }
        }
    }
}

// ── Masked email for the OTP screen ──
$maskedEmail = '';
if ($step === 'otp' && !empty($_SESSION['fp_email'])) {
    $parts = explode('@', $_SESSION['fp_email']);
    $maskedEmail = substr($parts[0], 0, 2)
                 . str_repeat('*', max(2, strlen($parts[0]) - 2))
                 . '@' . ($parts[1] ?? '');
}

// ════════════════════════════════════════════════════════
// Render
// ════════════════════════════════════════════════════════
pageHeader('Forgot Password', $cfg['accent']);
?>
<div class="login-wrap">
  <div class="login-card">
    <div class="login-logo"><?= $cfg['icon'] ?></div>
    <h2>Reset Access</h2>
    <div class="subtitle"><?= htmlspecialchars($cfg['title']) ?> — GEMB Access Control</div>

    <?= getFlash() ?>
    <?php if ($error): ?>
      <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <?php if ($step === 'identify'): ?>
      <div class="alert alert-info" style="font-size:.88rem;">
        Enter your <?= $cfg['idBy'] === 'username' ? 'username' : 'erf number' ?>
        and we'll email a 6-digit code to the address on file.
      </div>
      <form method="POST" action="forgot.php?role=<?= urlencode($role) ?>">
        <?= csrfField() ?>
        <?php if ($cfg['idBy'] === 'username'): ?>
        <div class="form-group">
          <label>Username</label>
          <input type="text" name="username" required autofocus autocomplete="username">
        </div>
        <?php else: ?>
        <div class="form-group">
          <label>Erf Number</label>
          <input type="text" name="erf_number" required autofocus
                 style="text-transform:uppercase;text-align:center;letter-spacing:.08em;"
                 oninput="this.value=this.value.toUpperCase()"
                 placeholder="e.g. E15227" maxlength="10">
        </div>
        <div class="form-group">
          <label>Occupant Code (letter)</label>
          <input type="text" name="occupant_code" value="A" maxlength="1"
                 style="text-transform:uppercase;text-align:center;"
                 oninput="this.value=this.value.toUpperCase()"
                 pattern="[A-Za-z]" title="A single letter, e.g. A">
        </div>
        <?php endif; ?>
        <button type="submit" class="btn btn-primary btn-block" style="margin-top:8px;">
          Send Code
        </button>
      </form>

    <?php elseif ($step === 'otp'): ?>
      <div class="alert alert-info" style="font-size:.88rem;">
        📧 If an account with a registered email address exists, a
        <strong>6-digit code</strong> has been sent
        <?php if ($maskedEmail): ?>to <strong><?= htmlspecialchars($maskedEmail) ?></strong><?php endif; ?>.
        It is valid for 5 minutes.
      </div>
      <form method="POST" action="forgot.php?role=<?= urlencode($role) ?>">
        <?= csrfField() ?>
        <div class="form-group">
          <label>6-digit code</label>
          <input type="text" name="otp" required autofocus
                 style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;"
                 maxlength="6" pattern="\d{6}" inputmode="numeric"
                 placeholder="_ _ _ _ _ _">
        </div>
        <button type="submit" class="btn btn-primary btn-block">Verify Code</button>
      </form>

    <?php elseif ($step === 'reset'): ?>
      <div class="alert alert-success" style="font-size:.88rem;">
        ✅ Verified. Set your new <?= $cfg['credKind'] === 'pin' ? 'PIN' : 'password' ?>.
      </div>
      <form method="POST" action="forgot.php?role=<?= urlencode($role) ?>">
        <?= csrfField() ?>
        <?php if ($cfg['credKind'] === 'pin'): ?>
        <div class="form-group">
          <label>New 4-digit PIN</label>
          <input type="password" name="new_cred" required autofocus
                 style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;"
                 maxlength="4" pattern="\d{4}" inputmode="numeric" placeholder="••••">
        </div>
        <div class="form-group">
          <label>Confirm PIN</label>
          <input type="password" name="confirm_cred" required
                 style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;"
                 maxlength="4" pattern="\d{4}" inputmode="numeric" placeholder="••••">
        </div>
        <?php else: ?>
        <div class="form-group">
          <label>New Password (min 8 characters)</label>
          <input type="password" name="new_cred" required autofocus
                 autocomplete="new-password" minlength="8">
        </div>
        <div class="form-group">
          <label>Confirm Password</label>
          <input type="password" name="confirm_cred" required
                 autocomplete="new-password" minlength="8">
        </div>
        <?php endif; ?>
        <button type="submit" class="btn btn-primary btn-block">
          Save <?= $cfg['credKind'] === 'pin' ? 'PIN' : 'Password' ?>
        </button>
      </form>
    <?php endif; ?>

    <a href="<?= $cfg['login'] ?>"
       style="display:block;text-align:center;margin-top:14px;font-size:.85rem;color:var(--muted);">
      ← Back to login
    </a>
    <?php if ($step !== 'identify'): ?>
    <a href="forgot.php?role=<?= urlencode($role) ?>&cancel=1"
       style="display:block;text-align:center;margin-top:8px;font-size:.8rem;color:var(--muted);">
      Start over
    </a>
    <?php endif; ?>

    <div class="popia-notice">
      Identity is verified by a one-time code sent to your registered email,
      per POPIA §11 for estate security purposes.
    </div>
  </div>
</div>
<?php pageFooter(); ?>
