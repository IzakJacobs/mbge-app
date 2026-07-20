<?php
// ============================================================
// GEMB Access Control — admin.php
// admins:         id, username, email, phone, password
// guards:         id, username, name, phone, pin, gate
// security_users: id, username, name, phone, pin
// helpdesk:       resident_erfno, resident_name, subject,
//                 category, description, priority, status, response
// ============================================================
require_once __DIR__ . '/layout.php';
if (session_status() === PHP_SESSION_NONE) session_start();

$action = $_GET['action'] ?? 'login';

// ── LOGIN ─────────────────────────────────────────────────
if ($action === 'login') {

    // Already logged in
    if (!empty($_SESSION['admin_id'])) {
        header('Location: admin.php?action=menu'); exit;
    }

    /* Device token — persistent 10-year cookie */
    if (empty($_COOKIE['gemb_admin_device'])) {
        $tok = bin2hex(random_bytes(24));
        setcookie('gemb_admin_device', $tok,
                  time() + (10 * 365 * 24 * 60 * 60),
                  '/', '', true, true);
        $_COOKIE['gemb_admin_device'] = $tok;
    }
    $deviceToken = $_COOKIE['gemb_admin_device'];

    $step  = $_SESSION['admin_login_step'] ?? 'credentials';
    $error = '';

    if (isset($_GET['cancel'])) {
        session_unset(); session_destroy();
        header('Location: admin.php?action=login'); exit;
    }
    if (isset($_GET['err']) && $_GET['err'] === 'otp') {
        $error = 'Incorrect OTP. Session reset. Please try again.';
        $step  = 'credentials';
    }
    if (isset($_GET['err']) && $_GET['err'] === 'elsewhere') {
        $error = 'You have been signed out because this account was signed in from another device.';
        $step  = 'credentials';
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();

        /* ── Step 1: Username + Password ── */
        if ($step === 'credentials'
            && isset($_POST['username'], $_POST['password'])) {

            $user = trim($_POST['username'] ?? '');
            $pass = $_POST['password']       ?? '';

            /* Brute force check */
            $lockCheck = bfIsLocked('admin', $user);
            if ($lockCheck['locked']) {
                $error = bfLockoutMessage($lockCheck);
            } else {
                $stmt = db()->prepare(
                    "SELECT * FROM admins WHERE username = ? LIMIT 1"
                );
                $stmt->execute([$user]);
                $adm = $stmt->fetch();

                if (!$adm || !password_verify($pass, $adm['password'])) {
                    bfRecordFailure('admin', $user);
                    $remaining = bfAttemptsRemaining('admin', $user);
                    $error = 'Invalid credentials.'
                           . ($remaining <= 2
                               ? ' ' . bfWarningMessage($remaining)
                               : '');
                } else {
                    bfClearAttempts('admin', $user);

                    if (empty($adm['device_token'])) {
                        /* First login — register device */
                        db()->prepare(
                            "UPDATE admins SET device_token=? WHERE id=?"
                        )->execute([hashDeviceToken($deviceToken), $adm['id']]);
                        adminGrantAccess($adm); exit;
                    } elseif (hash_equals($adm['device_token'], hashDeviceToken($deviceToken))) {
                        adminGrantAccess($adm); exit;
                    } else {
                        /* New device — email OTP (mirrors resident flow) */
                        $adminEmail = trim($adm['email'] ?? '');
                        if ($adminEmail === '') {
                            $error = 'No email address is on file for this admin '
                                   . 'account, so a one-time PIN cannot be sent. '
                                   . 'Please ask another administrator to add your '
                                   . 'email address before logging in from a new device.';
                        } else {
                            $_SESSION['admin_login_step']    = 'otp';
                            $_SESSION['admin_pending_id']     = $adm['id'];
                            $_SESSION['admin_pending_email']  = $adminEmail;
                            require_once __DIR__ . '/twilio_helper.php';
                            generateEmailOtp($adminEmail);
                            header('Location: admin.php?action=login'); exit;
                        }
                    }
                }
            }
        }

        /* ── Step 2: OTP ── */
        elseif ($step === 'otp' && isset($_POST['otp'])) {
            $otp   = preg_replace('/\D/', '', trim($_POST['otp']));
            $email = $_SESSION['admin_pending_email'] ?? '';
            require_once __DIR__ . '/twilio_helper.php';

            if (strlen($otp) !== 6) {
                $error = 'OTP must be 6 digits.';
            } elseif (!verifyEmailOtp($email, $otp)) {
                session_unset(); session_destroy();
                header('Location: admin.php?action=login&err=otp'); exit;
            } else {
                $_SESSION['admin_login_step'] = 'reset';
                header('Location: admin.php?action=login'); exit;
            }
        }

        /* ── Step 3: New password + register device ── */
        elseif ($step === 'reset'
                && isset($_POST['new_password'], $_POST['confirm_password'])) {
            $newPass = trim($_POST['new_password']);
            $conPass = trim($_POST['confirm_password']);
            $pid     = (int)($_SESSION['admin_pending_id'] ?? 0);

            if (strlen($newPass) < 8) {
                $error = 'Password must be at least 8 characters.';
            } elseif ($newPass !== $conPass) {
                $error = 'Passwords do not match.';
            } elseif (!$pid) {
                session_unset(); session_destroy();
                header('Location: admin.php?action=login'); exit;
            } else {
                $cur = db()->prepare("SELECT password FROM admins WHERE id=? LIMIT 1");
                $cur->execute([$pid]);
                $cur = $cur->fetch();
                if ($cur && password_verify($newPass, $cur['password'])) {
                    $error = 'New password must be different from your current password.';
                } else {
                    db()->prepare(
                        "UPDATE admins SET password=?, device_token=?, password_changed_at=NOW() WHERE id=?"
                    )->execute([
                        password_hash($newPass, PASSWORD_BCRYPT),
                        hashDeviceToken($deviceToken), $pid
                    ]);
                    unset($_SESSION['admin_force_expired']);
                    $adm = db()->prepare(
                        "SELECT * FROM admins WHERE id=? LIMIT 1"
                    );
                    $adm->execute([$pid]);
                    adminGrantAccess($adm->fetch()); exit;
                }
            }
        }
    }

    /* (The OTP screen masks the email address inline — see below) */

    pageHeader('Admin Login', 'admin');
    ?>
    <div class="login-wrap">
      <div class="login-card">
        <div class="login-logo">⚙️</div>
        <h2>System Administrator</h2>
        <div class="subtitle">GEMB Access Control</div>

        <?php if ($error): ?>
          <div class="alert alert-danger">
            <?= $error /* may contain HTML from bfWarningMessage */ ?>
          </div>
        <?php endif; ?>

        <?php if ($step === 'credentials'): ?>
        <form method="POST" action="admin.php?action=login">
          <?= csrfField() ?>
          <div class="form-group">
            <label>Username</label>
            <input type="text" name="username" required
                   autocomplete="username">
          </div>
          <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" required
                   autocomplete="current-password">
          </div>
          <button type="submit" class="btn btn-primary btn-block"
                  style="margin-top:8px;">Login</button>
        </form>
        <a href="forgot.php?role=admin"
           style="display:block;text-align:center;margin-top:14px;
                  font-size:.85rem;color:var(--muted);">
          Forgot password?
        </a>

        <?php elseif ($step === 'otp'): ?>
        <div class="alert alert-info" style="font-size:.88rem;">
          📧 <strong>New device detected.</strong><br><br>
          <?php
          $pendingEmail = $_SESSION['admin_pending_email'] ?? '';
          if ($pendingEmail) {
              $parts  = explode('@', $pendingEmail);
              $masked = substr($parts[0], 0, 2)
                      . str_repeat('*', max(2, strlen($parts[0]) - 2))
                      . '@' . ($parts[1] ?? '');
              echo 'A <strong>6-digit OTP</strong> has been sent to <strong>'
                   . htmlspecialchars($masked) . '</strong>.';
          } else {
              echo 'No email address is on file for this account. '
                   . 'Please contact another administrator.';
          }
          ?><br>
          Enter the code below to verify your identity.
        </div>
        <form method="POST" action="admin.php?action=login">
          <?= csrfField() ?>
          <div class="form-group">
            <label>6-digit OTP</label>
            <input type="text" name="otp" required autofocus
                   style="font-size:1.6rem;letter-spacing:0.4em;
                          text-align:center;"
                   maxlength="6" pattern="\d{6}"
                   inputmode="numeric"
                   placeholder="_ _ _ _ _ _">
          </div>
          <button type="submit" class="btn btn-primary btn-block">
            Verify OTP
          </button>
        </form>
        <a href="admin.php?action=login&cancel=1"
           style="display:block;text-align:center;margin-top:14px;
                  font-size:.85rem;color:var(--muted);">
          ← Cancel and start over
        </a>

        <?php elseif ($step === 'reset'): ?>
        <div class="alert <?= !empty($_SESSION['admin_force_expired']) ? 'alert-warning' : 'alert-success' ?>" style="font-size:.88rem;">
          <?php if (!empty($_SESSION['admin_force_expired'])): ?>
            ⏰ Your password has expired under the 30-day policy.
            Please set a new one to continue.
          <?php else: ?>
            ✅ Identity verified.
            Please set a new password for this device.
          <?php endif; ?>
        </div>
        <form method="POST" action="admin.php?action=login">
          <?= csrfField() ?>
          <div class="form-group">
            <label>New Password (min 8 characters)</label>
            <input type="password" name="new_password" required
                   autofocus autocomplete="new-password" minlength="8">
          </div>
          <div class="form-group">
            <label>Confirm Password</label>
            <input type="password" name="confirm_password" required
                   autocomplete="new-password" minlength="8">
          </div>
          <button type="submit" class="btn btn-primary btn-block">
            Save Password &amp; Login
          </button>
        </form>
        <?php endif; ?>

        <div class="popia-notice">
          Admin access logged for security audit per POPIA §11.
        </div>
      </div>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end action

requireAdmin();

// ── Helper ────────────────────────────────────────────────
function adminGrantAccess(array $adm): void {
    // 30-day password rotation: NULL or older than 30 days = expired.
    $changed = $adm['password_changed_at'] ?? null;
    if (empty($changed) || strtotime($changed) < strtotime('-30 days')) {
        $_SESSION['admin_login_step']    = 'reset';
        $_SESSION['admin_pending_id']    = $adm['id'];
        $_SESSION['admin_force_expired'] = true;
        header('Location: admin.php?action=login'); exit;
    }
    session_regenerate_id(true);

    $sessionToken = bin2hex(random_bytes(32));
    db()->prepare("UPDATE admins SET active_session_token=? WHERE id=?")
        ->execute([$sessionToken, $adm['id']]);

    $_SESSION['admin_id']            = $adm['id'];
    $_SESSION['admin_name']          = $adm['username'];
    $_SESSION['admin_session_token'] = $sessionToken;
    $_SESSION['last_activity']       = time();
    unset($_SESSION['admin_login_step'],
          $_SESSION['admin_pending_id'],
          $_SESSION['admin_pending_email']);
    header('Location: admin.php?action=menu');
}

// ── MENU ──────────────────────────────────────────────────
if ($action === 'menu') {
    // Resident requests awaiting admin approval:
    // engine applications (to-let / tenant / pet / estate agent)
    // + visitor pet requests (Conduct Rule 1.4)
    try {
        $pendingApps = db()->query(
            "SELECT
               (SELECT COUNT(*) FROM applications
                WHERE app_type IN ('to_let','tenant','pet','estate_agent')
                  AND status IN ('pending_verification','induction_scheduled'))
             + (SELECT COUNT(*) FROM pets
                WHERE pet_type='visitor' AND status='pending')"
        )->fetchColumn();
    } catch (Exception $e) {
        $pendingApps = 0;   // engine tables not installed yet — button still works
    }

    pageHeader('Admin Menu', 'admin');
    renderHeader('⚙️ Admin — ' . ($_SESSION['admin_name'] ?? ''), 'logout.php');
    ?>
    <div class="container">
      <?= getFlash() ?>
      <div class="menu-grid">
        <a href="residents_admin.php?action=list" class="menu-btn"><span class="icon">🏠</span>Residents</a>
        
         <a href="admin_approvals.php" class="menu-btn">
          <span class="icon">📋</span>Approvals of Resident Requests
          <?php if ($pendingApps > 0): ?>
            <span class="badge badge-warning"><?= $pendingApps ?></span>
          <?php endif; ?>
        </a>
        
        <a href="admin.php?action=add_security"   class="menu-btn"><span class="icon">🛡️</span>Site Managers</a>
        <a href="admin.php?action=add_guard"       class="menu-btn"><span class="icon">👮</span>Guards</a>
        <a href="export.php?action=menu"           class="menu-btn"><span class="icon">📊</span>Export</a>
        <a href="admin.php?action=helpdesk"        class="menu-btn"><span class="icon">🔧</span>Helpdesk</a>
        <a href="document_portal.php"              class="menu-btn"><span class="icon">📤</span>Send Documents</a>
        <a href="document_archive.php"             class="menu-btn"><span class="icon">📄</span>Document Archive</a>
        <a href="admin.php?action=cleanup"         class="menu-btn"><span class="icon">🧹</span>Cleanup</a>
        <a href="admin.php?action=add_admin"       class="menu-btn"><span class="icon">👤</span>Admins</a>
        <a href="admin.php?action=change_pw"        class="menu-btn"><span class="icon">🔑</span>Change Password</a>
      </div>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end action



// ── CHANGE PASSWORD (logged-in admin) ─────────────────────
if ($action === 'change_pw') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $cur = $_POST['current_password']  ?? '';
        $new = trim($_POST['new_password'] ?? '');
        $con = trim($_POST['confirm_password'] ?? '');
        $aid = (int)($_SESSION['admin_id'] ?? 0);

        $row = db()->prepare("SELECT password FROM admins WHERE id=? LIMIT 1");
        $row->execute([$aid]);
        $row = $row->fetch();

        if (!$row || !password_verify($cur, $row['password'])) {
            setFlash('error', 'Current password is incorrect.');
            header('Location: admin.php?action=change_pw'); exit;
        }
        if (strlen($new) < 8) {
            setFlash('error', 'New password must be at least 8 characters.');
            header('Location: admin.php?action=change_pw'); exit;
        }
        if ($new !== $con) {
            setFlash('error', 'New passwords do not match.');
            header('Location: admin.php?action=change_pw'); exit;
        }
        if (password_verify($new, $row['password'])) {
            setFlash('error', 'New password must be different from your current password.');
            header('Location: admin.php?action=change_pw'); exit;
        }
        db()->prepare("UPDATE admins SET password=?, password_changed_at=NOW() WHERE id=?")
            ->execute([password_hash($new, PASSWORD_BCRYPT), $aid]);
        setFlash('success', 'Password updated.');
        header('Location: admin.php?action=menu'); exit;
    }

    pageHeader('Change Password', 'admin');
    renderHeader('🔑 Change Password', 'admin.php?action=menu');
    ?>
    <div class="container" style="max-width:420px;">
      <div class="card">
        <?= getFlash() ?>
        <form method="POST">
          <?= csrfField() ?>
          <div class="form-group">
            <label>Current Password</label>
            <input type="password" name="current_password" required
                   autocomplete="current-password">
          </div>
          <div class="form-group">
            <label>New Password (min 8 characters)</label>
            <input type="password" name="new_password" required
                   minlength="8" autocomplete="new-password">
          </div>
          <div class="form-group">
            <label>Confirm New Password</label>
            <input type="password" name="confirm_password" required
                   minlength="8" autocomplete="new-password">
          </div>
          <button type="submit" class="btn btn-primary btn-block">Update Password</button>
        </form>
        <div class="popia-notice">
          For security, administrators must change their password every 30 days.
        </div>
      </div>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end action

// ════════════════════════════════════════════════════════
// ADMINISTRATORS — list / add / edit / delete
// Layout mirrors residents_admin.php (search + add bar,
// summary line, table, separate add/edit pages).
//
// Lockout safety:
//   1. Cannot delete the account you are logged in with
//   2. Cannot delete the last remaining administrator
//   3. Cannot delete administrator id 1 (bootstrap account);
//      also enforced at the database level by a trigger
// Both are enforced server-side AND shown as a disabled
// Delete button with a tooltip (same idiom as the resident
// "primary with siblings" rule).
// ════════════════════════════════════════════════════════
if ($action === 'add_admin') {

    /* ── POST handlers (add / update / delete) ── */
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $act = $_POST['form_action'] ?? 'add';

        /* ── Add ── */
        if ($act === 'add') {
            $username = trim($_POST['username'] ?? '');
            $email    = trim($_POST['email']    ?? '');
            $phone    = trim($_POST['phone']    ?? '');
            $password = $_POST['password']      ?? '';

            if ($username === '' || $email === '') {
                setFlash('error', 'Username and email are required.');
                header('Location: admin.php?action=add_admin&new=1'); exit;
            }
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                setFlash('error', 'Please enter a valid email address.');
                header('Location: admin.php?action=add_admin&new=1'); exit;
            }
            if (strlen($password) < 8) {
                setFlash('error', 'Password must be at least 8 characters.');
                header('Location: admin.php?action=add_admin&new=1'); exit;
            }
            if ($phone !== '' && !preg_match('/^27\d{9}$/', $phone)) {
                setFlash('error', 'Phone must be in format 27XXXXXXXXX (11 digits).');
                header('Location: admin.php?action=add_admin&new=1'); exit;
            }
            try {
                db()->prepare(
                    "INSERT INTO admins (username, password, email, phone, password_changed_at) VALUES (?,?,?,?,NOW())"
                )->execute([
                    $username,
                    password_hash($password, PASSWORD_BCRYPT),
                    $email,
                    $phone,
                ]);
                setFlash('success', "Administrator {$username} added.");
                header('Location: admin.php?action=add_admin'); exit;
            } catch (Exception $e) {
                setFlash('error', 'Username already exists.');
                header('Location: admin.php?action=add_admin&new=1'); exit;
            }
        }

        /* ── Update ── */
        elseif ($act === 'update') {
            $uid      = (int)($_POST['uid'] ?? 0);
            $username = trim($_POST['username'] ?? '');
            $email    = trim($_POST['email']    ?? '');
            $phone    = trim($_POST['phone']    ?? '');
            $password = $_POST['password']      ?? '';

            if (!$uid || $username === '' || $email === '') {
                setFlash('error', 'Username and email are required.');
                header('Location: admin.php?action=add_admin&edit=' . $uid); exit;
            }
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                setFlash('error', 'Please enter a valid email address.');
                header('Location: admin.php?action=add_admin&edit=' . $uid); exit;
            }
            if ($phone !== '' && !preg_match('/^27\d{9}$/', $phone)) {
                setFlash('error', 'Phone must be in format 27XXXXXXXXX (11 digits).');
                header('Location: admin.php?action=add_admin&edit=' . $uid); exit;
            }
            try {
                if ($password !== '') {
                    if (strlen($password) < 8) {
                        setFlash('error', 'Password must be at least 8 characters.');
                        header('Location: admin.php?action=add_admin&edit=' . $uid); exit;
                    }
                    db()->prepare(
                        "UPDATE admins SET username=?, email=?, phone=?, password=?, password_changed_at=NOW() WHERE id=?"
                    )->execute([
                        $username, $email, $phone,
                        password_hash($password, PASSWORD_BCRYPT), $uid,
                    ]);
                } else {
                    db()->prepare(
                        "UPDATE admins SET username=?, email=?, phone=? WHERE id=?"
                    )->execute([$username, $email, $phone, $uid]);
                }
                setFlash('success', 'Administrator updated.');
            } catch (Exception $e) {
                setFlash('error', 'Username already exists.');
            }
            header('Location: admin.php?action=add_admin'); exit;
        }

        /* ── Delete (with lockout safety) ── */
        elseif ($act === 'delete') {
            $uid   = (int)($_POST['uid'] ?? 0);
            $self  = (int)($_SESSION['admin_id'] ?? 0);
            $count = (int)db()->query("SELECT COUNT(*) FROM admins")->fetchColumn();

            if ($uid === 1) {
                setFlash('error', 'Administrator id 1 is the protected bootstrap account and cannot be deleted.');
            } elseif ($uid === $self) {
                setFlash('error', 'You cannot delete the account you are logged in with.');
            } elseif ($count <= 1) {
                setFlash('error', 'Cannot delete the last remaining administrator.');
            } else {
                try {
                    db()->prepare("DELETE FROM admins WHERE id=?")->execute([$uid]);
                    setFlash('success', 'Administrator removed.');
                } catch (Exception $e) {
                    /* Backstop: a database trigger may protect this row */
                    setFlash('error', 'This administrator is protected and cannot be deleted.');
                }
            }
            header('Location: admin.php?action=add_admin'); exit;
        }

        header('Location: admin.php?action=add_admin'); exit;
    }

    // ──────────────────────────────────────────────────────
    // ADD PAGE  (?action=add_admin&new=1)
    // ──────────────────────────────────────────────────────
    if (isset($_GET['new'])) {
        pageHeader('Add Administrator', 'admin');
        renderHeader('➕ Add Administrator', 'admin.php?action=add_admin');
        ?>
        <div class="container" style="max-width:560px;">
          <div class="card">
            <?= getFlash() ?>
            <div class="alert alert-info" style="margin-bottom:16px;font-size:.88rem;">
              This creates a <strong>new administrator</strong> with full
              access to the management portal.<br><br>
              When logging in from a <strong>new device</strong>, a one-time
              PIN is sent to the administrator's <strong>email address</strong>,
              so a valid email is required.
            </div>
            <form method="POST" action="admin.php?action=add_admin">
              <?= csrfField() ?>
              <input type="hidden" name="form_action" value="add">
              <div class="form-group">
                <label>Username *</label>
                <input type="text" name="username" required autocomplete="off">
              </div>
              <div class="form-group">
                <label>Email * <small style="color:#888;">(OTP is sent here)</small></label>
                <input type="email" name="email" required placeholder="name@example.com">
              </div>
              <div class="form-group">
                <label>Phone (optional, 27XXXXXXXXX)</label>
                <input type="tel" name="phone" placeholder="e.g. 27821234567"
                       pattern="27[0-9]{9}" title="Format: 27 followed by 9 digits">
              </div>
              <div class="form-group">
                <label>Password * (min 8 characters)</label>
                <input type="password" name="password" required
                       autocomplete="new-password" minlength="8">
              </div>
              <button type="submit" class="btn btn-primary btn-block">
                Create Administrator
              </button>
            </form>
            <div class="popia-notice">
              Administrator data processed under POPIA §11 for access control purposes.
            </div>
          </div>
        </div>
        <?php pageFooter(); exit;
    }

    // ──────────────────────────────────────────────────────
    // EDIT PAGE  (?action=add_admin&edit=ID)
    // ──────────────────────────────────────────────────────
    if (isset($_GET['edit'])) {
        $uid   = (int)$_GET['edit'];
        $eStmt = db()->prepare(
            "SELECT id, username, email, phone FROM admins WHERE id=? LIMIT 1"
        );
        $eStmt->execute([$uid]);
        $adm = $eStmt->fetch();

        if (!$adm) {
            setFlash('error', 'Administrator not found.');
            header('Location: admin.php?action=add_admin'); exit;
        }

        pageHeader('Edit Administrator', 'admin');
        renderHeader('✏️ Edit — ' . htmlspecialchars($adm['username']),
                     'admin.php?action=add_admin');
        ?>
        <div class="container" style="max-width:560px;">
          <div class="card">
            <?= getFlash() ?>
            <div style="background:#f5f7fa;border-radius:8px;padding:10px 14px;
                        margin-bottom:16px;font-size:.88rem;">
              <strong>Username:</strong>
              <span style="font-family:monospace;font-size:1.05rem;font-weight:800;
                           color:var(--accent);">
                <?= htmlspecialchars($adm['username']) ?>
              </span>
            </div>
            <form method="POST" action="admin.php?action=add_admin">
              <?= csrfField() ?>
              <input type="hidden" name="form_action" value="update">
              <input type="hidden" name="uid" value="<?= $adm['id'] ?>">
              <div class="form-group">
                <label>Username *</label>
                <input type="text" name="username" required autocomplete="off"
                       value="<?= htmlspecialchars($adm['username']) ?>">
              </div>
              <div class="form-group">
                <label>Email * <small style="color:#888;">(OTP is sent here)</small></label>
                <input type="email" name="email" required
                       value="<?= htmlspecialchars($adm['email'] ?? '') ?>">
              </div>
              <div class="form-group">
                <label>Phone (optional, 27XXXXXXXXX)</label>
                <input type="tel" name="phone"
                       pattern="27[0-9]{9}" title="Format: 27 followed by 9 digits"
                       value="<?= htmlspecialchars($adm['phone'] ?? '') ?>">
              </div>
              <div class="form-group">
                <label>New Password (leave blank to keep current)</label>
                <input type="password" name="password"
                       autocomplete="new-password" minlength="8" placeholder="••••••••">
              </div>
              <button type="submit" class="btn btn-primary btn-block">
                Save Changes
              </button>
            </form>
            <div class="popia-notice">
              Administrator data processed under POPIA §11 for access control purposes.
            </div>
          </div>
        </div>
        <?php pageFooter(); exit;
    }

    // ──────────────────────────────────────────────────────
    // LIST PAGE  (default)
    // ──────────────────────────────────────────────────────
    $search = trim($_GET['q'] ?? '');
    if (strlen($search) === 1) $search = '';
    if ($search) {
        $stmt = db()->prepare(
            "SELECT id, username, email, phone FROM admins
             WHERE (username LIKE ? OR email LIKE ? OR phone LIKE ?)
             ORDER BY username"
        );
        $like = "%{$search}%";
        $stmt->execute([$like, $like, $like]);
    } else {
        $stmt = db()->query(
            "SELECT id, username, email, phone FROM admins ORDER BY username"
        );
    }
    $admins = $stmt->fetchAll();

    $self  = (int)($_SESSION['admin_id'] ?? 0);
    $count = (int)db()->query("SELECT COUNT(*) FROM admins")->fetchColumn();

    pageHeader('Administrators', 'admin');
    renderHeader('👤 Administrators', 'admin.php?action=menu');
    ?>
    <div class="container">
      <?= getFlash() ?>

      <!-- Search + Add -->
      <div class="card" style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;">
        <form method="GET" style="flex:1;display:flex;gap:8px;">
          <input type="hidden" name="action" value="add_admin">
          <input type="text" name="q" value="<?= htmlspecialchars($search) ?>"
                 placeholder="Search username, email or phone… (min 2 chars)"
                 minlength="2"
                 style="flex:1;padding:8px 12px;border:1px solid #dee2e6;border-radius:6px;">
          <button type="submit" class="btn btn-primary">Search</button>
          <?php if ($search): ?>
          <a href="admin.php?action=add_admin" class="btn btn-secondary">Clear</a>
          <?php endif; ?>
        </form>
        <a href="admin.php?action=add_admin&new=1" class="btn btn-success">+ Add Administrator</a>
      </div>

      <!-- Summary -->
      <div style="font-size:.85rem;color:#666;margin-bottom:12px;">
        <?= $count ?> administrator<?= $count === 1 ? '' : 's' ?> total
        <?php if ($search): ?>
          &nbsp;|&nbsp; Search: <strong><?= htmlspecialchars($search) ?></strong>
        <?php endif; ?>
      </div>

      <!-- Table -->
      <div class="card">
        <?php if (empty($admins)): ?>
          <p style="color:#666;">No administrators found.</p>
        <?php else: ?>
        <div class="table-wrap"><table>
          <tr><th>Username</th><th>Email</th><th>Phone</th><th>Actions</th></tr>
          <?php foreach ($admins as $a):
            $isSelf      = ((int)$a['id'] === $self);
            $isBootstrap = ((int)$a['id'] === 1);
            $isLast      = ($count <= 1);
            $blockDelete = $isSelf || $isLast || $isBootstrap;
            $blockReason = $isBootstrap
                ? 'Protected bootstrap administrator (id 1) — cannot be deleted'
                : ($isSelf
                    ? 'You cannot delete the account you are logged in with'
                    : 'Cannot delete the last remaining administrator');
          ?>
          <tr>
            <td>
              <span style="font-weight:700;">
                <?= htmlspecialchars($a['username']) ?>
              </span>
              <?php if ($isBootstrap): ?>
                <span class="badge badge-warning" style="margin-left:4px;">PROTECTED</span>
              <?php endif; ?>
              <?php if ($isSelf): ?>
                <span class="badge badge-info" style="margin-left:4px;">YOU</span>
              <?php endif; ?>
            </td>
            <td><?= htmlspecialchars($a['email'] ?? '') ?></td>
            <td><?= htmlspecialchars($a['phone'] ?? '') ?></td>
            <td>
              <div style="display:flex;gap:4px;flex-wrap:wrap;">
                <a href="admin.php?action=add_admin&edit=<?= $a['id'] ?>"
                   class="btn btn-primary btn-sm">Edit</a>
                <?php if ($blockDelete): ?>
                  <button class="btn btn-sm btn-danger"
                          style="opacity:.4;cursor:not-allowed;"
                          title="<?= htmlspecialchars($blockReason) ?>"
                          disabled>Delete</button>
                <?php else: ?>
                  <form method="POST" action="admin.php?action=add_admin"
                        style="display:inline"
                        onsubmit="return confirm('Permanently delete administrator <?= htmlspecialchars(addslashes($a['username'])) ?>?\n\nThis cannot be undone.')">
                    <?= csrfField() ?>
                    <input type="hidden" name="form_action" value="delete">
                    <input type="hidden" name="uid" value="<?= $a['id'] ?>">
                    <button class="btn btn-danger btn-sm">Delete</button>
                  </form>
                <?php endif; ?>
              </div>
            </td>
          </tr>
          <?php endforeach; ?>
        </table></div>
        <?php endif; ?>
      </div>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end action

// ── SITE MANAGERS (formerly Security Users) ───────────────
if ($action === 'add_security') {
    $users = db()->query("SELECT * FROM security_users ORDER BY name")->fetchAll();

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $act = $_POST['form_action'] ?? 'add';
        if ($act === 'add') {
            $pin   = trim($_POST['pin'] ?? '');
            $email = trim($_POST['email'] ?? '');
            if (!preg_match('/^\d{4,8}$/', $pin)) {
                setFlash('error', 'PIN must be 4–8 digits.');
                header('Location: admin.php?action=add_security'); exit;
            }
            if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                setFlash('error', 'A valid email address is required (used for password reset).');
                header('Location: admin.php?action=add_security'); exit;
            }
            try {
                db()->prepare(
                    "INSERT INTO security_users (username, name, phone, email, pin, password_changed_at) VALUES (?,?,?,?,?,NOW())"
                )->execute([
                    trim($_POST['username']),
                    trim($_POST['name']),
                    trim($_POST['phone'] ?? ''),
                    $email,
                    password_hash($pin, PASSWORD_BCRYPT),
                ]);
                setFlash('success', 'Site Manager added.');
            } catch (Exception $e) {
                setFlash('error', 'Username already exists.');
            }
        } elseif ($act === 'update') {
            $uid   = (int)($_POST['uid'] ?? 0);
            $name  = trim($_POST['name'] ?? '');
            $uname = trim($_POST['username'] ?? '');
            $phone = trim($_POST['phone'] ?? '');
            $email = trim($_POST['email'] ?? '');
            $pin   = trim($_POST['pin'] ?? '');

            if (!$uid || $name === '' || $uname === '') {
                setFlash('error', 'Name and username are required.');
                header('Location: admin.php?action=add_security&edit=' . $uid); exit;
            }
            if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                setFlash('error', 'A valid email address is required (used for password reset).');
                header('Location: admin.php?action=add_security&edit=' . $uid); exit;
            }
            if ($phone !== '' && !preg_match('/^27\d{9}$/', $phone)) {
                setFlash('error', 'Phone must be in format 27XXXXXXXXX (11 digits).');
                header('Location: admin.php?action=add_security&edit=' . $uid); exit;
            }
            try {
                if ($pin !== '') {
                    if (!preg_match('/^\d{4,8}$/', $pin)) {
                        setFlash('error', 'PIN must be 4–8 digits.');
                        header('Location: admin.php?action=add_security&edit=' . $uid); exit;
                    }
                    /* PIN change: reset device token + restart 30-day clock */
                    db()->prepare(
                        "UPDATE security_users SET name=?, username=?, phone=?, email=?,
                                pin=?, device_token=NULL, password_changed_at=NOW() WHERE id=?"
                    )->execute([
                        $name, $uname, $phone, $email,
                        password_hash($pin, PASSWORD_BCRYPT), $uid,
                    ]);
                    setFlash('success', 'Site Manager updated. PIN reset — they must log in again.');
                } else {
                    db()->prepare(
                        "UPDATE security_users SET name=?, username=?, phone=?, email=? WHERE id=?"
                    )->execute([$name, $uname, $phone, $email, $uid]);
                    setFlash('success', 'Site Manager updated.');
                }
            } catch (Exception $e) {
                setFlash('error', 'Username already exists.');
            }
        } elseif ($act === 'delete') {
            db()->prepare("DELETE FROM security_users WHERE id=?")
                ->execute([(int)$_POST['uid']]);
            setFlash('success', 'Site Manager removed.');
        }
        header('Location: admin.php?action=add_security'); exit;
    }

    /* Edit mode — preload one Site Manager */
    $editUser = null;
    if (isset($_GET['edit'])) {
        $eStmt = db()->prepare(
            "SELECT id, username, name, phone, email FROM security_users WHERE id=? LIMIT 1"
        );
        $eStmt->execute([(int)$_GET['edit']]);
        $editUser = $eStmt->fetch();
    }

    pageHeader('Site Managers', 'admin');
    renderHeader('🛡️ Site Managers', 'admin.php?action=menu');
    ?>
    <div class="container">
      <?= getFlash() ?>
      <div class="card">
        <div class="card-title">Site Managers</div>
        <?php if (empty($users)): ?>
          <p style="color:#666;">None added yet.</p>
        <?php else: ?>
        <div class="table-wrap"><table>
          <tr><th>Name</th><th>Username</th><th>Phone</th><th>Email</th><th>Action</th></tr>
          <?php foreach ($users as $u): ?>
          <tr>
            <td><?= htmlspecialchars($u['name']) ?></td>
            <td><?= htmlspecialchars($u['username']) ?></td>
            <td><?= htmlspecialchars($u['phone'] ?? '') ?></td>
            <td><?= htmlspecialchars($u['email'] ?? '') ?></td>
            <td>
              <a href="admin.php?action=add_security&edit=<?= $u['id'] ?>"
                 class="btn btn-primary btn-sm">Edit</a>
              <form method="POST" onsubmit="return confirm('Delete this Site Manager?')"
                    style="display:inline">
                <?= csrfField() ?>
                <input type="hidden" name="form_action" value="delete">
                <input type="hidden" name="uid" value="<?= $u['id'] ?>">
                <button class="btn btn-danger btn-sm">Delete</button>
              </form>
            </td>
          </tr>
          <?php endforeach; endif; ?>
        </table></div>
      </div>

      <div class="card">
        <div class="card-title"><?= $editUser ? 'Edit Site Manager' : 'Add Site Manager' ?></div>
        <form method="POST">
          <?= csrfField() ?>
          <input type="hidden" name="form_action" value="<?= $editUser ? 'update' : 'add' ?>">
          <?php if ($editUser): ?>
            <input type="hidden" name="uid" value="<?= $editUser['id'] ?>">
          <?php endif; ?>
          <div class="form-group"><label>Full Name</label>
            <input type="text" name="name" required
                   value="<?= htmlspecialchars($editUser['name'] ?? '') ?>">
          </div>
          <div class="form-group"><label>Username</label>
            <input type="text" name="username" required autocomplete="off"
                   value="<?= htmlspecialchars($editUser['username'] ?? '') ?>">
          </div>
          <div class="form-group"><label>Phone (27XXXXXXXXX)</label>
            <input type="tel" name="phone" placeholder="e.g. 27821234567"
                   pattern="27[0-9]{9}" title="Format: 27 followed by 9 digits"
                   value="<?= htmlspecialchars($editUser['phone'] ?? '') ?>">
          </div>
          <div class="form-group"><label>Email <small style="color:#888;">(for password reset)</small></label>
            <input type="email" name="email" required placeholder="name@example.com"
                   value="<?= htmlspecialchars($editUser['email'] ?? '') ?>">
          </div>
          <div class="form-group"><label><?= $editUser
                ? 'New PIN (leave blank to keep current)' : 'PIN (4–8 digits)' ?></label>
            <input type="password" name="pin" <?= $editUser ? '' : 'required' ?>
                   inputmode="numeric" maxlength="8" pattern="\d{4,8}"
                   placeholder="e.g. 1234"
                   style="font-size:1.4rem;letter-spacing:0.3em;text-align:center;">
            <small style="color:#888;">
              <?= $editUser
                  ? 'Changing the PIN resets their device — they must log in again.'
                  : 'Used to log in to the Site Manager portal.' ?>
            </small>
          </div>
          <button type="submit" class="btn btn-primary">
            <?= $editUser ? 'Save Changes' : 'Add Site Manager' ?>
          </button>
          <?php if ($editUser): ?>
            <a href="admin.php?action=add_security"
               style="margin-left:12px;font-size:.85rem;color:var(--muted);">Cancel</a>
          <?php endif; ?>
        </form>
        <div class="popia-notice">
          Staff data processed under POPIA §11 for access control purposes.
        </div>
      </div>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end action

// ── GUARDS ────────────────────────────────────────────────
if ($action === 'add_guard') {
    $guards = db()->query("SELECT * FROM guards ORDER BY name")->fetchAll();

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $act = $_POST['form_action'] ?? 'add';
        if ($act === 'add') {
            $pin = trim($_POST['pin'] ?? '');
            if (!preg_match('/^\d{4}$/', $pin)) {
                setFlash('error', 'PIN must be exactly 4 digits.');
                header('Location: admin.php?action=add_guard'); exit;
            }
            $phone = trim($_POST['phone'] ?? '');
            if ($phone && !preg_match('/^27\d{9}$/', $phone)) {
                setFlash('error', 'Phone must be in format 27XXXXXXXXX (11 digits).');
                header('Location: admin.php?action=add_guard'); exit;
            }
            try {
                db()->prepare(
                    "INSERT INTO guards (username, name, phone, pin, gate) VALUES (?,?,?,?,?)"
                )->execute([
                    trim($_POST['username']),
                    trim($_POST['name']),
                    $phone,
                    password_hash($pin, PASSWORD_BCRYPT),
                    $_POST['gate'] ?? 'SSgate',
                ]);
                setFlash('success', 'Guard added successfully.');
            } catch (Exception $e) {
                setFlash('error', 'Username already exists.');
            }
        } elseif ($act === 'delete') {
            db()->prepare("DELETE FROM guards WHERE id=?")
                ->execute([(int)$_POST['uid']]);
            setFlash('success', 'Guard removed.');
        }
        header('Location: admin.php?action=add_guard'); exit;
    }

    pageHeader('Guards', 'admin');
    renderHeader('👮 Manage Guards', 'admin.php?action=menu');
    ?>
    <div class="container">
      <?= getFlash() ?>
      <div class="card">
        <div class="card-title">Guards</div>
        <?php if (empty($guards)): ?>
          <p style="color:#666;">None added yet.</p>
        <?php else: ?>
        <div class="table-wrap"><table>
          <tr><th>Name</th><th>Username</th><th>Gate</th><th>Phone</th><th>Action</th></tr>
          <?php foreach ($guards as $g): ?>
          <tr>
            <td><?= htmlspecialchars($g['name']) ?></td>
            <td><?= htmlspecialchars($g['username']) ?></td>
            <td><span class="badge badge-info"><?= htmlspecialchars($g['gate'] ?? 'Any') ?></span></td>
            <td><?= htmlspecialchars($g['phone'] ?? '') ?></td>
            <td>
              <form method="POST" onsubmit="return confirm('Delete this guard?')"
                    style="display:inline">
                <?= csrfField() ?>
                <input type="hidden" name="form_action" value="delete">
                <input type="hidden" name="uid" value="<?= $g['id'] ?>">
                <button class="btn btn-danger btn-sm">Delete</button>
              </form>
            </td>
          </tr>
          <?php endforeach; endif; ?>
        </table></div>
      </div>

      <div class="card">
        <div class="card-title">Add Guard</div>
        <form method="POST">
          <?= csrfField() ?>
          <input type="hidden" name="form_action" value="add">
          <div class="form-group"><label>Full Name</label>
            <input type="text" name="name" required>
          </div>
          <div class="form-group"><label>Username</label>
            <input type="text" name="username" required autocomplete="off">
          </div>
          <div class="form-group"><label>Phone (27XXXXXXXXX)</label>
            <input type="tel" name="phone" placeholder="e.g. 27821234567"
                   pattern="27[0-9]{9}" title="Format: 27 followed by 9 digits">
          </div>
          <div class="form-group"><label>4-digit PIN</label>
            <input type="password" name="pin" required
                   inputmode="numeric" maxlength="4" pattern="\d{4}"
                   placeholder="e.g. 1234"
                   style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;">
            <small style="color:#888;">Guard logs in with username + this 4-digit PIN.</small>
          </div>
          <div class="form-group"><label>Gate Assignment</label>
            <select name="gate">
              <option value="SSgate">SSgate — Schoeman Street</option>
              <option value="CSgate">CSgate — Church Street</option>
              <option value="entry">Any Gate</option>
            </select>
          </div>
          <button type="submit" class="btn btn-primary">Add Guard</button>
        </form>
        <div class="popia-notice">
          Staff data processed under POPIA §11 for access control purposes.
        </div>
      </div>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end action

// ── HELPDESK ──────────────────────────────────────────────
if ($action === 'helpdesk') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $validStatuses = ['open', 'in_progress', 'resolved', 'closed'];
        $status = in_array($_POST['status'] ?? '', $validStatuses, true)
                  ? $_POST['status'] : 'open';
        db()->prepare("UPDATE helpdesk SET response=?, status=? WHERE id=?")
          ->execute([
              trim($_POST['response']),
              $status,
              (int)$_POST['ticket_id'],
          ]);
        setFlash('success', 'Ticket updated.');
        header('Location: admin.php?action=helpdesk'); exit;
    }
    $tickets = db()->query("
        SELECT * FROM helpdesk
        ORDER BY FIELD(status,'open','in_progress','resolved','closed'),
                 FIELD(priority,'urgent','high','normal','low'),
                 created_at DESC
    ")->fetchAll();
    pageHeader('Helpdesk', 'admin');
    renderHeader('🔧 Helpdesk Tickets', 'admin.php?action=menu');
    ?>
    <div class="container">
      <?= getFlash() ?>
      <?php if (empty($tickets)): ?>
        <div class="card"><p style="color:#666;">No tickets yet.</p></div>
      <?php endif; ?>
      <?php foreach ($tickets as $t):
        $borderColor = $t['status'] === 'open'
            ? '#ffc107'
            : (in_array($t['status'], ['resolved','closed']) ? '#28a745' : '#17a2b8');
      ?>
      <div class="card" style="border-left:4px solid <?= $borderColor ?>">
        <div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px;margin-bottom:6px;">
          <div>
            <strong><?= htmlspecialchars($t['subject']) ?></strong>
            <span style="color:#666;font-size:.82rem;margin-left:6px;">
              <?= htmlspecialchars($t['category']) ?>
            </span>
            <div style="font-size:.8rem;color:#999;">
              Erf <?= $t['resident_erfno'] ?> — <?= htmlspecialchars($t['resident_name']) ?>
            </div>
          </div>
          <div style="display:flex;gap:6px;align-items:center;">
            <span class="badge badge-<?= $t['priority']==='urgent'?'danger':($t['priority']==='high'?'warning':'info') ?>">
              <?= $t['priority'] ?>
            </span>
            <span class="badge badge-<?= in_array($t['status'],['resolved','closed'])?'success':($t['status']==='open'?'warning':'info') ?>">
              <?= $t['status'] ?>
            </span>
          </div>
        </div>
        <div style="font-size:.85rem;margin-bottom:10px;">
          <?= htmlspecialchars($t['description']) ?>
        </div>
        <form method="POST" style="display:flex;gap:8px;flex-wrap:wrap;">
          <?= csrfField() ?>
          <input type="hidden" name="ticket_id" value="<?= $t['id'] ?>">
          <input type="text" name="response"
                 value="<?= htmlspecialchars($t['response'] ?? '') ?>"
                 placeholder="Response to resident…"
                 style="flex:1;padding:6px 10px;border:1px solid #dee2e6;
                        border-radius:6px;font-size:.88rem;">
          <select name="status"
                  style="padding:6px;border:1px solid #dee2e6;border-radius:6px;">
            <option value="open"        <?= $t['status']==='open'        ?'selected':'' ?>>Open</option>
            <option value="in_progress" <?= $t['status']==='in_progress' ?'selected':'' ?>>In Progress</option>
            <option value="resolved"    <?= $t['status']==='resolved'    ?'selected':'' ?>>Resolved</option>
            <option value="closed"      <?= $t['status']==='closed'      ?'selected':'' ?>>Closed</option>
          </select>
          <button type="submit" class="btn btn-primary btn-sm">Update</button>
        </form>
      </div>
      <?php endforeach; ?>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end action

// ── CLEANUP ───────────────────────────────────────────────
if ($action === 'cleanup') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $days = (int)($_POST['days'] ?? 90);
        db()->prepare("DELETE FROM visitors WHERE visit_date < DATE_SUB(CURDATE(), INTERVAL ? DAY)")
            ->execute([$days]);
        db()->prepare("DELETE FROM service_providers WHERE end_date < DATE_SUB(CURDATE(), INTERVAL ? DAY)")
            ->execute([$days]);
        db()->prepare("DELETE FROM access_log WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)")
            ->execute([$days]);
        db()->prepare("DELETE FROM notifications WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)")
            ->execute([$days]);
        setFlash('success', "Cleanup complete. Records older than {$days} days removed.");
        header('Location: admin.php?action=cleanup'); exit;
    }
    pageHeader('Cleanup', 'admin');
    renderHeader('🧹 Data Cleanup', 'admin.php?action=menu');
    ?>
    <div class="container" style="max-width:480px;">
      <?= getFlash() ?>
      <div class="card">
        <div class="card-title">POPIA Data Purge</div>
        <p style="font-size:.88rem;color:#666;margin-bottom:16px;">
          Removes expired records older than selected days. This action is irreversible.
        </p>
        <form method="POST" onsubmit="return confirm('Permanently delete old records? This cannot be undone.')">
          <?= csrfField() ?>
          <div class="form-group">
            <label>Delete records older than (days)</label>
            <input type="number" name="days" value="90" min="30" max="365">
          </div>
          <button type="submit" class="btn btn-danger btn-block">Run Cleanup</button>
        </form>
      </div>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end action

// Fallback
header('Location: admin.php?action=menu'); exit;