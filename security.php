<?php
// ============================================================
// GEMB Access Control — security.php
// Actions: login | menu | approvals | sp_add | guards | logs | qr | reset | helpdesk
// ============================================================
require_once __DIR__ . '/layout.php';
if (session_status() === PHP_SESSION_NONE) session_start();

$action = $_GET['action'] ?? 'login';

if ($action === 'login' && !empty($_SESSION['security_id'])) {
    header('Location: security.php?action=menu'); exit;
}

// ════════════════════════════════════════════════════════
// LOGIN
// ════════════════════════════════════════════════════════
if ($action === 'login') {

    if (empty($_COOKIE['gemb_security_device'])) {
        $tok = bin2hex(random_bytes(24));
        setcookie('gemb_security_device', $tok, time() + (10 * 365 * 24 * 60 * 60), '/', '', true, true);
        $_COOKIE['gemb_security_device'] = $tok;
    }
    $deviceToken = $_COOKIE['gemb_security_device'];

    $step  = $_SESSION['sec_login_step'] ?? 'credentials';
    $error = '';

    if (isset($_GET['cancel'])) {
        session_unset(); session_destroy();
        header('Location: security.php?action=login'); exit;
    }
    if (isset($_GET['err']) && $_GET['err'] === 'otp') {
        $error = 'Incorrect OTP. For security your session has been reset. Please try again.';
        $step  = 'credentials';
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {

        if ($step === 'credentials' && isset($_POST['username'], $_POST['password'])) {
            $user = trim($_POST['username'] ?? '');
            $pass = $_POST['password']       ?? '';

            $lockCheck = bfIsLocked('security', $user);
            if ($lockCheck['locked']) {
                $error = bfLockoutMessage($lockCheck);
            } else {
                $stmt = db()->prepare(
                    "SELECT id, name, username, pin, phone, device_token, password_changed_at
                     FROM security_users WHERE username = ? LIMIT 1"
                );
                $stmt->execute([$user]);
                $sec = $stmt->fetch();

                if (!$sec || !password_verify($pass, $sec['pin'])) {
                    bfRecordFailure('security', $user);
                    $remaining = bfAttemptsRemaining('security', $user);
                    $error = 'Invalid username or PIN.'
                           . ($remaining <= 2 ? ' ' . bfWarningMessage($remaining) : '');
                } else {
                    bfClearAttempts('security', $user);
                    if (empty($sec['device_token'])) {
                        db()->prepare("UPDATE security_users SET device_token=? WHERE id=?")
                            ->execute([hashDeviceToken($deviceToken), $sec['id']]);
                        securityGrantAccess($sec); exit;
                    } elseif (hash_equals($sec['device_token'], hashDeviceToken($deviceToken))) {
                        securityGrantAccess($sec); exit;
                    } else {
                        $_SESSION['sec_login_step']    = 'otp';
                        $_SESSION['sec_pending_id']    = $sec['id'];
                        $_SESSION['sec_pending_phone'] = $sec['phone'] ?? '';
                        header('Location: security.php?action=login'); exit;
                    }
                }
            }
        }

        elseif ($step === 'otp' && isset($_POST['otp'])) {
            $otp      = preg_replace('/\D/', '', trim($_POST['otp']));
            $phone    = $_SESSION['sec_pending_phone'] ?? '';
            $expected = substr(preg_replace('/\D/', '', $phone), -6);

            if (strlen($otp) !== 6) {
                $error = 'OTP must be 6 digits.';
            } elseif ($otp !== $expected) {
                session_unset(); session_destroy();
                header('Location: security.php?action=login&err=otp'); exit;
            } else {
                $_SESSION['sec_login_step'] = 'reset';
                header('Location: security.php?action=login'); exit;
            }
        }

        elseif ($step === 'reset' && isset($_POST['new_password'], $_POST['confirm_password'])) {
            $newPass = trim($_POST['new_password']);
            $conPass = trim($_POST['confirm_password']);
            $pid     = (int)($_SESSION['sec_pending_id'] ?? 0);

            if (strlen($newPass) < 8) {
                $error = 'Password must be at least 8 characters.';
            } elseif ($newPass !== $conPass) {
                $error = 'Passwords do not match.';
            } elseif (!$pid) {
                session_unset(); session_destroy();
                header('Location: security.php?action=login'); exit;
            } else {
                $cur = db()->prepare("SELECT pin FROM security_users WHERE id=? LIMIT 1");
                $cur->execute([$pid]);
                $cur = $cur->fetch();
                if ($cur && password_verify($newPass, $cur['pin'])) {
                    $error = 'New password must be different from your current password.';
                } else {
                    db()->prepare(
                        "UPDATE security_users SET pin=?, device_token=?, password_changed_at=NOW() WHERE id=?"
                    )->execute([password_hash($newPass, PASSWORD_BCRYPT), hashDeviceToken($deviceToken), $pid]);
                    unset($_SESSION['sec_force_expired']);
                    $sec = db()->prepare(
                        "SELECT id, name, username, pin, phone, device_token, password_changed_at
                         FROM security_users WHERE id=? LIMIT 1"
                    );
                    $sec->execute([$pid]);
                    securityGrantAccess($sec->fetch());
                    exit;
                }
            }
        }
    }

    $maskedPhone = '';
    if ($step === 'otp' && !empty($_SESSION['sec_pending_phone'])) {
        $p = preg_replace('/\D/', '', $_SESSION['sec_pending_phone']);
        $maskedPhone = substr($p, 0, 4) . '***' . substr($p, -3);
    }

    pageHeader('Security Login', 'security');
    ?>
    <div class="login-wrap">
      <div class="login-card">
        <div class="login-logo">🛡️</div>
        <h2>Security Officer</h2>
        <div class="subtitle">GEMB Access Control</div>

        <?php if ($error): ?>
          <div class="alert alert-danger"><?= $error /* may contain HTML from bfWarningMessage */ ?></div>
        <?php endif; ?>

        <?php if ($step === 'credentials'): ?>
        <form method="POST" action="security.php?action=login">
          <?= csrfField() ?>
          <div class="form-group">
            <label>Username</label>
            <input type="text" name="username" required autocomplete="username">
          </div>
          <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" required autocomplete="current-password">
          </div>
          <button type="submit" class="btn btn-primary btn-block" style="margin-top:8px;">Login</button>
        </form>
        <a href="forgot.php?role=security"
           style="display:block;text-align:center;margin-top:14px;font-size:.85rem;color:var(--muted);">
          Forgot password?
        </a>

        <?php elseif ($step === 'otp'): ?>
        <div class="alert alert-info" style="font-size:.88rem;">
          🔐 <strong>New device detected.</strong><br><br>
          Enter the <strong>last 6 digits</strong> of your registered phone number.<br>
          Number on file: <strong><?= htmlspecialchars($maskedPhone) ?></strong>
        </div>
        <form method="POST" action="security.php?action=login">
          <?= csrfField() ?>
          <div class="form-group">
            <label>6-digit OTP</label>
            <input type="text" name="otp" required autofocus
                   style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;"
                   maxlength="6" pattern="\d{6}" inputmode="numeric"
                   placeholder="_ _ _ _ _ _">
          </div>
          <button type="submit" class="btn btn-primary btn-block">Verify OTP</button>
        </form>
        <a href="security.php?action=login&cancel=1"
           style="display:block;text-align:center;margin-top:14px;font-size:.85rem;color:var(--muted);">
          ← Cancel and start over
        </a>

        <?php elseif ($step === 'reset'): ?>
        <div class="alert <?= !empty($_SESSION['sec_force_expired']) ? 'alert-warning' : 'alert-success' ?>" style="font-size:.88rem;">
          <?php if (!empty($_SESSION['sec_force_expired'])): ?>
            ⏰ Your password has expired under the 30-day policy. Please set a new one to continue.
          <?php else: ?>
            ✅ Identity verified. Please set a new password for this device.
          <?php endif; ?>
        </div>
        <form method="POST" action="security.php?action=login">
          <?= csrfField() ?>
          <div class="form-group">
            <label>New Password (min 8 characters)</label>
            <input type="password" name="new_password" required autofocus
                   autocomplete="new-password" minlength="8">
          </div>
          <div class="form-group">
            <label>Confirm Password</label>
            <input type="password" name="confirm_password" required
                   autocomplete="new-password" minlength="8">
          </div>
          <button type="submit" class="btn btn-primary btn-block">Save Password &amp; Login</button>
        </form>
        <?php endif; ?>

        <div class="popia-notice">Security access logged for audit per POPIA §11.</div>
      </div>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end login

requireSecurity();

// ════════════════════════════════════════════════════════
// MENU
// ── Change 1: badge counts only pending approvals that
//    need security action (not already approved/expired)
// ── Change 3: Helpdesk icon added
// ── Change 4: Applications button added (gemB Application
//    Engine — verification of contractor/to-let/tenant/pet
//    applications by the site manager)
// ════════════════════════════════════════════════════════
if ($action === 'menu') {
    // Count SP records genuinely awaiting security approval:
    // status = 'pending' OR (approved = 'false'/''/NULL AND not expired)
    // Excludes: already approved, expired, invited-but-not-yet-presented
    try {
        $pending = db()->query(
            "SELECT COUNT(*) FROM service_providers
             WHERE (approved = 'false' OR approved = '' OR approved IS NULL)
               AND expired = 0
               AND end_date >= CURDATE()
               AND (status = 'pending' OR status IS NULL OR status = '')"
        )->fetchColumn();
    } catch (Exception $e) {
        $pending = db()->query(
            "SELECT COUNT(*) FROM service_providers
             WHERE (approved = 'false' OR approved IS NULL)
               AND expired = 0"
        )->fetchColumn();
    }

    // Open helpdesk tickets
    try {
        $openTickets = db()->query(
            "SELECT COUNT(*) FROM helpdesk
             WHERE status IN ('open','in_progress')"
        )->fetchColumn();
    } catch (Exception $e) {
        $openTickets = 0;
    }

    // Applications awaiting site manager action (Application Engine)
    try {
        $pendingApps = db()->query(
            "SELECT COUNT(*) FROM applications
             WHERE status IN ('pending_verification','induction_scheduled')"
        )->fetchColumn();
    } catch (Exception $e) {
        $pendingApps = 0;   // engine tables not installed yet — button still works
    }

    pageHeader('Security Menu', 'security');
    renderHeader('🛡️ Security — ' . ($_SESSION['security_name'] ?? ''), 'logout.php');
    ?>
    <div class="container">
      <?= getFlash() ?>
      <div class="menu-grid">
        <a href="security.php?action=approvals" class="menu-btn">
          <span class="icon">✅</span>SP Approvals
          <?php if ($pending > 0): ?>
            <span class="badge badge-warning"><?= $pending ?></span>
          <?php endif; ?>
        </a>
        <a href="application_admin.php" class="menu-btn">
          <span class="icon">📋</span>Applications
          <?php if ($pendingApps > 0): ?>
            <span class="badge badge-warning"><?= $pendingApps ?></span>
          <?php endif; ?>
        </a>
        <a href="security.php?action=sp_add"        class="menu-btn"><span class="icon">➕</span>Invite Resident SP</a>
        <a href="security.php?action=estate_sp_add" class="menu-btn"><span class="icon">🏗️</span>Estate SP</a>
        <a href="security.php?action=guards"        class="menu-btn"><span class="icon">👮</span>Manage Guards</a>
        <a href="security.php?action=logs"          class="menu-btn"><span class="icon">📋</span>Access Logs</a>
        <a href="security.php?action=qr"            class="menu-btn"><span class="icon">🔍</span>QR Lookup</a>
        <a href="security.php?action=helpdesk"      class="menu-btn">
          <span class="icon">🔧</span>Helpdesk
          <?php if ($openTickets > 0): ?>
            <span class="badge badge-warning"><?= $openTickets ?></span>
          <?php endif; ?>
        </a>
        <a href="document_archive.php"               class="menu-btn"><span class="icon">📄</span>Estate Documents</a>
        <a href="security.php?action=gate_override" class="menu-btn"><span class="icon">🚨</span>Remote Gate Open</a>
        <a href="security.php?action=reset"         class="menu-btn"><span class="icon">🔑</span>Change Password</a>
      </div>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end menu

// ════════════════════════════════════════════════════════
// HELPDESK — view and respond to tickets
// ════════════════════════════════════════════════════════
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
        header('Location: security.php?action=helpdesk'); exit;
    }

    // Whitelist $filterStatus — only known values accepted
    $filterStatus = $_GET['status'] ?? 'open';
    if (!in_array($filterStatus, ['open','in_progress','resolved','closed','all'], true)) {
        $filterStatus = 'open';
    }
    if ($filterStatus === 'all') {
        $tickets = db()->query("
            SELECT * FROM helpdesk
            ORDER BY FIELD(status,'open','in_progress','resolved','closed'),
                     FIELD(priority,'urgent','high','normal','low'),
                     created_at ASC
        ")->fetchAll();
    } else {
        $stmt = db()->prepare("
            SELECT * FROM helpdesk
            WHERE status = ?
            ORDER BY FIELD(priority,'urgent','high','normal','low'),
                     created_at ASC
        ");
        $stmt->execute([$filterStatus === 'in_progress' ? 'in_progress' : $filterStatus]);
        $tickets = $stmt->fetchAll();
    }

    pageHeader('Helpdesk', 'security');
    renderHeader('🔧 Helpdesk Tickets', 'security.php?action=menu');
    ?>
    <div class="container">
      <?= getFlash() ?>

      <!-- Filter tabs -->
      <div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;">
        <?php foreach (['open'=>'⏳ Open','in_progress'=>'🔄 In Progress','resolved'=>'✅ Resolved','closed'=>'🗄️ Closed','all'=>'📋 All'] as $s => $label): ?>
        <a href="security.php?action=helpdesk&status=<?= $s ?>"
           class="btn btn-sm <?= $filterStatus===$s ? 'btn-primary' : 'btn-secondary' ?>">
          <?= $label ?>
        </a>
        <?php endforeach; ?>
      </div>

      <?php if (empty($tickets)): ?>
        <div class="card"><p style="color:#666;">No tickets in this category.</p></div>
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
            <span style="color:#666;font-size:.82rem;margin-left:6px;"><?= htmlspecialchars($t['category']) ?></span>
            <div style="font-size:.8rem;color:#999;">
              Erf <?= $t['resident_erfno'] ?> — <?= htmlspecialchars($t['resident_name']) ?>
              &nbsp;|&nbsp; <?= date('d M Y H:i', strtotime($t['created_at'])) ?>
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
        <div style="font-size:.85rem;margin-bottom:10px;"><?= htmlspecialchars($t['description']) ?></div>
        <form method="POST" style="display:flex;gap:8px;flex-wrap:wrap;">
          <?= csrfField() ?>
          <input type="hidden" name="ticket_id" value="<?= $t['id'] ?>">
          <input type="text" name="response"
                 value="<?= htmlspecialchars($t['response'] ?? '') ?>"
                 placeholder="Response to resident…"
                 style="flex:1;padding:6px 10px;border:1px solid #dee2e6;border-radius:6px;font-size:.88rem;">
          <select name="status" style="padding:6px;border:1px solid #dee2e6;border-radius:6px;">
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
<?php } // end helpdesk

// ── GUARDS ────────────────────────────────────────────────
if ($action === 'guards') {

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $act = $_POST['form_action'] ?? '';

        // ── ADD ───────────────────────────────────────────
        if ($act === 'add') {
            $pin   = trim($_POST['pin']   ?? '');
            $phone = trim($_POST['phone'] ?? '');

            if (!preg_match('/^\d{4}$/', $pin)) {
                setFlash('error', 'PIN must be exactly 4 digits.');
                header('Location: security.php?action=guards'); exit;
            }
            if ($phone && !preg_match('/^27\d{9}$/', $phone)) {
                setFlash('error', 'Phone must be in format 27XXXXXXXXX (e.g. 27821234567).');
                header('Location: security.php?action=guards'); exit;
            }
            try {
                db()->prepare(
                    "INSERT INTO guards (username, name, phone, pin, gate) VALUES (?,?,?,?,?)"
                )->execute([
                    trim($_POST['username']),
                    trim($_POST['name']),
                    $phone ?: null,
                    password_hash($pin, PASSWORD_BCRYPT),
                    $_POST['gate'] ?? 'SSgate',
                ]);
                setFlash('success', 'Guard added successfully.');
            } catch (Exception $e) {
                setFlash('error', 'Username already exists.');
            }

        // ── UPDATE ────────────────────────────────────────
        } elseif ($act === 'update') {
            $uid   = (int)$_POST['uid'];
            $phone = trim($_POST['phone'] ?? '');
            $pin   = trim($_POST['pin']   ?? ''); // optional — blank = no change

            if ($phone && !preg_match('/^27\d{9}$/', $phone)) {
                setFlash('error', 'Phone must be in format 27XXXXXXXXX.');
                header('Location: security.php?action=guards&edit=' . $uid); exit;
            }
            if ($pin !== '' && !preg_match('/^\d{4}$/', $pin)) {
                setFlash('error', 'PIN must be exactly 4 digits.');
                header('Location: security.php?action=guards&edit=' . $uid); exit;
            }

            if ($pin !== '') {
                // Update name, phone, gate AND reset PIN + clear device token
                db()->prepare(
                    "UPDATE guards SET name=?, phone=?, gate=?, pin=?, device_token=NULL WHERE id=?"
                )->execute([
                    trim($_POST['name']),
                    $phone ?: null,
                    $_POST['gate'] ?? 'SSgate',
                    password_hash($pin, PASSWORD_BCRYPT),
                    $uid,
                ]);
                setFlash('success', 'Guard updated and PIN reset. Device re-registration required on next login.');
            } else {
                // Update name, phone, gate only — PIN unchanged
                db()->prepare(
                    "UPDATE guards SET name=?, phone=?, gate=? WHERE id=?"
                )->execute([
                    trim($_POST['name']),
                    $phone ?: null,
                    $_POST['gate'] ?? 'SSgate',
                    $uid,
                ]);
                setFlash('success', 'Guard details updated.');
            }

        // ── DELETE ────────────────────────────────────────
        } elseif ($act === 'delete') {
            db()->prepare("DELETE FROM guards WHERE id=?")->execute([(int)$_POST['uid']]);
            setFlash('success', 'Guard removed.');
        }

        header('Location: security.php?action=guards'); exit;
    }

    $guards   = db()->query("SELECT * FROM guards ORDER BY name")->fetchAll();
    $editId   = filter_var($_GET['edit'] ?? 0, FILTER_VALIDATE_INT);
    $editGuard = null;
    if ($editId) {
        $s = db()->prepare("SELECT * FROM guards WHERE id=? LIMIT 1");
        $s->execute([$editId]);
        $editGuard = $s->fetch();
    }

    pageHeader('Guards', 'security');
    renderHeader('👮 Manage Guards', 'security.php?action=menu');
    ?>
    <div class="container">
      <?= getFlash() ?>

      <!-- ── Guard List ─────────────────────────────────── -->
      <div class="card">
        <div class="card-title">Active Guards</div>
        <?php if (empty($guards)): ?>
          <p style="color:#666;">No guards added yet.</p>
        <?php else: ?>
        <div class="table-wrap"><table>
          <tr>
            <th>Name</th><th>Username</th><th>Gate</th>
            <th>Phone</th><th>Device</th><th>Actions</th>
          </tr>
          <?php foreach ($guards as $g): ?>
          <tr style="<?= $editId===$g['id'] ? 'background:#fffde7;' : '' ?>">
            <td><?= htmlspecialchars($g['name']) ?></td>
            <td style="font-family:monospace;"><?= htmlspecialchars($g['username']) ?></td>
            <td><span class="badge badge-info"><?= htmlspecialchars($g['gate'] ?? 'Any') ?></span></td>
            <td><?= htmlspecialchars($g['phone'] ?? '—') ?></td>
            <td>
              <?php if ($g['device_token']): ?>
                <span class="badge badge-success">Registered</span>
              <?php else: ?>
                <span class="badge badge-muted">None</span>
              <?php endif; ?>
            </td>
            <td style="white-space:nowrap;">
              <a href="security.php?action=guards&edit=<?= $g['id'] ?>"
                 class="btn btn-primary btn-sm">Edit</a>
              <form method="POST" onsubmit="return confirm('Remove <?= htmlspecialchars(addslashes($g['name'])) ?>?')" style="display:inline">
                <?= csrfField() ?>
                <input type="hidden" name="form_action" value="delete">
                <input type="hidden" name="uid" value="<?= $g['id'] ?>">
                <button class="btn btn-danger btn-sm">Remove</button>
              </form>
            </td>
          </tr>
          <?php endforeach; ?>
        </table></div>
        <?php endif; ?>
      </div>

      <!-- ── Edit Guard ─────────────────────────────────── -->
      <?php if ($editGuard): ?>
      <div class="card" style="border-left:4px solid var(--accent);">
        <div class="card-title">✏️ Edit Guard — <?= htmlspecialchars($editGuard['name']) ?></div>
        <form method="POST" action="security.php?action=guards">
          <?= csrfField() ?>
          <input type="hidden" name="form_action" value="update">
          <input type="hidden" name="uid" value="<?= $editGuard['id'] ?>">

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div class="form-group">
              <label>Full Name</label>
              <input type="text" name="name" required
                     value="<?= htmlspecialchars($editGuard['name']) ?>">
            </div>
            <div class="form-group">
              <label>Username <small style="color:#999;">(cannot change)</small></label>
              <input type="text" value="<?= htmlspecialchars($editGuard['username']) ?>"
                     disabled style="background:#f5f5f5;color:#999;">
            </div>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div class="form-group">
              <label>Phone (27XXXXXXXXX)</label>
              <input type="tel" name="phone"
                     value="<?= htmlspecialchars($editGuard['phone'] ?? '') ?>"
                     placeholder="27821234567" pattern="27[0-9]{9}">
              <small style="color:#888;">Required for OTP on new device.</small>
            </div>
            <div class="form-group">
              <label>Gate Assignment</label>
              <select name="gate">
                <option value="SSgate" <?= ($editGuard['gate']??'')==='SSgate'?'selected':'' ?>>SSgate — Schoeman Street</option>
                <option value="CSgate" <?= ($editGuard['gate']??'')==='CSgate'?'selected':'' ?>>CSgate — Church Street</option>
                <option value="entry"  <?= ($editGuard['gate']??'')==='entry' ?'selected':'' ?>>Any Gate</option>
              </select>
            </div>
          </div>

          <div class="form-group">
            <label>Reset PIN <small style="color:#999;">(leave blank to keep current PIN)</small></label>
            <input type="password" name="pin" inputmode="numeric" maxlength="4"
                   pattern="\d{4}" placeholder="New 4-digit PIN — blank = no change"
                   autocomplete="new-password"
                   style="font-size:1.4rem;letter-spacing:0.4em;text-align:center;">
            <?php if ($editGuard['device_token']): ?>
            <small style="color:#e67e22;">⚠️ Resetting PIN will clear the registered device — guard must re-register on next login.</small>
            <?php endif; ?>
          </div>

          <div style="display:flex;gap:10px;">
            <button type="submit" class="btn btn-primary">Save Changes</button>
            <a href="security.php?action=guards" class="btn btn-secondary">Cancel</a>
          </div>
        </form>
      </div>
      <?php endif; ?>

      <!-- ── Add Guard ──────────────────────────────────── -->
      <?php if (!$editGuard): ?>
      <div class="card">
        <div class="card-title">➕ Add Guard</div>
        <form method="POST" action="security.php?action=guards">
          <?= csrfField() ?>
          <input type="hidden" name="form_action" value="add">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div class="form-group"><label>Full Name</label><input type="text" name="name" required></div>
            <div class="form-group"><label>Username</label><input type="text" name="username" required autocomplete="off"></div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div class="form-group">
              <label>Phone (27XXXXXXXXX)</label>
              <input type="tel" name="phone" placeholder="e.g. 27821234567" pattern="27[0-9]{9}">
              <small style="color:#888;">Required for OTP verification on new device.</small>
            </div>
            <div class="form-group">
              <label>Gate Assignment</label>
              <select name="gate">
                <option value="SSgate">SSgate — Schoeman Street</option>
                <option value="CSgate">CSgate — Church Street</option>
                <option value="entry">Any Gate</option>
              </select>
            </div>
          </div>
          <div class="form-group">
            <label>4-digit PIN</label>
            <input type="password" name="pin" required inputmode="numeric" maxlength="4" pattern="\d{4}"
                   placeholder="••••" style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;">
          </div>
          <button type="submit" class="btn btn-primary btn-block">Add Guard</button>
        </form>
        <div class="popia-notice">Staff data processed under POPIA §11 for access control purposes.</div>
      </div>
      <?php endif; ?>

    </div>
    <?php pageFooter(); exit; ?>
<?php } // end guards

// ════════════════════════════════════════════════════════
// ESTATE SP
// ════════════════════════════════════════════════════════
if ($action === 'estate_sp_add') {

    $categories = [
        'domestic'          => ['icon'=>'🏠', 'label'=>'Domestic / Cleaner',   'permit'=>'card', 'days'=>'Mon,Tue,Wed,Thu,Fri,Sat', 'start'=>'07:00', 'end'=>'17:00', 'once_off'=>0],
        'resident_worker'   => ['icon'=>'🔧', 'label'=>'Maintenance Worker',   'permit'=>'card', 'days'=>'Mon,Tue,Wed,Thu,Fri,Sat', 'start'=>'07:00', 'end'=>'17:00', 'once_off'=>0],
        'contractor_lead'   => ['icon'=>'👷', 'label'=>'Contractor Lead',       'permit'=>'card', 'days'=>'Mon,Tue,Wed,Thu,Fri',     'start'=>'07:00', 'end'=>'17:00', 'once_off'=>0],
        'contractor_worker' => ['icon'=>'🪖', 'label'=>'Contractor Worker',     'permit'=>'slip', 'days'=>'Mon,Tue,Wed,Thu,Fri',     'start'=>'07:00', 'end'=>'17:00', 'once_off'=>0],
        'delivery'          => ['icon'=>'📦', 'label'=>'Delivery / Supplier',   'permit'=>'slip', 'days'=>'Mon,Tue,Wed,Thu,Fri,Sat', 'start'=>'07:00', 'end'=>'17:00', 'once_off'=>1],
    ];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $cat     = $_POST['category'] ?? 'resident_worker';
        $catRule = $categories[$cat] ?? $categories['resident_worker'];
        $pdo     = db();

        if (empty(trim($_POST['service_name'] ?? ''))) {
            setFlash('error', 'Worker name is required.');
            header('Location: security.php?action=estate_sp_add'); exit;
        }
        if ($cat === 'contractor_worker' && empty((int)($_POST['lead_id'] ?? 0))) {
            setFlash('error', 'Contractor Worker must be linked to a Lead.');
            header('Location: security.php?action=estate_sp_add'); exit;
        }

        do {
            $unique = '7' . str_pad(random_int(0, 99999), 5, '0', STR_PAD_LEFT);
            $chk    = $pdo->prepare("SELECT id FROM service_providers WHERE unique_code=? LIMIT 1");
            $chk->execute([$unique]);
        } while ($chk->rowCount() > 0);

        $resErfno = '';
        $resName  = 'GEMB Estate';
        if ($cat === 'contractor_worker' && !empty((int)($_POST['lead_id'] ?? 0))) {
            $lead = $pdo->prepare("SELECT resident_erfno, resident_name FROM service_providers WHERE id=? LIMIT 1");
            $lead->execute([(int)$_POST['lead_id']]);
            $leadRow = $lead->fetch();
            if ($leadRow) { $resErfno = $leadRow['resident_erfno']; $resName = $leadRow['resident_name']; }
        }

        $pdo->prepare("
            INSERT INTO service_providers
              (resident_erfno, resident_name, service_name, company_name,
               id_number, sp_phone, category, permit_type, lead_id,
               once_off, access_days, access_start, access_end,
               start_date, end_date, notes,
               unique_code, status, approved, expired,
               invited_by_resident_id, id_verified)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending','false',0,NULL,1)
        ")->execute([
            $resErfno, $resName,
            trim($_POST['service_name']), trim($_POST['company_name'] ?? ''),
            trim($_POST['id_number'] ?? ''), trim($_POST['sp_phone'] ?? ''),
            $cat, $catRule['permit'],
            ($cat === 'contractor_worker' ? (int)$_POST['lead_id'] : null),
            $catRule['once_off'], $catRule['days'],
            $catRule['start'] . ':00', $catRule['end'] . ':00',
            $_POST['start_date'], $_POST['end_date'],
            trim($_POST['notes'] ?? ''), $unique,
        ]);

        setFlash('success', "Estate SP registered (ID verified). Pending your approval. Code: {$unique}");
        header('Location: security.php?action=approvals&filter=pending'); exit;
    }

    $leads = db()->query("
        SELECT id, service_name, company_name, resident_name FROM service_providers
        WHERE category='contractor_lead' AND (approved='true' OR approved=1)
          AND expired=0 AND end_date >= CURDATE() ORDER BY service_name
    ")->fetchAll();

    pageHeader('Register Estate SP', 'security');
    renderHeader('🏗️ Register Estate Service Provider', 'security.php?action=menu');
    ?>
    <div class="container" style="max-width:580px;">
      <div class="card">
        <?= getFlash() ?>
        <div class="alert alert-info" style="font-size:.88rem;margin-bottom:16px;">
          For estate workers not linked to a specific resident. ID verified on the spot.
        </div>
        <form method="POST" action="security.php?action=estate_sp_add">
          <?= csrfField() ?>
          <div class="form-group">
            <label>Worker Category *</label>
            <div style="display:flex;flex-direction:column;gap:8px;margin-top:4px;">
              <?php foreach ($categories as $key => $cat): ?>
              <label style="display:flex;align-items:center;gap:12px;padding:10px 14px;border:2px solid #dee2e6;border-radius:8px;cursor:pointer;" class="ecat-opt" id="ecat-<?= $key ?>">
                <input type="radio" name="category" value="<?= $key ?>" onchange="updateECat('<?= $key ?>')" <?= $key==='resident_worker' ? 'checked' : '' ?> style="flex-shrink:0;width:18px;height:18px;">
                <div style="font-size:1.3rem;flex-shrink:0;"><?= $cat['icon'] ?></div>
                <div style="flex:1;">
                  <div style="font-weight:700;font-size:.95rem;"><?= $cat['label'] ?></div>
                  <div style="font-size:.75rem;color:#666;margin-top:1px;"><?= $cat['permit']==='card' ? '💳 Card permit' : '📄 Paper slip' ?><?= $cat['once_off'] ? ' · Once-off' : '' ?></div>
                </div>
              </label>
              <?php endforeach; ?>
            </div>
          </div>
          <div class="form-group"><label>Full Name *</label><input type="text" name="service_name" required placeholder="Worker's full name"></div>
          <div class="form-group">
            <label>ID Number *</label>
            <input type="text" name="id_number" required placeholder="SA ID or passport number">
            <small style="color:#28a745;font-weight:600;">✅ ID must be verified in person before saving.</small>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div class="form-group"><label>Company Name</label><input type="text" name="company_name" placeholder="If applicable"></div>
            <div class="form-group"><label>Phone Number</label><input type="tel" name="sp_phone" placeholder="e.g. 27821234567"></div>
          </div>
          <div class="form-group" id="estLeadSection" style="display:none;">
            <label>Contractor Lead *</label>
            <select name="lead_id">
              <option value="">— Select Lead —</option>
              <?php foreach ($leads as $l): ?>
              <option value="<?= $l['id'] ?>"><?= htmlspecialchars($l['service_name']) ?><?= $l['company_name'] ? ' ('.htmlspecialchars($l['company_name']).')' : '' ?> — <?= htmlspecialchars($l['resident_name']) ?></option>
              <?php endforeach; ?>
            </select>
          </div>
          <div class="form-group"><label>Work Description</label><input type="text" name="notes" placeholder="e.g. Estate garden maintenance"></div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div class="form-group"><label>Start Date *</label><input type="date" name="start_date" required value="<?= date('Y-m-d') ?>"></div>
            <div class="form-group"><label>End Date *</label><input type="date" name="end_date" required value="<?= date('Y-m-d', strtotime('+30 days')) ?>"></div>
          </div>
          <button type="submit" class="btn btn-primary btn-block">Register &amp; Submit for Approval</button>
        </form>
        <div class="popia-notice">Personal data collected under POPIA §11. Retained 90 days after expiry.</div>
      </div>
    </div>
    <script>
    function updateECat(key) {
        document.getElementById('estLeadSection').style.display = (key === 'contractor_worker') ? '' : 'none';
        document.querySelectorAll('.ecat-opt').forEach(el => { el.style.borderColor='#dee2e6'; el.style.background='#fff'; });
        const sel = document.getElementById('ecat-' + key);
        if (sel) { sel.style.borderColor='var(--accent)'; sel.style.background='#f5f0ff'; }
    }
    updateECat('resident_worker');
    </script>
    <?php pageFooter(); exit; ?>
<?php } // end estate_sp_add

// ── AJAX: search residents by erf ─────────────────────────
if ($action === 'search_residents') {
    header('Content-Type: application/json');
    $erf = strtoupper(preg_replace('/[^A-Z0-9]/i', '', trim($_GET['erf'] ?? '')));
    if (strlen($erf) < 2) { echo '[]'; exit; }
    $stmt = db()->prepare("
        SELECT resident_erfno, occupant_code, resident_name, occupant_type, address
        FROM residents WHERE UPPER(resident_erfno) LIKE ? AND status='active'
        ORDER BY resident_erfno, occupant_code LIMIT 20
    ");
    $stmt->execute([$erf . '%']);
    echo json_encode($stmt->fetchAll());
    exit;
}

// ── AJAX: get approved contractor leads ───────────────────
if ($action === 'get_leads') {
    header('Content-Type: application/json');
    echo json_encode(db()->query("
        SELECT id, service_name, company_name, resident_erfno, resident_name, end_date
        FROM service_providers
        WHERE category='contractor_lead' AND (approved='true' OR approved=1)
          AND expired=0 AND end_date >= CURDATE() ORDER BY service_name
    ")->fetchAll());
    exit;
}

// ════════════════════════════════════════════════════════
// SP REGISTRATION (resident-linked)
// ════════════════════════════════════════════════════════
if ($action === 'sp_add') {

    $categories = [
        'domestic'          => ['icon'=>'🏠','label'=>'Domestic Worker','desc'=>'Regular domestic worker — linked to specific resident','days'=>'Mon,Tue,Wed,Thu,Fri,Sat','start'=>'07:00','end'=>'17:00','once_off'=>0,'needs_resident'=>true,'needs_lead'=>false],
        'delivery'          => ['icon'=>'📦','label'=>'Delivery','desc'=>'Once-off delivery — expires after first gate scan','days'=>'Mon,Tue,Wed,Thu,Fri,Sat','start'=>'07:00','end'=>'17:00','once_off'=>1,'needs_resident'=>true,'needs_lead'=>false],
        'resident_worker'   => ['icon'=>'🔧','label'=>'Resident Worker','desc'=>'Individual working under resident supervision','days'=>'Mon,Tue,Wed,Thu,Fri,Sat','start'=>'07:00','end'=>'17:00','once_off'=>0,'needs_resident'=>true,'needs_lead'=>false],
        'contractor_lead'   => ['icon'=>'👷','label'=>'Contractor Lead','desc'=>'Team leader — linked to resident, responsible for their team','days'=>'Mon,Tue,Wed,Thu,Fri','start'=>'07:00','end'=>'17:00','once_off'=>0,'needs_resident'=>true,'needs_lead'=>false],
        'contractor_worker' => ['icon'=>'🪖','label'=>'Contractor Worker','desc'=>'Works under a Lead — resident inherited from Lead','days'=>'Mon,Tue,Wed,Thu,Fri','start'=>'07:00','end'=>'17:00','once_off'=>0,'needs_resident'=>false,'needs_lead'=>true],
    ];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $pdo      = db();
        $cat      = $_POST['category'] ?? 'resident_worker';
        $catRules = $categories[$cat] ?? $categories['resident_worker'];
        $errors   = [];
        if (empty(trim($_POST['service_name'] ?? ''))) $errors[] = 'Service / Worker Name is required.';
        if ($catRules['needs_resident'] && empty(trim($_POST['resident_erfno'] ?? ''))) $errors[] = 'This category requires a linked resident.';
        if ($catRules['needs_lead'] && empty((int)($_POST['lead_id'] ?? 0))) $errors[] = 'Contractor Worker must be linked to a Contractor Lead.';
        if (!empty($errors)) { setFlash('error', implode(' ', $errors)); header('Location: security.php?action=sp_add'); exit; }

        do {
            $unique = '7' . str_pad(random_int(0, 99999), 5, '0', STR_PAD_LEFT);
            $chk = $pdo->prepare("SELECT id FROM service_providers WHERE unique_code=? LIMIT 1");
            $chk->execute([$unique]);
        } while ($chk->rowCount() > 0);

        $residentErfno = trim($_POST['resident_erfno'] ?? '');
        $residentName  = trim($_POST['resident_name']  ?? '');
        if ($cat === 'contractor_worker' && !empty((int)($_POST['lead_id'] ?? 0))) {
            $lead = $pdo->prepare("SELECT resident_erfno, resident_name FROM service_providers WHERE id=? LIMIT 1");
            $lead->execute([(int)$_POST['lead_id']]);
            $leadRow = $lead->fetch();
            if ($leadRow) { $residentErfno = $leadRow['resident_erfno']; $residentName = $leadRow['resident_name']; }
        }

        $pdo->prepare("
            INSERT INTO service_providers
              (resident_erfno, resident_name, service_name, company_name,
               id_number, category, lead_id, once_off,
               access_days, access_start, access_end,
               start_date, end_date, notes, qrcode, unique_code, approved, expired)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'false',0)
        ")->execute([
            $residentErfno, $residentName,
            trim($_POST['service_name']), trim($_POST['company_name'] ?? ''),
            trim($_POST['id_number'] ?? ''), $cat,
            ($catRules['needs_lead'] ? (int)$_POST['lead_id'] : null),
            $catRules['once_off'], $catRules['days'],
            ($_POST['access_start'] ?? $catRules['start']) . ':00',
            ($_POST['access_end']   ?? $catRules['end'])   . ':00',
            $_POST['start_date'], $_POST['end_date'],
            trim($_POST['notes'] ?? ''), '', $unique,
        ]);

        setFlash('success', "Service provider registered — pending security approval. Code: {$unique}");
        header('Location: security.php?action=approvals'); exit;
    }

    pageHeader('Register Service Provider', 'security');
    renderHeader('➕ Register Service Provider', 'security.php?action=menu');
    ?>
    <div class="container">
      <div class="card">
        <?= getFlash() ?>
        <form method="POST" action="security.php?action=sp_add" id="spForm">
          <?= csrfField() ?>
          <div class="form-group">
            <label>Category *</label>
            <div style="display:flex;flex-direction:column;gap:8px;margin-top:4px;" id="catGrid">
              <?php foreach ($categories as $key => $cat): ?>
              <label style="display:flex;align-items:center;gap:12px;padding:10px 14px;border:2px solid #dee2e6;border-radius:8px;cursor:pointer;transition:all .15s;" class="cat-option" id="cat-<?= $key ?>">
                <input type="radio" name="category" value="<?= $key ?>" onchange="updateCategory('<?= $key ?>')" <?= $key==='resident_worker'?'checked':'' ?> style="flex-shrink:0;width:18px;height:18px;">
                <div style="font-size:1.3rem;flex-shrink:0;"><?= $cat['icon'] ?></div>
                <div style="flex:1;">
                  <div style="font-weight:700;font-size:.95rem;"><?= $cat['label'] ?></div>
                  <div style="font-size:.78rem;color:#666;margin-top:1px;"><?= $cat['desc'] ?></div>
                </div>
              </label>
              <?php endforeach; ?>
            </div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div class="form-group"><label>Worker / Service Name *</label><input type="text" name="service_name" required placeholder="Full name of person"></div>
            <div class="form-group"><label>Company Name</label><input type="text" name="company_name" placeholder="If applicable"></div>
          </div>
          <div class="form-group"><label>ID Number</label><input type="text" name="id_number" placeholder="SA ID or passport"></div>
          <div class="form-group" id="residentSection">
            <label>Linked Resident Erf *</label>
            <input type="text" id="erfSearch" placeholder="Type erf number e.g. E15227" autocomplete="off" style="text-transform:uppercase;margin-bottom:6px;" oninput="this.value=this.value.toUpperCase();searchResidents(this.value)">
            <div id="residentResults" style="display:none;border:1px solid #dee2e6;border-radius:6px;max-height:200px;overflow-y:auto;background:#fff;box-shadow:0 4px 12px rgba(0,0,0,.1);"></div>
            <input type="hidden" name="resident_erfno" id="selectedErf">
            <input type="hidden" name="resident_name"  id="selectedName">
            <div id="selectedResident" style="display:none;background:#e8f8ee;border:1px solid #2ecc71;border-radius:6px;padding:10px 12px;margin-top:6px;font-size:.88rem;"></div>
          </div>
          <div class="form-group" id="leadSection" style="display:none;">
            <label>Contractor Lead *</label>
            <select name="lead_id" id="leadSelect" style="font-size:.95rem;"><option value="">— Select Lead —</option></select>
            <div id="inheritedResident" style="display:none;background:#e8f0fe;border:1px solid #1565c0;border-radius:6px;padding:8px 12px;margin-top:6px;font-size:.85rem;color:#1565c0;"></div>
          </div>
          <div class="form-group"><label>Work Description / Notes</label><input type="text" name="notes" placeholder="e.g. Painting interior, Garden maintenance"></div>
          <div id="accessInfo" style="background:#f5f7fa;border-radius:8px;padding:12px 14px;margin-bottom:14px;font-size:.85rem;">
            <strong>Access hours:</strong> <span id="accessDisplay">Mon–Sat 07:00–17:00</span>
            <span id="onceOffBadge" style="display:none;margin-left:8px;background:#ffc107;color:#000;padding:2px 8px;border-radius:10px;font-size:.78rem;font-weight:700;">ONCE-OFF — expires after first scan</span>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div class="form-group"><label>Start Date *</label><input type="date" name="start_date" required value="<?= date('Y-m-d') ?>"></div>
            <div class="form-group"><label>End Date *</label><input type="date" name="end_date" required id="endDateInput" value="<?= date('Y-m-d', strtotime('+30 days')) ?>"></div>
          </div>
          <button type="submit" class="btn btn-primary btn-block" id="submitBtn">Register &amp; Submit for Approval</button>
        </form>
        <div class="popia-notice">Personal data collected under POPIA §11. Retained 90 days after expiry.</div>
      </div>
    </div>
    <script>
    const catRules = {
        domestic:          {needsResident:true, needsLead:false, onceOff:false, days:'Mon–Sat', hours:'07:00–17:00'},
        delivery:          {needsResident:true, needsLead:false, onceOff:true,  days:'Mon–Sat', hours:'07:00–17:00'},
        resident_worker:   {needsResident:true, needsLead:false, onceOff:false, days:'Mon–Sat', hours:'07:00–17:00'},
        contractor_lead:   {needsResident:true, needsLead:false, onceOff:false, days:'Mon–Fri', hours:'07:00–17:00'},
        contractor_worker: {needsResident:false,needsLead:true,  onceOff:false, days:'Mon–Fri', hours:'07:00–17:00'},
    };
    function updateCategory(key) {
        const r = catRules[key];
        document.getElementById('residentSection').style.display = r.needsResident ? '' : 'none';
        document.getElementById('leadSection').style.display     = r.needsLead     ? '' : 'none';
        document.getElementById('onceOffBadge').style.display    = r.onceOff       ? '' : 'none';
        document.getElementById('accessDisplay').textContent     = r.days + ' ' + r.hours;
        document.querySelectorAll('.cat-option').forEach(el => { el.style.borderColor='#dee2e6'; el.style.background='#fff'; });
        const sel = document.getElementById('cat-' + key);
        if (sel) { sel.style.borderColor='var(--accent)'; sel.style.background='#f0f4ff'; }
        if (key === 'delivery') { document.getElementById('endDateInput').value = new Date().toISOString().split('T')[0]; document.getElementById('submitBtn').textContent = '✅ Create Delivery Pass (Auto-Approved)'; }
        else if (key === 'contractor_worker') { loadLeads(); document.getElementById('submitBtn').textContent = 'Register & Submit for Approval'; }
        else { document.getElementById('submitBtn').textContent = 'Register & Submit for Approval'; }
    }
    let searchTimer = null;
    function searchResidents(val) {
        clearTimeout(searchTimer);
        const results = document.getElementById('residentResults');
        if (val.length < 2) { results.style.display = 'none'; return; }
        searchTimer = setTimeout(() => {
            fetch('security.php?action=search_residents&erf=' + encodeURIComponent(val))
              .then(r => r.json()).then(data => {
                if (!data.length) { results.style.display = 'none'; return; }
                results.innerHTML = data.map(r => `<div onclick="selectResident('${r.resident_erfno}','${r.occupant_code}','${escHtml(r.resident_name)}','${escHtml(r.address)}')" style="padding:10px 14px;cursor:pointer;border-bottom:1px solid #eee;font-size:.88rem;" onmouseover="this.style.background='#f0f4ff'" onmouseout="this.style.background=''"><strong>${r.resident_erfno}${r.occupant_code}</strong> — ${escHtml(r.resident_name)} <span style="color:#888;font-size:.8rem;">(${ucFirst(r.occupant_type.replace('_',' '))})</span><br><span style="color:#999;font-size:.78rem;">${escHtml(r.address)}</span></div>`).join('');
                results.style.display = 'block';
              });
        }, 350);
    }
    function selectResident(erf, code, name, address) {
        document.getElementById('selectedErf').value = erf;
        document.getElementById('selectedName').value = name;
        document.getElementById('erfSearch').value = erf;
        const div = document.getElementById('selectedResident');
        div.innerHTML = `✅ <strong>${erf}${code}</strong> — ${name} <span style="color:#666;font-size:.82rem;">&nbsp;${address}</span> <a href="#" onclick="clearResident();return false;" style="float:right;color:#c00;font-size:.8rem;">✕ Clear</a>`;
        div.style.display = 'block';
        document.getElementById('residentResults').style.display = 'none';
    }
    function clearResident() {
        document.getElementById('selectedErf').value = '';
        document.getElementById('selectedName').value = '';
        document.getElementById('erfSearch').value = '';
        document.getElementById('selectedResident').style.display = 'none';
    }
    function loadLeads() {
        fetch('security.php?action=get_leads').then(r => r.json()).then(data => {
            const sel = document.getElementById('leadSelect');
            sel.innerHTML = '<option value="">— Select Lead —</option>';
            if (!data.length) { sel.innerHTML += '<option disabled>No approved Contractor Leads found</option>'; return; }
            data.forEach(l => {
                const opt = document.createElement('option');
                opt.value = l.id; opt.dataset.resident = l.resident_name||''; opt.dataset.erfno = l.resident_erfno||'';
                opt.textContent = l.service_name + (l.company_name?' ('+l.company_name+')':'') + ' — ' + (l.resident_name ? 'Erf '+l.resident_erfno+' '+l.resident_name : 'Estate-wide') + ' — until '+l.end_date;
                sel.appendChild(opt);
            });
            sel.onchange = function() {
                const opt = this.options[this.selectedIndex];
                const info = document.getElementById('inheritedResident');
                if (opt && opt.dataset.resident) { info.innerHTML = '🏠 Resident inherited from Lead: <strong>Erf '+escHtml(opt.dataset.erfno)+' — '+escHtml(opt.dataset.resident)+'</strong>'; info.style.display='block'; }
                else { info.style.display='none'; }
            };
        });
    }
    function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
    function ucFirst(s) { return s.charAt(0).toUpperCase()+s.slice(1); }
    updateCategory('resident_worker');
    </script>
    <?php pageFooter(); exit; ?>
<?php } // end sp_add

// ════════════════════════════════════════════════════════
// SP APPROVALS
// ── Change 2: pending count = genuinely awaiting approval
// ── Change 3: ORDER BY created_at ASC (oldest first)
// ── Change 5: Contractor Leads must be approved via the
//    Application Engine (application_admin.php). Direct
//    Approve is blocked server-side and the button is
//    replaced with "Capture Application".
// ════════════════════════════════════════════════════════
if ($action === 'approvals') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $id  = (int)$_POST['sp_id'];
        $act = $_POST['sp_action'];

        if ($act === 'approve') {
            // ── Engine enforcement: Contractor Leads must come through
            //    the Application Verification process. Records created BY
            //    the engine carry '[gemB APP-' in notes and are born
            //    approved, so this only blocks raw invite placeholders.
            $guard = db()->prepare("SELECT category, notes FROM service_providers WHERE id=? LIMIT 1");
            $guard->execute([$id]);
            $guardRow = $guard->fetch();
            if ($guardRow
                && $guardRow['category'] === 'contractor_lead'
                && strpos($guardRow['notes'] ?? '', '[gemB APP-') === false) {
                setFlash('error',
                    'Contractor Leads cannot be approved directly. Use "Capture Application" to complete the '
                    . 'contractor application (worker documents, police clearances, payment, induction) — approval '
                    . 'happens in Application Verification once every checklist item passes.');
                header('Location: security.php?action=approvals'); exit;
            }

            db()->prepare(
                "UPDATE service_providers SET approved='true', approved_by=?, approved_at=NOW() WHERE id=?"
            )->execute([$_SESSION['security_name'], $id]);
            generateSpQr($id);
            setFlash('success', 'Service provider approved.');

        } elseif ($act === 'revoke') {
            db()->prepare(
                "UPDATE service_providers SET approved='false', expired=1 WHERE id=?"
            )->execute([$id]);
            $sp = db()->prepare("SELECT category FROM service_providers WHERE id=? LIMIT 1");
            $sp->execute([$id]);
            $sp = $sp->fetch();
            if ($sp && $sp['category'] === 'contractor_lead') {
                $workers = db()->prepare(
                    "UPDATE service_providers SET approved='false', expired=1,
                     notes=CONCAT(notes,' [Auto-revoked: Lead revoked ',NOW(),']')
                     WHERE lead_id=? AND expired=0"
                );
                $workers->execute([$id]);
                $count = $workers->rowCount();
                setFlash('success', 'Contractor Lead revoked. ' . ($count > 0 ? "{$count} worker(s) automatically revoked." : 'No active workers affected.'));
            } else {
                setFlash('success', 'Service provider revoked.');
            }
        }
        header('Location: security.php?action=approvals'); exit;
    }

    // Whitelist $filter — only known values accepted; anything else → 'all'
    $filter = $_GET['filter'] ?? 'pending';
    if (!in_array($filter, ['pending','invited','approved','all'], true)) {
        $filter = 'all';
    }

    $hasStatusCol = true;
    try { db()->query("SELECT status FROM service_providers LIMIT 1"); }
    catch (Exception $e) { $hasStatusCol = false; }

    if (!$hasStatusCol) {
        $whereFilter = '';
    } elseif ($filter === 'invited') {
        $whereFilter = "AND (sp.status = 'invited')";
    } elseif ($filter === 'pending') {
        $whereFilter = "AND (sp.approved='false' OR sp.approved='' OR sp.approved IS NULL)
                        AND sp.expired=0 AND sp.end_date >= CURDATE()
                        AND (sp.status='pending' OR sp.status IS NULL OR sp.status='')";
    } elseif ($filter === 'approved') {
        $whereFilter = "AND (sp.status='approved' OR sp.approved='true' OR sp.approved=1) AND sp.expired=0";
    } else {
        $whereFilter = ''; // 'all' — no filter
    }

    // ── ORDER: oldest first for pending (first received = first served)
    //           newest first for approved/all
    $orderBy = ($filter === 'pending' || $filter === 'invited')
               ? 'ORDER BY sp.created_at ASC'
               : 'ORDER BY sp.created_at DESC';

    try {
        $sps = db()->query("
            SELECT sp.*,
                   IF(sp.lead_id IS NOT NULL,
                      (SELECT service_name FROM service_providers WHERE id=sp.lead_id), NULL) AS lead_name
            FROM service_providers sp
            WHERE 1=1 {$whereFilter}
            {$orderBy}
        ")->fetchAll();
    } catch (Exception $e) {
        $sps = db()->query("SELECT * FROM service_providers ORDER BY created_at ASC")->fetchAll();
        $sps = array_map(function($sp) {
            $sp['lead_name']=''; $sp['status']=$sp['approved']==='true'?'approved':'pending';
            $sp['category']=$sp['category']??'resident_worker'; $sp['permit_type']='slip';
            $sp['once_off']=0; $sp['access_days']='Mon-Sat';
            $sp['access_start']='07:00:00'; $sp['access_end']='17:00:00';
            $sp['invited_by_resident_id']=null; $sp['id_verified']=0;
            return $sp;
        }, $sps);
    }

    $catLabels = [
        'domestic'          => ['icon'=>'🏠','label'=>'Domestic'],
        'delivery'          => ['icon'=>'📦','label'=>'Delivery'],
        'resident_worker'   => ['icon'=>'🔧','label'=>'Resident Worker'],
        'contractor_lead'   => ['icon'=>'👷','label'=>'Contractor Lead'],
        'contractor_worker' => ['icon'=>'🪖','label'=>'Contractor Worker'],
    ];

    pageHeader('SP Approvals', 'security');
    renderHeader('✅ Service Provider Approvals', 'security.php?action=menu');
    ?>
    <div class="container">
      <?= getFlash() ?>
      <div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;">
        <a href="security.php?action=approvals&filter=invited"  class="btn btn-sm <?= $filter==='invited' ?'btn-primary':'btn-secondary' ?>">🔔 Awaiting Office Visit</a>
        <a href="security.php?action=approvals&filter=pending"  class="btn btn-sm <?= $filter==='pending' ?'btn-primary':'btn-secondary' ?>">⏳ Pending Approval</a>
        <a href="security.php?action=approvals&filter=approved" class="btn btn-sm <?= $filter==='approved'?'btn-primary':'btn-secondary' ?>">✅ Approved</a>
        <a href="security.php?action=approvals&filter=all"      class="btn btn-sm <?= $filter==='all'     ?'btn-primary':'btn-secondary' ?>">📋 All</a>
      </div>

      <?php if (empty($sps)): ?>
        <div class="card"><p style="color:#666;">No records in this category.</p></div>
      <?php endif; ?>

      <?php foreach ($sps as $sp):
        $isApproved  = ($sp['approved'] === 'true' || $sp['approved'] == 1);
        $isExpired   = $sp['expired'] || $sp['end_date'] < date('Y-m-d');
        $statusColor = $isExpired ? '#aaa' : ($isApproved ? '#28a745' : '#ffc107');
        $statusLabel = $isExpired ? 'expired' : ($isApproved ? 'approved' : 'pending');
        $cat         = $catLabels[$sp['category'] ?? 'resident_worker'] ?? $catLabels['resident_worker'];
      ?>
      <div class="card" style="border-left:4px solid <?= $statusColor ?>">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;">
          <div>
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
              <strong><?= htmlspecialchars($sp['service_name']) ?></strong>
              <span class="badge badge-info" style="font-size:.75rem;"><?= $cat['icon'] ?> <?= $cat['label'] ?></span>
              <?php if ($sp['once_off']): ?><span class="badge badge-warning" style="font-size:.72rem;">ONCE-OFF</span><?php endif; ?>
            </div>
            <?php if ($sp['company_name']): ?><div style="color:#666;font-size:.85rem;margin-top:2px;"><?= htmlspecialchars($sp['company_name']) ?></div><?php endif; ?>
            <?php if ($sp['lead_name']): ?><div style="color:#1565c0;font-size:.82rem;margin-top:2px;">👷 Lead: <?= htmlspecialchars($sp['lead_name']) ?></div><?php endif; ?>
            <div style="font-size:.8rem;color:#999;margin-top:3px;">
              <?= $sp['start_date'] ?> → <?= $sp['end_date'] ?>
              &nbsp;|&nbsp; <?= htmlspecialchars($sp['access_days'] ?? 'Mon-Sat') ?>
              <?= htmlspecialchars(substr($sp['access_start']??'07:00:00',0,5)) ?>–<?= htmlspecialchars(substr($sp['access_end']??'17:00:00',0,5)) ?>
              <?php if ($sp['resident_erfno']): ?>
                &nbsp;|&nbsp; Erf <?= $sp['resident_erfno'] ?> <?= htmlspecialchars($sp['resident_name']??'') ?>
              <?php elseif (($sp['resident_name']??'') === 'GEMB Estate'): ?>
                &nbsp;|&nbsp; <em>🏗️ Estate worker</em>
              <?php else: ?>
                &nbsp;|&nbsp; <em>Estate-wide</em>
              <?php endif; ?>
            </div>
            <div style="font-size:.78rem;color:#888;margin-top:2px;">
              Received: <?= date('d M Y H:i', strtotime($sp['created_at'])) ?>
            </div>
            <div style="font-size:.78rem;margin-top:2px;">
              <?php if ($sp['invited_by_resident_id']): ?>
                <span style="color:#1565c0;">👤 Invited by resident</span>
              <?php else: ?>
                <span style="color:#8e44ad;">🛡️ Registered by Site Manager</span>
              <?php endif; ?>
              <?php if ($sp['id_verified']??false): ?>&nbsp;|&nbsp; <span style="color:#28a745;">✅ ID verified</span><?php endif; ?>
            </div>
            <?php if ($sp['notes']): ?><div style="font-size:.82rem;color:#666;margin-top:2px;">📝 <?= htmlspecialchars($sp['notes']) ?></div><?php endif; ?>
            <div style="font-size:.78rem;color:#999;margin-top:3px;font-family:monospace;">
              Code: <strong><?= htmlspecialchars($sp['unique_code']??'') ?></strong>
            </div>
          </div>
          <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
            <span class="badge badge-<?= $isExpired?'muted':($isApproved?'success':'warning') ?>"><?= $statusLabel ?></span>
            <?php if (!$isApproved && !$isExpired): ?>
              <?php if (($sp['category'] ?? '') === 'contractor_lead'
                        && strpos($sp['notes'] ?? '', '[gemB APP-') === false): ?>
              <a href="application_form.php?type=contractor&invite=<?= urlencode($sp['unique_code'] ?? '') ?>"
                 class="btn btn-primary btn-sm">📋 Capture Application</a>
              <?php else: ?>
              <form method="POST" style="display:inline">
                <?= csrfField() ?>
                <input type="hidden" name="sp_id" value="<?= $sp['id'] ?>">
                <input type="hidden" name="sp_action" value="approve">
                <button class="btn btn-success btn-sm">Approve</button>
              </form>
              <?php endif; ?>
            <?php endif; ?>
            <?php if ($isApproved && !$isExpired): ?>
            
            <a href="permit_photo_upload.php?id=<?= $sp['id'] ?>&type=<?= $sp['permit_type']==='card' ? 'card' : 'slip' ?>" target="_blank" class="btn btn-primary btn-sm">
                 🖨️ <?= $sp['permit_type']==='card' ? 'Print Card' : 'Print Slip' ?>
            </a>
            
            <form method="POST" style="display:inline" onsubmit="return confirm(<?= $sp['category']==='contractor_lead' ? "'Revoking this Lead will also revoke all their workers. Continue?'" : "'Revoke this service provider?'" ?>)">
              <?= csrfField() ?>
              <input type="hidden" name="sp_id" value="<?= $sp['id'] ?>">
              <input type="hidden" name="sp_action" value="revoke">
              <button class="btn btn-danger btn-sm">Revoke</button>
            </form>
            <?php endif; ?>
          </div>
        </div>
      </div>
      <?php endforeach; ?>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end approvals

// ── ACCESS LOGS ───────────────────────────────────────────
if ($action === 'logs') {
    // Whitelist and sanitise all GET params for logs
    $gate = in_array($_GET['gate'] ?? '', ['SSgate','CSgate',''], true)
            ? ($_GET['gate'] ?? '') : '';
    $rawDate = $_GET['date'] ?? date('Y-m-d');
    $date = preg_match('/^\d{4}-\d{2}-\d{2}$/', $rawDate) ? $rawDate : date('Y-m-d');
    $view = in_array($_GET['view'] ?? 'paired', ['paired','all'], true)
            ? ($_GET['view'] ?? 'paired') : 'paired';

    // ── Paired view: match ENTRY + EXIT on same row ───────
    if ($view === 'paired') {
        // Fetch all ENTRY records for the day/gate
        if ($gate) {
            $stmt = db()->prepare(
                "SELECT a.*,
                        b.created_at  AS exit_time,
                        b.guard_name  AS exit_guard,
                        b.gate_point  AS exit_gate_point,
                        b.event_id    AS exit_event_id
                 FROM access_log a
                 LEFT JOIN access_log b
                        ON b.entry_ref = a.event_id
                       AND b.direction = 'EXIT'
                 WHERE DATE(a.created_at) = ?
                   AND a.gate = ?
                   AND a.direction = 'ENTRY'
                 ORDER BY a.created_at DESC"
            );
            $stmt->execute([$date, $gate]);
        } else {
            $stmt = db()->prepare(
                "SELECT a.*,
                        b.created_at  AS exit_time,
                        b.guard_name  AS exit_guard,
                        b.gate_point  AS exit_gate_point,
                        b.event_id    AS exit_event_id
                 FROM access_log a
                 LEFT JOIN access_log b
                        ON b.entry_ref = a.event_id
                       AND b.direction = 'EXIT'
                 WHERE DATE(a.created_at) = ?
                   AND a.direction = 'ENTRY'
                 ORDER BY a.created_at DESC"
            );
            $stmt->execute([$date]);
        }
        $logs = $stmt->fetchAll();

        // Also fetch exits that have NO matching entry
        // (guard logged exit without prior entry scan)
        if ($gate) {
            $stmtX = db()->prepare(
                "SELECT * FROM access_log
                 WHERE DATE(created_at) = ?
                   AND gate = ?
                   AND direction = 'EXIT'
                   AND (entry_ref IS NULL OR entry_ref = '')
                 ORDER BY created_at DESC"
            );
            $stmtX->execute([$date, $gate]);
        } else {
            $stmtX = db()->prepare(
                "SELECT * FROM access_log
                 WHERE DATE(created_at) = ?
                   AND direction = 'EXIT'
                   AND (entry_ref IS NULL OR entry_ref = '')
                 ORDER BY created_at DESC"
            );
            $stmtX->execute([$date]);
        }
        $unpairedExits = $stmtX->fetchAll();

    } else {
        // ── All events flat list ──────────────────────────
        if ($gate) {
            $stmt = db()->prepare(
                "SELECT * FROM access_log
                 WHERE DATE(created_at)=? AND gate=?
                 ORDER BY created_at DESC LIMIT 500"
            );
            $stmt->execute([$date, $gate]);
        } else {
            $stmt = db()->prepare(
                "SELECT * FROM access_log
                 WHERE DATE(created_at)=?
                 ORDER BY created_at DESC LIMIT 500"
            );
            $stmt->execute([$date]);
        }
        $logs          = $stmt->fetchAll();
        $unpairedExits = [];
    }

    // ── Summary counts ────────────────────────────────────
    try {
        $summary = db()->prepare(
            "SELECT
               SUM(direction='ENTRY' AND granted=1)  AS entries,
               SUM(direction='EXIT'  AND granted=1)  AS exits,
               SUM(granted=0)                         AS denied,
               SUM(direction='ENTRY' AND granted=1
                   AND (entry_ref IS NULL OR entry_ref='')) AS on_estate
             FROM access_log
             WHERE DATE(created_at)=?" . ($gate ? " AND gate=?" : "")
        );
        $gate ? $summary->execute([$date, $gate])
              : $summary->execute([$date]);
        $summary = $summary->fetch();
    } catch (Exception $e) {
        $summary = ['entries'=>0,'exits'=>0,'denied'=>0,'on_estate'=>0];
    }

    pageHeader('Access Logs', 'security');
    renderHeader('📋 Access Logs', 'security.php?action=menu');
    ?>
    <div class="container">
      <!-- Filter bar -->
      <div class="card">
        <form method="GET" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;">
          <input type="hidden" name="action" value="logs">
          <div>
            <label style="display:block;font-size:.8rem;color:#666;margin-bottom:3px;">Date</label>
            <input type="date" name="date" value="<?= $date ?>"
                   style="padding:8px;border:1px solid #dee2e6;border-radius:6px;">
          </div>
          <div>
            <label style="display:block;font-size:.8rem;color:#666;margin-bottom:3px;">Gate</label>
            <select name="gate" style="padding:8px;border:1px solid #dee2e6;border-radius:6px;">
              <option value="">All Gates</option>
              <option value="SSgate" <?= $gate==='SSgate'?'selected':'' ?>>Schoeman Street</option>
              <option value="CSgate" <?= $gate==='CSgate'?'selected':'' ?>>Church Street</option>
            </select>
          </div>
          <div>
            <label style="display:block;font-size:.8rem;color:#666;margin-bottom:3px;">View</label>
            <select name="view" style="padding:8px;border:1px solid #dee2e6;border-radius:6px;">
              <option value="paired" <?= $view==='paired'?'selected':'' ?>>Paired Entry+Exit</option>
              <option value="all"    <?= $view==='all'   ?'selected':'' ?>>All Events</option>
            </select>
          </div>
          <button type="submit" class="btn btn-primary">Filter</button>
        </form>
      </div>

      <!-- Summary strip -->
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px;">
        <?php foreach ([
            ['⬇️ Entries',  $summary['entries']  ?? 0, '#1565c0'],
            ['⬆️ Exits',    $summary['exits']    ?? 0, '#8e44ad'],
            ['⛔ Denied',   $summary['denied']   ?? 0, '#dc3545'],
            ['🏡 On Estate',$summary['on_estate']?? 0, '#28a745'],
        ] as [$lbl,$val,$col]): ?>
        <div style="background:#fff;border-radius:8px;padding:12px;text-align:center;
                    box-shadow:0 2px 8px rgba(0,0,0,.06);border-top:3px solid <?= $col ?>;">
          <div style="font-size:.78rem;color:#666;"><?= $lbl ?></div>
          <div style="font-size:1.6rem;font-weight:700;color:<?= $col ?>;"><?= $val ?></div>
        </div>
        <?php endforeach; ?>
      </div>

      <?php if ($view === 'paired'): ?>
      <!-- ── PAIRED VIEW ─────────────────────────────── -->
      <div class="card">
        <div class="card-title">
          Entry + Exit pairs — <?= date('d M Y', strtotime($date)) ?>
          <?= $gate ? ' — ' . htmlspecialchars($gate) : '' ?>
        </div>
        <?php if (empty($logs) && empty($unpairedExits)): ?>
          <p style="color:#666;font-size:.9rem;">No records for this selection.</p>
        <?php else: ?>
        <div class="table-wrap">
          <table>
            <tr>
              <th>Type</th>
              <th>Name / Code</th>
              <th>Entry Time</th>
              <th>Entry Point</th>
              <th>Entry Guard</th>
              <th>Exit Time</th>
              <th>Exit Point</th>
              <th>Exit Guard</th>
              <th>Duration</th>
              <th>Result</th>
            </tr>
            <?php foreach ($logs as $l):
              $granted   = $l['granted'] ?? (empty($l['deny_reason']) ? 1 : 0);
              $entryTime = strtotime($l['created_at']);
              $exitTime  = $l['exit_time'] ? strtotime($l['exit_time']) : null;
              $duration  = '—';
              if ($exitTime) {
                  $diff = $exitTime - $entryTime;
                  $h    = floor($diff / 3600);
                  $m    = floor(($diff % 3600) / 60);
                  $duration = $h > 0 ? "{$h}h {$m}m" : "{$m}m";
              }
              $rowBg = !$granted ? '#fff5f5' : ($exitTime ? '#f5fff8' : '#fff');
            ?>
            <tr style="background:<?= $rowBg ?>;">
              <td style="font-size:.82rem;">
                <?= htmlspecialchars($l['entry_type'] ?? '') ?>
              </td>
              <td>
                <strong style="font-size:.88rem;">
                  <?= htmlspecialchars($l['person_name'] ?? $l['plate'] ?? $l['qr_code'] ?? '—') ?>
                </strong>
                <?php if ($l['qr_code'] ?? false): ?>
                  <div style="font-size:.75rem;color:#999;font-family:monospace;">
                    <?= htmlspecialchars($l['qr_code']) ?>
                  </div>
                <?php endif; ?>
              </td>
              <td style="white-space:nowrap;font-size:.85rem;">
                <?= date('H:i:s', $entryTime) ?>
              </td>
              <td style="font-size:.78rem;color:#666;">
                <?= htmlspecialchars($l['gate_point'] ?? '') ?>
              </td>
              <td style="font-size:.78rem;color:#666;">
                <?= htmlspecialchars($l['guard_name'] ?? '') ?>
              </td>
              <td style="white-space:nowrap;font-size:.85rem;
                         color:<?= $exitTime ? '#8e44ad' : '#ccc' ?>;">
                <?= $exitTime ? date('H:i:s', $exitTime) : '—' ?>
              </td>
              <td style="font-size:.78rem;color:#666;">
                <?= htmlspecialchars($l['exit_gate_point'] ?? '') ?>
              </td>
              <td style="font-size:.78rem;color:#666;">
                <?= htmlspecialchars($l['exit_guard'] ?? '') ?>
              </td>
              <td style="font-weight:600;color:<?= $exitTime?'#28a745':'#999' ?>;">
                <?= $duration ?>
              </td>
              <td>
                <span class="badge badge-<?= $granted?'success':'danger' ?>">
                  <?= $granted ? 'OK' : 'DENIED' ?>
                </span>
              </td>
            </tr>
            <?php endforeach; ?>

            <?php foreach ($unpairedExits as $l): ?>
            <tr style="background:#f5f0ff;">
              <td style="font-size:.82rem;">
                <?= htmlspecialchars($l['entry_type'] ?? '') ?>
              </td>
              <td>
                <strong style="font-size:.88rem;">
                  <?= htmlspecialchars($l['person_name'] ?? $l['plate'] ?? '—') ?>
                </strong>
                <div style="font-size:.72rem;color:#8e44ad;">⬆️ Exit only (no entry scan)</div>
              </td>
              <td style="color:#ccc;">—</td>
              <td style="color:#ccc;">—</td>
              <td style="color:#ccc;">—</td>
              <td style="white-space:nowrap;font-size:.85rem;color:#8e44ad;">
                <?= date('H:i:s', strtotime($l['created_at'])) ?>
              </td>
              <td style="font-size:.78rem;color:#666;">
                <?= htmlspecialchars($l['gate_point'] ?? '') ?>
              </td>
              <td style="font-size:.78rem;color:#666;">
                <?= htmlspecialchars($l['guard_name'] ?? '') ?>
              </td>
              <td style="color:#ccc;">—</td>
              <td><span class="badge badge-muted">EXIT ONLY</span></td>
            </tr>
            <?php endforeach; ?>
          </table>
        </div>
        <?php endif; ?>
      </div>

      <?php else: ?>
      <!-- ── ALL EVENTS FLAT LIST ─────────────────────── -->
      <div class="card">
        <div class="card-title">
          All Events — <?= date('d M Y', strtotime($date)) ?>
          <?= $gate ? ' — ' . htmlspecialchars($gate) : '' ?>
        </div>
        <div class="table-wrap"><table>
          <tr>
            <th>Time</th><th>Dir</th><th>Gate Point</th>
            <th>Type</th><th>Name</th><th>Guard</th><th>Result</th>
          </tr>
          <?php foreach ($logs as $l):
            $granted = $l['granted'] ?? (empty($l['deny_reason']) ? 1 : 0);
            $isExit  = ($l['direction'] ?? 'ENTRY') === 'EXIT';
          ?>
          <tr>
            <td style="white-space:nowrap;font-size:.82rem;">
              <?= date('H:i:s', strtotime($l['created_at'])) ?>
            </td>
            <td>
              <span style="font-weight:700;color:<?= $isExit?'#8e44ad':'#1565c0' ?>;">
                <?= $isExit ? '⬆️ EXIT' : '⬇️ ENTRY' ?>
              </span>
            </td>
            <td style="font-size:.78rem;color:#666;">
              <?= htmlspecialchars($l['gate_point'] ?? '') ?>
            </td>
            <td style="font-size:.82rem;">
              <?= htmlspecialchars($l['entry_type'] ?? '') ?>
            </td>
            <td style="font-size:.85rem;">
              <?= htmlspecialchars($l['person_name'] ?? $l['plate'] ?? '—') ?>
            </td>
            <td style="font-size:.78rem;color:#666;">
              <?= htmlspecialchars($l['guard_name'] ?? '') ?>
            </td>
            <td>
              <span class="badge badge-<?= $granted?'success':'danger' ?>">
                <?= $granted ? 'OK' : 'DENIED' ?>
              </span>
            </td>
          </tr>
          <?php endforeach; ?>
        </table></div>
      </div>
      <?php endif; ?>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end logs

// ════════════════════════════════════════════════════════
// GATE OVERRIDE — remote gate open with audit trail
// ════════════════════════════════════════════════════════
if ($action === 'gate_override') {

    // ── Rate limit: max 5 overrides per officer per hour ──
    $overrideCount = 0;
    try {
        $rc = db()->prepare("
            SELECT COUNT(*) FROM access_log
            WHERE entry_type = 'override'
              AND guard_name = ?
              AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
        ");
        $rc->execute([$_SESSION['security_name'] ?? '']);
        $overrideCount = (int)$rc->fetchColumn();
    } catch (Exception $e) {}

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();

        if ($overrideCount >= 5) {
            setFlash('error', 'Rate limit reached — maximum 5 remote overrides per hour. Contact administrator.');
            header('Location: security.php?action=gate_override'); exit;
        }

        $gate      = in_array($_POST['gate'] ?? '', ['SSgate','CSgate'], true)
                     ? $_POST['gate'] : 'SSgate';
        $reason    = trim($_POST['reason'] ?? '');
        $erfno     = strtoupper(trim($_POST['resident_erfno'] ?? ''));

        if (strlen($reason) < 10) {
            setFlash('error', 'Please provide a reason of at least 10 characters.');
            header('Location: security.php?action=gate_override'); exit;
        }

        $officerName = $_SESSION['security_name'] ?? 'Unknown';
        $officerId   = $_SESSION['security_id']   ?? 0;
        $gateLabel   = $gate === 'SSgate' ? 'Schoeman Street' : 'Church Street';

        // ── Store as pending override — Pi will poll and execute ──
        try {
            db()->prepare("
                INSERT INTO pending_gate_overrides
                  (gate, reason, officer_name, officer_id, resident_erfno, expires_at)
                VALUES (?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))
            ")->execute([
                $gate, $reason, $officerName, $officerId,
                $erfno ?: null,
            ]);
            $pendingId = (int)db()->lastInsertId();
        } catch (Exception $e) {
            setFlash('error', 'Could not store override request: ' . $e->getMessage());
            header('Location: security.php?action=gate_override'); exit;
        }

        setFlash('success',
            "✅ Override submitted for {$gateLabel} gate. "
            . "The gate controller will execute this within 30 seconds. "
            . "Resident and administrator will be notified automatically."
        );
        header('Location: security.php?action=gate_override&pending=' . $pendingId); exit;
    }

    // ── Show pending override status if redirected after submit ──
    $pendingId = filter_var($_GET['pending'] ?? 0, FILTER_VALIDATE_INT);
    $pendingOv = null;
    if ($pendingId) {
        $p = db()->prepare("SELECT * FROM pending_gate_overrides WHERE id=? LIMIT 1");
        $p->execute([$pendingId]);
        $pendingOv = $p->fetch();
    }

    pageHeader('Remote Gate Override', 'security');
    renderHeader('🚨 Remote Gate Override', 'security.php?action=menu');
    ?>
    <div class="container" style="max-width:540px;">
      <?= getFlash() ?>

      <!-- Pending override status -->
      <?php if ($pendingOv): ?>
      <?php
        $statusColors = ['pending'=>'#ffc107','executed'=>'#28a745','failed'=>'#dc3545','expired'=>'#aaa'];
        $statusIcons  = ['pending'=>'⏳','executed'=>'✅','failed'=>'❌','expired'=>'⏰'];
        $ovStatus     = $pendingOv['status'];
        $ovColor      = $statusColors[$ovStatus] ?? '#999';
        $ovIcon       = $statusIcons[$ovStatus]  ?? '?';
      ?>
      <div class="card" style="border-left:4px solid <?= $ovColor ?>;margin-bottom:16px;">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
          <div>
            <strong><?= $ovIcon ?> Override #<?= $pendingOv['id'] ?></strong>
            — <?= htmlspecialchars($pendingOv['gate'] === 'SSgate' ? 'Schoeman Street' : 'Church Street') ?>
            <div style="font-size:.85rem;color:#666;margin-top:3px;">
              <?= htmlspecialchars($pendingOv['reason']) ?>
            </div>
            <?php if ($pendingOv['result_msg']): ?>
            <div style="font-size:.82rem;color:<?= $ovColor ?>;margin-top:3px;">
              <?= htmlspecialchars($pendingOv['result_msg']) ?>
            </div>
            <?php endif; ?>
          </div>
          <span class="badge badge-<?= $ovStatus==='executed'?'success':($ovStatus==='pending'?'warning':'danger') ?>">
            <?= strtoupper($ovStatus) ?>
          </span>
        </div>
        <?php if ($ovStatus === 'pending'): ?>
        <div style="margin-top:10px;font-size:.85rem;color:#888;">
          ⏳ Waiting for gate controller response…
          <a href="security.php?action=gate_override&pending=<?= $pendingOv['id'] ?>"
             style="margin-left:8px;color:var(--accent);">Refresh</a>
        </div>
        <meta http-equiv="refresh" content="10;url=security.php?action=gate_override&pending=<?= $pendingOv['id'] ?>">
        <?php endif; ?>
      </div>
      <?php endif; ?>

      <?php if ($overrideCount >= 5): ?>
      <div class="alert alert-danger">
        ⛔ Rate limit reached — <?= $overrideCount ?>/5 overrides used this hour.
        Please wait before making another override.
      </div>
      <?php else: ?>

      <div class="alert alert-warning" style="font-size:.88rem;">
        ⚠️ <strong>This action opens a physical gate remotely.</strong><br>
        Every override is permanently logged and reported to the administrator.
        <?php if ($overrideCount > 0): ?>
          <br><strong><?= $overrideCount ?>/5</strong> override(s) used this hour.
        <?php endif; ?>
      </div>

      <div class="card">
        <form method="POST" action="security.php?action=gate_override"
              onsubmit="return confirm('Open the gate remotely? This action is permanently logged.')">
          <?= csrfField() ?>

          <div class="form-group">
            <label>Gate to Open *</label>
            <select name="gate" style="font-size:1rem;padding:10px;">
              <option value="SSgate">🚗 Schoeman Street Gate</option>
              <option value="CSgate">🚗 Church Street Gate</option>
            </select>
          </div>

          <div class="form-group">
            <label>Linked Resident Erf
              <small style="color:#999;">(optional — for notification)</small>
            </label>
            <input type="text" name="resident_erfno"
                   placeholder="e.g. E15227"
                   style="text-transform:uppercase;"
                   oninput="this.value=this.value.toUpperCase()">
            <small style="color:#888;">Resident will be notified by email if provided.</small>
          </div>

          <div class="form-group">
            <label>Reason for Override * <small style="color:#999;">(min 10 characters)</small></label>
            <textarea name="reason" required minlength="10" rows="3"
                      placeholder="e.g. Resident requested emergency access for medical personnel"
                      style="width:100%;padding:10px;border:1px solid #dee2e6;
                             border-radius:6px;resize:vertical;font-size:.95rem;"></textarea>
          </div>

          <button type="submit" class="btn btn-danger btn-block"
                  style="font-size:1.1rem;padding:16px;">
            🚨 Open Gate Remotely
          </button>
        </form>
        <div class="popia-notice" style="margin-top:12px;">
          All remote overrides are permanently logged per POPIA §11 and reported to the administrator.
        </div>
      </div>
      <?php endif; ?>

    </div>
    <?php pageFooter(); exit; ?>
<?php } // end gate_override


// ── QR LOOKUP ─────────────────────────────────────────────
if ($action === 'qr') {
    $found = null;
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $code = strtoupper(trim($_POST['qr_code'] ?? ''));
        $stmt = db()->prepare("SELECT * FROM visitors WHERE code=?");
        $stmt->execute([$code]);
        $vis = $stmt->fetch();
        if ($vis) {
            $found = ['type' => 'Visitor', 'data' => $vis];
        } else {
            $stmt = db()->prepare("SELECT * FROM service_providers WHERE unique_code=?");
            $stmt->execute([$code]);
            $sp = $stmt->fetch();
            if ($sp) $found = ['type' => 'Service Provider', 'data' => $sp];
        }
    }
    pageHeader('QR Lookup', 'security');
    renderHeader('🔍 QR Code Lookup', 'security.php?action=menu');
    ?>
    <div class="container">
      <div class="card">
        <form method="POST" style="display:flex;gap:8px;">
          <?= csrfField() ?>
          <div class="form-group" style="flex:1;margin:0;">
            <input type="text" name="qr_code" placeholder="Enter 6-digit code (3XXXXX or 7XXXXX)" required
                   style="font-family:monospace;font-size:1.1rem;letter-spacing:0.1em;" maxlength="6" inputmode="numeric">
          </div>
          <button type="submit" class="btn btn-primary">Lookup</button>
        </form>
      </div>
      <?php if ($found): ?>
      <div class="card">
        <div class="card-title"><?= $found['type'] ?></div>
        <?php foreach ($found['data'] as $k => $v):
          if (!$v || in_array($k, ['id','pin','pin_hash'])) continue; ?>
        <div style="display:flex;gap:8px;padding:4px 0;border-bottom:1px solid #eee;font-size:.88rem;">
          <div style="min-width:130px;color:#666;"><?= htmlspecialchars(ucwords(str_replace('_',' ',$k))) ?></div>
          <div><?= htmlspecialchars($v) ?></div>
        </div>
        <?php endforeach; ?>
      </div>
      <?php elseif ($_SERVER['REQUEST_METHOD'] === 'POST'): ?>
      <div class="alert alert-danger">Code not found in system.</div>
      <?php endif; ?>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end qr

// ── RESET PASSWORD ────────────────────────────────────────
if ($action === 'reset') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $new = trim($_POST['new_password']     ?? '');
        $con = trim($_POST['confirm_password'] ?? '');
        if (strlen($new) < 8)  { setFlash('error', 'Minimum 8 characters.'); }
        elseif ($new !== $con) { setFlash('error', 'Passwords do not match.'); }
        else {
            db()->prepare("UPDATE security_users SET pin=?, password_changed_at=NOW() WHERE id=?")
                ->execute([password_hash($new, PASSWORD_BCRYPT), $_SESSION['security_id']]);
            setFlash('success', 'Password updated.');
            header('Location: security.php?action=menu'); exit;
        }
    }
    pageHeader('Reset Password', 'security');
    renderHeader('🔑 Change Password', 'security.php?action=menu');
    ?>
    <div class="container" style="max-width:420px;">
      <div class="card">
        <?= getFlash() ?>
        <form method="POST">
          <?= csrfField() ?>
          <div class="form-group"><label>New Password (min 8 characters)</label><input type="password" name="new_password" required minlength="8"></div>
          <div class="form-group"><label>Confirm</label><input type="password" name="confirm_password" required minlength="8"></div>
          <button type="submit" class="btn btn-primary btn-block">Update</button>
        </form>
      </div>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end reset

header('Location: security.php?action=menu'); exit;

// ════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════
function securityGrantAccess(array $sec): void {
    // 30-day password rotation: NULL or older than 30 days = expired.
    $changed = $sec['password_changed_at'] ?? null;
    if (empty($changed) || strtotime($changed) < strtotime('-30 days')) {
        $_SESSION['sec_login_step']    = 'reset';
        $_SESSION['sec_pending_id']    = $sec['id'];
        $_SESSION['sec_force_expired'] = true;
        header('Location: security.php?action=login'); exit;
    }
    session_regenerate_id(true);
    $_SESSION['security_id']   = $sec['id'];
    $_SESSION['security_name'] = $sec['name'];
    $_SESSION['last_activity'] = time();
    unset($_SESSION['sec_login_step'], $_SESSION['sec_pending_id'], $_SESSION['sec_pending_phone']);
    header('Location: security.php?action=menu');
}

function generateSpQr(int $spId): void {
    $qrLib = __DIR__ . '/phpqrcode/qrlib.php';
    if (!file_exists($qrLib)) return;
    require_once $qrLib;
    $row = db()->prepare("SELECT unique_code FROM service_providers WHERE id=? LIMIT 1");
    $row->execute([$spId]);
    $row = $row->fetch();
    if (!$row) return;
    $code      = $row['unique_code'];
    $verifyUrl = SITE_URL . '/service_qr_verify.php?code=' . urlencode($code);
    $tempDir   = __DIR__ . '/temp';
    if (!is_dir($tempDir)) @mkdir($tempDir, 0755, true);
    $filePath  = $tempDir . '/' . $code . '.png';
    QRcode::png($verifyUrl, $filePath, QR_ECLEVEL_M, 6, 2);
    if (file_exists($filePath)) {
        db()->prepare("UPDATE service_providers SET qrcode=? WHERE id=?")->execute(['/temp/'.$code.'.png', $spId]);
    }
}