<?php
// ============================================================
// GEMB Access Control — resident.php
// Handles login (with device token + OTP + PIN reset) and
// all resident portal actions: menu, visitors, vehicles,
// helpdesk, reset password
// Note: Comms/Notices removed — Phase 2 bolt-on
// ============================================================
require_once __DIR__ . '/layout.php';
if (session_status() === PHP_SESSION_NONE) session_start();

$action = $_GET['action'] ?? 'login';

// ── Already logged in — skip login ───────────────────────
if ($action === 'login' && !empty($_SESSION['resident_id'])) {
    header('Location: resident.php?action=menu'); exit;
}

// ── AJAX: get occupants for erf (used by login dropdown) ─
if ($action === 'get_occupants') {
    header('Content-Type: application/json');
    $erf  = strtoupper(preg_replace('/[^A-Z0-9]/i', '',
                       trim($_GET['erf'] ?? '')));
    if (!$erf) { echo '[]'; exit; }

    $stmt = db()->prepare("
        SELECT occupant_code AS code,
               resident_name AS name,
               occupant_type AS type,
               status
        FROM residents
        WHERE UPPER(resident_erfno) = ?
          AND status = 'active'
        ORDER BY occupant_code ASC
    ");
    $stmt->execute([$erf]);
    $rows = $stmt->fetchAll();

    // Return code, name, type — never PIN or device token
    echo json_encode(array_map(function($r) {
        return [
            'code' => $r['code'],
            'name' => $r['name'],
            'type' => ucfirst(str_replace('_', ' ', $r['type'])),
        ];
    }, $rows));
    exit;
}

// ════════════════════════════════════════════════════════
// LOGIN  (action=login)
// Three steps: login → otp → reset
// ════════════════════════════════════════════════════════
if ($action === 'login') {

    /* Device token — persistent 10-year cookie */
    if (empty($_COOKIE['gemb_device'])) {
        $tok = bin2hex(random_bytes(24));
        setcookie('gemb_device', $tok, time() + (10 * 365 * 24 * 60 * 60), '/', '', true, true);
        $_COOKIE['gemb_device'] = $tok;
    }
    $deviceToken = $_COOKIE['gemb_device'];

    $step  = $_SESSION['login_step'] ?? 'credentials';
    $error = '';

    /* Cancel OTP — clear and restart */
    if (isset($_GET['cancel'])) {
        session_unset(); session_destroy();
        header('Location: resident.php?action=login'); exit;
    }
    /* OTP failure redirect */
    if (isset($_GET['err']) && $_GET['err'] === 'otp') {
        $error = 'Incorrect OTP. For security your session has been reset. Please try again.';
        $step  = 'credentials';
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {

        /* ── Step 1: Erf + Occupant Code + PIN ── */
        if ($step === 'credentials'
            && isset($_POST['erf_number'], $_POST['pin'])) {

            $erf  = strtoupper(preg_replace('/[^A-Z0-9]/i', '',
                               trim($_POST['erf_number'])));
            $code = strtoupper(trim($_POST['occupant_code'] ?? 'A'));
            $pin  = trim($_POST['pin']);

            // Fallback: if code empty default to A
            if (!preg_match('/^[A-Z]$/', $code)) $code = 'A';

            $identifier = $erf . $code;  // e.g. E12345A

            /* ── Brute force check ── */
            $lockCheck = bfIsLocked('resident', $identifier);
            if ($lockCheck['locked']) {
                $error = bfLockoutMessage($lockCheck);
            } elseif (!preg_match('/^\d{4}$/', $pin)) {
                $error = 'PIN must be exactly 4 digits.';
            } else {
                $res = db()->prepare(
                    "SELECT id, resident_name, address, resident_erfno,
                            occupant_code, occupant_type, is_primary,
                            phone, email, pin_hash, device_token, status
                     FROM residents
                     WHERE UPPER(resident_erfno) = ?
                       AND UPPER(occupant_code)  = ?
                       AND status = 'active'
                     LIMIT 1"
                );
                $res->execute([$erf, $code]);
                $res = $res->fetch();

                if (!$res) {
                    bfRecordFailure('resident', $identifier);
                    $remaining = bfAttemptsRemaining('resident', $identifier);
                    $error = 'Erf/occupant code not found or inactive.'
                           . ($remaining <= 2
                               ? ' ' . bfWarningMessage($remaining)
                               : '');
                } elseif (!password_verify($pin, $res['pin_hash'])) {
                    bfRecordFailure('resident', $identifier);
                    $remaining = bfAttemptsRemaining('resident', $identifier);
                    $error = 'Incorrect PIN.'
                           . ($remaining <= 2
                               ? ' ' . bfWarningMessage($remaining)
                               : '');
                } else {
                    /* ── PIN correct — clear attempts ── */
                    bfClearAttempts('resident', $identifier);

                    if (empty($res['device_token'])) {
                        db()->prepare("UPDATE residents SET device_token=? WHERE id=?")
                            ->execute([hashDeviceToken($deviceToken), $res['id']]);
                        residentGrantAccess($res); exit;
                    } elseif (hash_equals($res['device_token'], hashDeviceToken($deviceToken))) {
                        residentGrantAccess($res); exit;
                    } else {
                        $_SESSION['login_step']    = 'otp';
                        $_SESSION['pending_id']    = $res['id'];
                        $_SESSION['pending_erf']   = $res['resident_erfno'];
                        $_SESSION['pending_phone'] = $res['phone'];
                        $_SESSION['pending_email'] = $res['email'] ?? '';
                        require_once __DIR__ . '/twilio_helper.php';
                        generateOtp($res['phone'], $res['email'] ?? '');
                        header('Location: resident.php?action=login'); exit;
                    }
                }
            }
        }

        /* ── Step 2: OTP ── */
        elseif ($step === 'otp' && isset($_POST['otp'])) {
            $otp   = preg_replace('/\D/', '', trim($_POST['otp']));
            $phone = $_SESSION['pending_phone'] ?? '';
            require_once __DIR__ . '/twilio_helper.php';

            if (strlen($otp) !== 6) {
                $error = 'OTP must be 6 digits.';
            } elseif (!verifyOtp($phone, $otp)) {
                session_unset(); session_destroy();
                header('Location: resident.php?action=login&err=otp'); exit;
            } else {
                $_SESSION['login_step'] = 'reset';
                header('Location: resident.php?action=login'); exit;
            }
        }

        /* ── Step 3: New PIN + register device ── */
        elseif ($step === 'reset' && isset($_POST['new_pin'], $_POST['confirm_pin'])) {
            $newPin  = trim($_POST['new_pin']);
            $conPin  = trim($_POST['confirm_pin']);
            $pid     = (int)($_SESSION['pending_id'] ?? 0);

            if (!preg_match('/^\d{4}$/', $newPin)) {
                $error = 'PIN must be exactly 4 digits.';
            } elseif ($newPin !== $conPin) {
                $error = 'PINs do not match.';
            } elseif (!$pid) {
                session_unset(); session_destroy();
                header('Location: resident.php?action=login'); exit;
            } else {
                db()->prepare(
                    "UPDATE residents SET pin_hash=?, device_token=? WHERE id=?"
                )->execute([password_hash($newPin, PASSWORD_BCRYPT), hashDeviceToken($deviceToken), $pid]);

                $res = db()->prepare(
                    "SELECT id, resident_name, address, resident_erfno, phone,
                            pin_hash, device_token, status
                     FROM residents WHERE id=? LIMIT 1"
                );
                $res->execute([$pid]);
                residentGrantAccess($res->fetch());
                exit;
            }
        }
    }

    /* ── Masked phone for OTP screen ── */
    $maskedPhone = '';
    if ($step === 'otp' && !empty($_SESSION['pending_phone'])) {
        $p = preg_replace('/\D/', '', $_SESSION['pending_phone']);
        $maskedPhone = substr($p, 0, 4) . '***' . substr($p, -3);
    }

    /* ── Render login page ── */
    pageHeader('Resident Login', 'resident');
    ?>
    <div class="login-wrap">
      <div class="login-card">
        <div class="login-logo">🏠</div>
        <h2>Resident Portal</h2>
        <div class="subtitle">GEMB Estate</div>

        <?php if ($error): ?>
          <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <?php if ($step === 'credentials'): ?>
        <!-- Step 1: Erf Number + Occupant dropdown + PIN -->
        <form method="POST" action="resident.php?action=login" id="loginForm">
          <div class="form-group">
            <label>Erf Number</label>
            <input type="text" name="erf_number" id="erfInput" required
                   autocomplete="off"
                   style="text-transform:uppercase;font-size:1.1rem;
                          letter-spacing:0.1em;text-align:center;"
                   oninput="this.value=this.value.toUpperCase();loadOccupants(this.value)"
                   placeholder="e.g. E12345"
                   maxlength="10">
          </div>
          <div class="form-group" id="occupantGroup" style="display:none;">
            <label>Occupant</label>
            <select name="occupant_code" id="occupantSelect"
                    style="font-size:1rem;padding:10px 12px;">
              <option value="A">A — Loading…</option>
            </select>
          </div>
          <!-- Hidden fallback when only one occupant -->
          <input type="hidden" name="occupant_code" id="occupantHidden" value="A">
          <div class="form-group">
            <label>4-digit PIN</label>
            <input type="password" name="pin" required
                   style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;"
                   maxlength="4" pattern="\d{4}" inputmode="numeric"
                   autocomplete="current-password" placeholder="••••">
          </div>
          <button type="submit" class="btn btn-primary btn-block"
                  style="margin-top:8px;">
            Login
          </button>
        </form>
        <a href="forgot.php?role=resident"
           style="display:block;text-align:center;margin-top:14px;
                  font-size:.85rem;color:var(--muted);">
          Forgot PIN?
        </a>

        <script>
        let occupantTimer = null;

        function loadOccupants(erf) {
          clearTimeout(occupantTimer);
          if (erf.length < 2) {
            document.getElementById('occupantGroup').style.display  = 'none';
            document.getElementById('occupantHidden').disabled      = false;
            return;
          }
          occupantTimer = setTimeout(() => {
            fetch('resident.php?action=get_occupants&erf=' + encodeURIComponent(erf))
              .then(r => r.json())
              .then(data => {
                const grp    = document.getElementById('occupantGroup');
                const sel    = document.getElementById('occupantSelect');
                const hidden = document.getElementById('occupantHidden');

                if (!data.length) {
                  grp.style.display    = 'none';
                  hidden.disabled      = false;
                  hidden.value         = 'A';
                  return;
                }

                if (data.length === 1) {
                  // Only one occupant — no need to show dropdown
                  grp.style.display    = 'none';
                  hidden.disabled      = false;
                  hidden.value         = data[0].code;
                } else {
                  // Multiple occupants — show dropdown
                  grp.style.display    = 'block';
                  hidden.disabled      = true;   // dropdown takes over
                  sel.innerHTML        = '';
                  data.forEach(o => {
                    const opt      = document.createElement('option');
                    opt.value      = o.code;
                    opt.textContent = o.code + ' — ' + o.name
                                   + ' (' + o.type + ')';
                    sel.appendChild(opt);
                  });
                }
              })
              .catch(() => {
                document.getElementById('occupantGroup').style.display = 'none';
              });
          }, 400);  // debounce 400ms
        }
        </script>

        <?php elseif ($step === 'otp'): ?>
        <!-- Step 2: OTP -->
        <div class="alert alert-info" style="font-size:.88rem;">
          📧 <strong>New device detected.</strong><br><br>
          <?php
          $pendingEmail = $_SESSION['pending_email'] ?? '';
          if ($pendingEmail) {
              $parts  = explode('@', $pendingEmail);
              $masked = substr($parts[0], 0, 2) . str_repeat('*', max(2, strlen($parts[0]) - 2))
                      . '@' . ($parts[1] ?? '');
              echo 'A <strong>6-digit OTP</strong> has been sent to <strong>'
                   . htmlspecialchars($masked) . '</strong>.';
          } else {
              echo 'No email address is on file for this account. '
                   . 'Please contact the administrator to add your email address.';
          }
          ?><br>
          Enter the code below to verify your identity.
        </div>
        <form method="POST" action="resident.php?action=login">
          <div class="form-group">
            <label>6-digit OTP</label>
            <input type="text" name="otp" required autofocus
                   style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;"
                   maxlength="6" pattern="\d{6}" inputmode="numeric"
                   placeholder="_ _ _ _ _ _">
          </div>
          <button type="submit" class="btn btn-primary btn-block">Verify OTP</button>
        </form>
        <a href="resident.php?action=login&cancel=1"
           style="display:block;text-align:center;margin-top:14px;
                  font-size:.85rem;color:var(--muted);">
          ← Cancel and start over
        </a>

        <?php elseif ($step === 'reset'): ?>
        <!-- Step 3: New PIN -->
        <div class="alert alert-success" style="font-size:.88rem;">
          ✅ Identity verified. Please set a new PIN for this device.
        </div>
        <form method="POST" action="resident.php?action=login">
          <div class="form-group">
            <label>New 6-digit OTP</label>
            <input type="password" name="new_pin" required autofocus
                   style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;"
                   maxlength="4" pattern="\d{4}" inputmode="numeric"
                   placeholder="••••">
          </div>
          <div class="form-group">
            <label>Confirm PIN</label>
            <input type="password" name="confirm_pin" required
                   style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;"
                   maxlength="4" pattern="\d{4}" inputmode="numeric"
                   placeholder="••••">
          </div>
          <button type="submit" class="btn btn-primary btn-block">
            Save PIN &amp; Login
          </button>
        </form>
        <?php endif; ?>

        <div class="popia-notice">
          Your personal information is processed under POPIA §11 for estate
          security and management purposes.
        </div>
      </div>
    </div>
    <?php
    pageFooter(); exit;
}

// ════════════════════════════════════════════════════════
// ALL OTHER ACTIONS — require login
// ════════════════════════════════════════════════════════
requireResident();

$rid   = $_SESSION['resident_id'];
$rname = $_SESSION['resident_name'];
$rerf  = $_SESSION['resident_erf'] ?? '';

// ── MENU ─────────────────────────────────────────────────
if ($action === 'menu') {
    pageHeader('Resident Menu', 'resident');
    renderHeader('🏠 ' . ($_SESSION['resident_login'] ?? $rerf . 'A') . ' — ' . $rname, 'logout.php');
    ?>
    <div class="container">
      <?= getFlash() ?>
      <div class="menu-grid">
        <a href="visitor.php?action=select" class="menu-btn">
          <span class="icon">👤</span>My Visitors
        </a>
        <a href="resident.php?action=vehicles" class="menu-btn">
          <span class="icon">🚗</span>My Vehicles
        </a>
        <a href="request_new.php" class="menu-btn">
          <span class="icon">📝</span>New Request
        </a>
        <a href="agent_invite.php" class="menu-btn">
          <span class="icon">🏢</span>Invite Agent
        </a>
        <a href="document_archive.php" class="menu-btn">
          <span class="icon">📄</span>Estate Documents
        </a>
        <a href="resident.php?action=helpdesk" class="menu-btn">
          <span class="icon">🔧</span>Report Fault
        </a>
        <a href="resident.php?action=reset" class="menu-btn">
          <span class="icon">🔑</span>Change PIN
        </a>
        <a href="logout.php" class="menu-btn">
          <span class="icon">🚪</span>Logout
        </a>
      </div>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end action


// ── VEHICLES ──────────────────────────────────────────────
if ($action === 'vehicles') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $act = $_POST['vact'] ?? '';
        if ($act === 'add') {
            $plate = strtoupper(trim($_POST['plate'] ?? ''));
            $desc  = trim($_POST['description'] ?? '');
            if ($plate) {
                db()->prepare(
                    "INSERT INTO resident_vehicles (resident_id,plate,description) VALUES (?,?,?)"
                )->execute([$rid, $plate, $desc]);
                setFlash('success', 'Vehicle added.');
            }
        } elseif ($act === 'delete') {
            db()->prepare(
                "DELETE FROM resident_vehicles WHERE id=? AND resident_id=?"
            )->execute([(int)$_POST['vid'], $rid]);
            setFlash('success', 'Vehicle removed.');
        }
        header('Location: resident.php?action=vehicles'); exit;
    }
    $stmt = db()->prepare(
        "SELECT * FROM resident_vehicles WHERE resident_id=? ORDER BY created_at DESC"
    );
    $stmt->execute([$rid]);
    $vehicles = $stmt->fetchAll();

    pageHeader('My Vehicles', 'resident');
    renderHeader('🚗 My Vehicles', 'resident.php?action=menu');
    ?>
    <div class="container">
      <?= getFlash() ?>
      <div class="card">
        <div class="card-title">Registered Vehicles (LPR Gate Access)</div>
        <?php if (empty($vehicles)): ?>
          <p style="color:#666;font-size:.9rem;">No vehicles registered yet.</p>
        <?php else: foreach ($vehicles as $v): ?>
        <div style="display:flex;justify-content:space-between;align-items:center;
                    padding:10px 0;border-bottom:1px solid #eee;">
          <div>
            <strong><?= htmlspecialchars($v['plate']) ?></strong>
            <?php if ($v['description']): ?>
              <span style="color:#666;font-size:.85rem;"> — <?= htmlspecialchars($v['description']) ?></span>
            <?php endif; ?>
          </div>
          <form method="POST" onsubmit="return confirm('Remove this vehicle?')">
            <?= csrfField() ?>
            <input type="hidden" name="vact" value="delete">
            <input type="hidden" name="vid"  value="<?= $v['id'] ?>">
            <button class="btn btn-danger btn-sm">Remove</button>
          </form>
        </div>
        <?php endforeach; endif; ?>
      </div>
      <div class="card">
        <div class="card-title">Add Vehicle</div>
        <form method="POST">
          <?= csrfField() ?>
          <input type="hidden" name="vact" value="add">
          <div class="form-group">
            <label>Plate Number *</label>
            <input type="text" name="plate" required
                   style="text-transform:uppercase;" placeholder="e.g. CBS 10009">
          </div>
          <div class="form-group">
            <label>Description (optional)</label>
            <input type="text" name="description" placeholder="e.g. Silver Toyota Hilux">
          </div>
          <button type="submit" class="btn btn-primary">Add Vehicle</button>
        </form>
      </div>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end action

// ── HELPDESK ──────────────────────────────────────────────
if ($action === 'helpdesk') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        db()->prepare(
            "INSERT INTO helpdesk
               (resident_erfno, resident_name, category, subject, description, priority)
             VALUES (?,?,?,?,?,?)"
        )->execute([
            $rerf, $rname,
            trim($_POST['category']),
            trim($_POST['subject']),
            trim($_POST['description']),
            $_POST['priority'] ?? 'normal',
        ]);
        setFlash('success', 'Fault report submitted. The management team will follow up.');
        header('Location: resident.php?action=helpdesk'); exit;
    }
    $tickets = db()->prepare(
        "SELECT * FROM helpdesk WHERE resident_erfno=? ORDER BY created_at DESC LIMIT 20"
    );
    $tickets->execute([$rerf]);
    $tickets = $tickets->fetchAll();

    pageHeader('Report Fault', 'resident');
    renderHeader('🔧 Report a Fault', 'resident.php?action=menu');
    ?>
    <div class="container">
      <?= getFlash() ?>
      <div class="card">
        <div class="card-title">Submit New Report</div>
        <form method="POST">
          <?= csrfField() ?>
          <div class="form-group">
            <label>Category</label>
            <select name="category" required>
              <option value="">— Select —</option>
              <option>Security concern</option>
              <option>Gate malfunction</option>
              <option>Road / infrastructure</option>
              <option>Lighting</option>
              <option>Noise complaint</option>
              <option>Other</option>
            </select>
          </div>
          <div class="form-group">
            <label>Subject *</label>
            <input type="text" name="subject" required placeholder="Brief summary">
          </div>
          <div class="form-group">
            <label>Priority</label>
            <select name="priority">
              <option value="low">Low</option>
              <option value="normal" selected>Normal</option>
              <option value="high">High</option>
              <option value="urgent">Urgent</option>
            </select>
          </div>
          <div class="form-group">
            <label>Description *</label>
            <textarea name="description" rows="4" required
                      placeholder="Describe the issue in detail…"></textarea>
          </div>
          <button type="submit" class="btn btn-primary">Submit Report</button>
        </form>
      </div>
      <?php if (!empty($tickets)): ?>
      <div class="card">
        <div class="card-title">My Previous Reports</div>
        <?php foreach ($tickets as $t): ?>
        <div style="padding:10px 0;border-bottom:1px solid #eee;">
          <div style="display:flex;justify-content:space-between;margin-bottom:4px;flex-wrap:wrap;gap:6px;">
            <strong style="font-size:.9rem;"><?= htmlspecialchars($t['subject']) ?></strong>
            <div style="display:flex;gap:6px;">
              <span class="badge badge-<?= $t['priority']==='urgent'?'danger':($t['priority']==='high'?'warning':'info') ?>">
                <?= $t['priority'] ?>
              </span>
              <span class="badge badge-<?= $t['status']==='open'?'warning':($t['status']==='resolved'?'success':'muted') ?>">
                <?= $t['status'] ?>
              </span>
            </div>
          </div>
          <div style="font-size:.85rem;color:#444;"><?= htmlspecialchars($t['description']) ?></div>
          <?php if ($t['response']): ?>
          <div style="font-size:.82rem;color:#1565c0;margin-top:4px;padding:6px 8px;
                      background:#e8f0fe;border-radius:4px;">
            💬 <?= htmlspecialchars($t['response']) ?>
          </div>
          <?php endif; ?>
          <div style="font-size:.75rem;color:#999;margin-top:4px;">
            <?= date('d M Y H:i', strtotime($t['created_at'])) ?>
          </div>
        </div>
        <?php endforeach; ?>
      </div>
      <?php endif; ?>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end action

// ── CHANGE PIN (when already logged in) ───────────────────
if ($action === 'reset') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $new = trim($_POST['new_password'] ?? '');
        $con = trim($_POST['confirm_password'] ?? '');
        if (!preg_match('/^\d{4}$/', $new)) {
            setFlash('error', 'PIN must be exactly 4 digits.');
        } elseif ($new !== $con) {
            setFlash('error', 'PINs do not match.');
        } else {
            db()->prepare("UPDATE residents SET pin_hash=? WHERE id=?")
                ->execute([password_hash($new, PASSWORD_BCRYPT), $rid]);
            setFlash('success', 'PIN updated successfully.');
            header('Location: resident.php?action=menu'); exit;
        }
    }
    pageHeader('Change PIN', 'resident');
    renderHeader('🔑 Change PIN', 'resident.php?action=menu');
    ?>
    <div class="container" style="max-width:420px;">
      <div class="card">
        <?= getFlash() ?>
        <form method="POST">
          <?= csrfField() ?>
          <div class="form-group">
            <label>New 4-digit PIN</label>
            <input type="password" name="new_password" required
                   style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;"
                   maxlength="4" pattern="\d{4}" inputmode="numeric" placeholder="••••">
          </div>
          <div class="form-group">
            <label>Confirm PIN</label>
            <input type="password" name="confirm_password" required
                   style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;"
                   maxlength="4" pattern="\d{4}" inputmode="numeric" placeholder="••••">
          </div>
          <button type="submit" class="btn btn-primary btn-block">Update PIN</button>
        </form>
      </div>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end action

// ── Fallback ──────────────────────────────────────────────
header('Location: resident.php?action=menu'); exit;

// ════════════════════════════════════════════════════════
// HELPER
// ════════════════════════════════════════════════════════
function residentGrantAccess(array $res): void {
    session_regenerate_id(true);
    $_SESSION['resident_logged_in'] = true;
    $_SESSION['resident_id']        = $res['id'];
    $_SESSION['resident_name']      = $res['resident_name'];
    $_SESSION['resident_erf']       = $res['resident_erfno'];
    $_SESSION['user_address']       = $res['address'];
    $_SESSION['last_activity']      = time();
    unset($_SESSION['login_step'], $_SESSION['pending_id'],
          $_SESSION['pending_erf'], $_SESSION['pending_phone']);
    header('Location: resident.php?action=menu');
}
