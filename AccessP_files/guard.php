<?php
// ============================================================
// GEMB Access Control — guard.php
// Actions: login | verify | reset
//
// Gate points:
//   SSgate: SS_CAR_IN1, SS_CAR_IN2, SS_CAR_OUT, SS_TURN
//   CSgate: CS_CAR_IN,  CS_CAR_OUT,  CS_CONT,   CS_TURN
//
// Entry/Exit rules:
//   Residents    — always permitted, any time, any direction
//   Visitors     — permitted within visit_date / visit_date_to
//   Service Prov — permitted within start_date/end_date +
//                  access_days + access_start/access_end
// ============================================================
require_once __DIR__ . '/layout.php';
require_once __DIR__ . '/twilio_helper.php';
require_once __DIR__ . '/totp_lib.php';
if (session_status() === PHP_SESSION_NONE) session_start();

$action = $_GET['action'] ?? 'login';

if ($action === 'login' && !empty($_SESSION['guard_id'])) {
    header('Location: guard.php?action=verify'); exit;
}

// ── Gate point definitions ────────────────────────────────
const GATE_POINTS = [
    'SSgate' => [
        'SS_CAR_IN1' => ['label' => '🚗 Schoeman — Car Entry 1',       'directions' => ['ENTRY']],
        'SS_CAR_IN2' => ['label' => '🚗 Schoeman — Car Entry 2',       'directions' => ['ENTRY']],
        'SS_CAR_OUT' => ['label' => '🚗 Schoeman — Car Exit',          'directions' => ['EXIT']],
        'SS_TURN'    => ['label' => '🚶 Schoeman — Pedestrian Turnstile','directions' => ['ENTRY','EXIT']],
    ],
    'CSgate' => [
        'CS_CAR_IN'  => ['label' => '🚗 Church — Car Entry',           'directions' => ['ENTRY']],
        'CS_CAR_OUT' => ['label' => '🚗 Church — Car Exit',            'directions' => ['EXIT']],
        'CS_CONT'    => ['label' => '👷 Church — Contractor Gate',      'directions' => ['ENTRY','EXIT']],
        'CS_TURN'    => ['label' => '🚶 Church — Pedestrian Turnstile', 'directions' => ['ENTRY','EXIT']],
    ],
];

// ════════════════════════════════════════════════════════
// LOGIN  (3-step: credentials → otp → reset)
// Extended: guard now also selects gate point on login
// ════════════════════════════════════════════════════════
if ($action === 'login') {

    if (empty($_COOKIE['gemb_guard_device'])) {
        $tok = bin2hex(random_bytes(24));
        setcookie('gemb_guard_device', $tok,
            time() + (10 * 365 * 24 * 60 * 60), '/', '', true, true);
        $_COOKIE['gemb_guard_device'] = $tok;
    }
    $deviceToken = $_COOKIE['gemb_guard_device'];
    $step  = $_SESSION['guard_login_step'] ?? 'credentials';
    $error = '';

    if (isset($_GET['cancel'])) {
        session_unset(); session_destroy();
        header('Location: guard.php?action=login'); exit;
    }
    if (isset($_GET['err']) && $_GET['err'] === 'otp') {
        $error = 'Incorrect OTP. Session reset. Please try again.';
        $step  = 'credentials';
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {

        // ── Step 1: credentials + gate + gate_point ───────
        if ($step === 'credentials'
            && isset($_POST['username'], $_POST['password'])) {

            $user       = trim($_POST['username']);
            $pass       = $_POST['password'];
            $gate       = $_POST['gate']       ?? 'SSgate';
            $gate_point = $_POST['gate_point'] ?? '';

            $lockCheck = bfIsLocked('guard', $user);
            if ($lockCheck['locked']) {
                $error = bfLockoutMessage($lockCheck);
            } else {
                $stmt = db()->prepare(
                    "SELECT id, name, username, pin, phone, device_token, gate,
                            totp_secret, totp_confirmed
                     FROM guards WHERE username = ? LIMIT 1"
                );
                $stmt->execute([$user]);
                $guard = $stmt->fetch();

                if (!$guard || !password_verify($pass, $guard['pin'])) {
                    bfRecordFailure('guard', $user);
                    $remaining = bfAttemptsRemaining('guard', $user);
                    $error = 'Invalid username or PIN.'
                           . ($remaining <= 2
                               ? ' ' . bfWarningMessage($remaining) : '');
                } else {
                    bfClearAttempts('guard', $user);

                    // Validate gate_point belongs to gate
                    $validPoints = array_keys(GATE_POINTS[$gate] ?? []);
                    if (!in_array($gate_point, $validPoints)) {
                        $gate_point = $validPoints[0] ?? '';
                    }

                    // Persist gate_point to DB for this guard
                    db()->prepare(
                        "UPDATE guards SET gate=?, gate_point=? WHERE id=?"
                    )->execute([$gate, $gate_point, $guard['id']]);

                    if (empty($guard['device_token'])) {
                        db()->prepare(
                            "UPDATE guards SET device_token=? WHERE id=?"
                        )->execute([hashDeviceToken($deviceToken), $guard['id']]);
                        guardGrantAccess($guard, $gate, $gate_point); exit;
                    } elseif (hash_equals($guard['device_token'], hashDeviceToken($deviceToken))) {
                        guardGrantAccess($guard, $gate, $gate_point); exit;
                    } else {
                        $_SESSION['guard_login_step']   = 'otp';
                        $_SESSION['guard_pending_id']   = $guard['id'];
                        $_SESSION['guard_pending_gate'] = $gate;
                        $_SESSION['guard_pending_gp']   = $gate_point;
                        header('Location: guard.php?action=login'); exit;
                    }
                }
            }
        }

        // ── Step 2: TOTP (authenticator app) — enrol or verify ──
        // Previously this compared against the last 6 digits of the
        // guard's own phone number. That's not a secret and isn't
        // one-time. TOTP is used here (not emailed OTP, like Admin/
        // Security/Resident) specifically because it verifies with pure
        // local arithmetic — no network call — which is required for
        // this same check to also work on the offline Pi gate node
        // (see pi/verify.php and totp_lib.php's header comment).
        elseif ($step === 'otp' && isset($_POST['totp'])) {
            $pid = (int)($_SESSION['guard_pending_id'] ?? 0);
            $g = $pid ? db()->prepare(
                "SELECT id, totp_secret, totp_confirmed FROM guards WHERE id=? LIMIT 1"
            ) : null;
            if ($g) { $g->execute([$pid]); $g = $g->fetch(); }

            if (!$g || empty($g['totp_secret'])) {
                session_unset(); session_destroy();
                header('Location: guard.php?action=login'); exit;
            }

            if (gembTotpVerify($g['totp_secret'], trim($_POST['totp']))) {
                if (empty($g['totp_confirmed'])) {
                    db()->prepare("UPDATE guards SET totp_confirmed=1 WHERE id=?")->execute([$pid]);
                }
                $_SESSION['guard_login_step'] = 'reset';
                header('Location: guard.php?action=login'); exit;
            } else {
                session_unset(); session_destroy();
                header('Location: guard.php?action=login&err=otp'); exit;
            }
        }

        // ── Step 3: New PIN + register device ─────────────
        elseif ($step === 'reset'
                && isset($_POST['new_password'], $_POST['confirm_password'])) {
            $newPass = trim($_POST['new_password']);
            $conPass = trim($_POST['confirm_password']);
            $pid     = (int)($_SESSION['guard_pending_id']  ?? 0);
            $gate    = $_SESSION['guard_pending_gate'] ?? 'SSgate';
            $gp      = $_SESSION['guard_pending_gp']   ?? '';

            if (strlen($newPass) < 4) {
                $error = 'PIN must be at least 4 digits.';
            } elseif ($newPass !== $conPass) {
                $error = 'PINs do not match.';
            } elseif (!$pid) {
                session_unset(); session_destroy();
                header('Location: guard.php?action=login'); exit;
            } else {
                db()->prepare(
                    "UPDATE guards SET pin=?, device_token=?, gate=?, gate_point=?
                     WHERE id=?"
                )->execute([
                    password_hash($newPass, PASSWORD_BCRYPT),
                    hashDeviceToken($deviceToken), $gate, $gp, $pid
                ]);
                $guard = db()->prepare(
                    "SELECT id, name, username, pin, phone, device_token, gate
                     FROM guards WHERE id=? LIMIT 1"
                );
                $guard->execute([$pid]);
                guardGrantAccess($guard->fetch(), $gate, $gp);
                exit;
            }
        }
    }

    // ── TOTP enrolment/verification screen data ───────────
    // Fetch (and create, on first arrival) the pending guard's TOTP
    // secret so the render section below can show either the
    // one-time "scan this QR" enrolment screen or a plain 6-digit
    // code prompt for an already-enrolled guard.
    $totpSecret = '';
    $totpNeedsEnrolment = false;
    $totpQrDataUri = null;
    if ($step === 'otp') {
        $pid = (int)($_SESSION['guard_pending_id'] ?? 0);
        if (!$pid) {
            header('Location: guard.php?action=login'); exit;
        }
        $g = db()->prepare("SELECT id, username, totp_secret, totp_confirmed FROM guards WHERE id=? LIMIT 1");
        $g->execute([$pid]);
        $g = $g->fetch();
        if (!$g) {
            session_unset(); session_destroy();
            header('Location: guard.php?action=login'); exit;
        }

        if (empty($g['totp_secret'])) {
            $totpSecret = gembTotpGenerateSecret();
            db()->prepare("UPDATE guards SET totp_secret=?, totp_confirmed=0 WHERE id=?")
                ->execute([$totpSecret, $pid]);
            $totpNeedsEnrolment = true;
        } else {
            $totpSecret = $g['totp_secret'];
            $totpNeedsEnrolment = empty($g['totp_confirmed']);
        }

        if ($totpNeedsEnrolment) {
            $provisioningUri = gembTotpProvisioningUri($totpSecret, $g['username'], 'GEMB Guard');
            $qrLibPath = __DIR__ . '/phpqrcode/qrlib.php';
            if (file_exists($qrLibPath)) {
                require_once $qrLibPath;
                if (class_exists('QRcode')) {
                    ob_start();
                    QRcode::png($provisioningUri, false, QR_ECLEVEL_M, 5, 2);
                    $png = ob_get_clean();
                    $totpQrDataUri = 'data:image/png;base64,' . base64_encode($png);
                }
            }
        }
    }

    pageHeader('Guard Login', 'guard');
    ?>
    <div class="login-wrap">
      <div class="login-card">
        <div class="login-logo">🔐</div>
        <h2>Guard Login</h2>
        <div class="subtitle">Gate Access Verification</div>

        <?php if ($error): ?>
          <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <?php if ($step === 'credentials'): ?>
        <form method="POST" action="guard.php?action=login" id="loginForm">
          <?= csrfField() ?>

          <div class="form-group">
            <label>Username</label>
            <input type="text" name="username" required autocomplete="username">
          </div>
          <div class="form-group">
            <label>4-digit PIN</label>
            <input type="password" name="password" required
                   autocomplete="current-password" inputmode="numeric"
                   maxlength="4" pattern="\d{4}"
                   style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;">
          </div>

          <!-- Gate selection — drives gate_point options -->
          <div class="form-group">
            <label>Gate</label>
            <select name="gate" id="gateSelect"
                    onchange="updateGatePoints(this.value)"
                    style="font-size:1rem;">
              <option value="SSgate">Schoeman Street Gate</option>
              <option value="CSgate">Church Street Gate</option>
            </select>
          </div>

          <!-- Gate point — updated by JS when gate changes -->
          <div class="form-group">
            <label>Gate Point</label>
            <select name="gate_point" id="gatePointSelect"
                    style="font-size:.95rem;">
              <!-- populated by JS on load -->
            </select>
          </div>

          <button type="submit" class="btn btn-primary btn-block"
                  style="margin-top:8px;">Login</button>
        </form>

        <script>
        const gatePoints = <?= json_encode(array_map(
            fn($pts) => array_map(fn($p) => $p['label'], $pts),
            GATE_POINTS
        )) ?>;

        function updateGatePoints(gate) {
            const sel = document.getElementById('gatePointSelect');
            sel.innerHTML = '';
            const pts = gatePoints[gate] || {};
            Object.entries(pts).forEach(([code, label]) => {
                const opt = document.createElement('option');
                opt.value = code;
                opt.textContent = label;
                sel.appendChild(opt);
            });
        }
        updateGatePoints('SSgate');
        </script>

        <?php elseif ($step === 'otp' && $totpNeedsEnrolment): ?>
        <div class="alert alert-info" style="font-size:.88rem;">
          📱 <strong>New device detected — one-time authenticator setup.</strong><br><br>
          Scan this with an authenticator app (Google Authenticator, Authy,
          Microsoft Authenticator), or enter the key manually. Then type
          the 6-digit code it shows.
        </div>
        <?php if ($totpQrDataUri): ?>
          <img src="<?= $totpQrDataUri ?>" alt="QR code" style="display:block;margin:0 auto 14px;">
        <?php endif; ?>
        <p style="text-align:center;font-family:monospace;font-size:1.05rem;letter-spacing:2px;margin-bottom:14px;">
          <?= htmlspecialchars(chunk_split($totpSecret, 4, ' ')) ?>
        </p>
        <form method="POST" action="guard.php?action=login">
          <?= csrfField() ?>
          <div class="form-group">
            <label>6-digit code from your app</label>
            <input type="text" name="totp" required autofocus
                   style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;"
                   maxlength="6" pattern="\d{6}" inputmode="numeric"
                   placeholder="_ _ _ _ _ _">
          </div>
          <button type="submit" class="btn btn-primary btn-block">Confirm Setup &amp; Continue</button>
        </form>
        <a href="guard.php?action=login&cancel=1"
           style="display:block;text-align:center;margin-top:14px;
                  font-size:.85rem;color:var(--muted);">
          ← Cancel and start over
        </a>

        <?php elseif ($step === 'otp'): ?>
        <div class="alert alert-info" style="font-size:.88rem;">
          🔐 <strong>New device detected.</strong><br><br>
          Enter the 6-digit code from your authenticator app.
        </div>
        <form method="POST" action="guard.php?action=login">
          <?= csrfField() ?>
          <div class="form-group">
            <label>6-digit code</label>
            <input type="text" name="totp" required autofocus
                   style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;"
                   maxlength="6" pattern="\d{6}" inputmode="numeric"
                   placeholder="_ _ _ _ _ _">
          </div>
          <button type="submit" class="btn btn-primary btn-block">Verify &amp; Log In</button>
        </form>
        <a href="guard.php?action=login&cancel=1"
           style="display:block;text-align:center;margin-top:14px;
                  font-size:.85rem;color:var(--muted);">
          ← Cancel and start over
        </a>

        <?php elseif ($step === 'reset'): ?>
        <div class="alert alert-success" style="font-size:.88rem;">
          ✅ Identity verified. Set a new 4-digit PIN for this device.
        </div>
        <form method="POST" action="guard.php?action=login">
          <?= csrfField() ?>
          <div class="form-group">
            <label>New 4-digit PIN</label>
            <input type="password" name="new_password" required autofocus
                   autocomplete="new-password" minlength="4">
          </div>
          <div class="form-group">
            <label>Confirm PIN</label>
            <input type="password" name="confirm_password" required
                   autocomplete="new-password" minlength="4">
          </div>
          <button type="submit" class="btn btn-primary btn-block">
            Save PIN &amp; Login
          </button>
        </form>
        <?php endif; ?>

        <div class="popia-notice">
          Guard access logged for security audit per POPIA §11.
        </div>
      </div>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end login

// ════════════════════════════════════════════════════════
// VERIFY — main gate screen
// ════════════════════════════════════════════════════════
if ($action === 'verify') {
    requireGuard();

    $gate       = $_SESSION['guard_gate']       ?? 'SSgate';
    $gate_point = $_SESSION['guard_gate_point'] ?? '';
    $guardName  = $_SESSION['guard_name']        ?? '';
    $guardId    = $_SESSION['guard_id']          ?? 0;
    $result     = null;

    // Determine allowed directions for this gate point
    $gpInfo       = GATE_POINTS[$gate][$gate_point] ?? null;
    $allowedDirs  = $gpInfo ? $gpInfo['directions'] : ['ENTRY', 'EXIT'];
    $defaultDir   = count($allowedDirs) === 1
                    ? $allowedDirs[0]
                    : ($_POST['direction'] ?? $_GET['dir'] ?? 'ENTRY');

    if ($_SERVER['REQUEST_METHOD'] === 'POST'
        && isset($_POST['verify_input'], $_POST['direction'])) {

        $direction = strtoupper(trim($_POST['direction']));
        if (!in_array($direction, ['ENTRY', 'EXIT'])) $direction = 'ENTRY';
        // Enforce gate-point direction restrictions
        if (!empty($allowedDirs) && !in_array($direction, $allowedDirs)) {
            $direction = $allowedDirs[0];
        }

        $type  = $_POST['verify_type'] ?? '';
        $input = strtoupper(trim($_POST['verify_input'] ?? ''));
        $now   = new DateTime('now', new DateTimeZone('Africa/Johannesburg'));
        $today = $now->format('Y-m-d');
        $time  = $now->format('H:i:s');
        $dow   = $now->format('D'); // Mon Tue Wed Thu Fri Sat Sun

        // ── Helper: find open ENTRY event_id for exit matching ──
        $findEntryRef = function(string $codeOrPlate, string $codeType)
                        use ($gate) : ?string {
            // Look for most recent unmatched ENTRY in last 24h
            $stmt = db()->prepare("
                SELECT event_id FROM access_log
                WHERE (qr_code = ? OR plate = ?)
                  AND direction = 'ENTRY'
                  AND granted   = 1
                  AND entry_ref IS NULL
                  AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                ORDER BY created_at DESC LIMIT 1
            ");
            $stmt->execute([$codeOrPlate, $codeOrPlate]);
            $row = $stmt->fetch();
            return $row ? $row['event_id'] : null;
        };

        // ────────────────────────────────────────────────
        // VISITOR  (code prefix 3)
        // ────────────────────────────────────────────────
        if ($type === 'qr') {
            $stmt = db()->prepare("
                SELECT * FROM visitors
                WHERE code = ? AND status = 'active' AND expired = 0
                  AND ? BETWEEN visit_date
                           AND COALESCE(visit_date_to, visit_date)
            ");
            $stmt->execute([$input, $today]);
            $vis = $stmt->fetch();

            if ($vis) {
                $entryRef = null;
                if ($direction === 'EXIT') {
                    $entryRef = $findEntryRef($input, 'qr');
                    // EXIT without a prior ENTRY still allowed — log it
                }
                $result = [
                    'granted'  => true,
                    'type'     => 'Visitor',
                    'name'     => $vis['visitor_name'],
                    'detail'   => 'Visiting ' . $vis['resident_name'],
                    'direction'=> $direction,
                ];
                logAccess(
                    'visitor', $vis['visitor_name'], $gate, $gate_point,
                    $direction, $vis['plate'] ?? null, $input,
                    $guardId, $guardName, null, $entryRef
                );
                $resPhone = getResidentEmailByErf($vis['resident_erfno'] ?? '');
                if ($resPhone) {
                    $gpLabel = GATE_POINTS[$gate][$gate_point]['label'] ?? $gate_point;
                    if ($direction === 'EXIT') {
                        notifyResidentExit($resPhone, $vis['visitor_name'], 'visitor', $gpLabel);
                    } else {
                        notifyResidentEntry($resPhone, $vis['visitor_name'], 'visitor', $gpLabel);
                    }
                }
            } else {
                // Check if exists but wrong date
                $anyVis = db()->prepare(
                    "SELECT visit_date, visit_date_to, status, expired
                     FROM visitors WHERE code=? LIMIT 1"
                );
                $anyVis->execute([$input]);
                $anyVis = $anyVis->fetch();
                $reason = 'QR code not found.';
                if ($anyVis) {
                    if ($anyVis['expired'])          $reason = 'Pass already expired.';
                    elseif ($anyVis['status'] !== 'active') $reason = 'Pass is not active.';
                    else $reason = "Pass valid " . $anyVis['visit_date']
                                 . ($anyVis['visit_date_to'] ? " – " . $anyVis['visit_date_to'] : '')
                                 . ". Today: {$today}.";
                }
                $result = [
                    'granted'  => false,
                    'type'     => 'Visitor',
                    'name'     => $input,
                    'detail'   => $reason,
                    'direction'=> $direction,
                ];
                logAccess('visitor', $input, $gate, $gate_point,
                    $direction, null, $input,
                    $guardId, $guardName, $reason, null);
            }

        // ────────────────────────────────────────────────
        // SERVICE PROVIDER  (code prefix 7)
        // ────────────────────────────────────────────────
        } elseif ($type === 'sp') {
            $stmt = db()->prepare("
                SELECT * FROM service_providers
                WHERE unique_code = ?
                  AND (approved = 'true' OR approved = 1)
                  AND expired = 0
                  AND ? BETWEEN start_date AND end_date
            ");
            $stmt->execute([$input, $today]);
            $sp = $stmt->fetch();

            if ($sp) {
                // ── Day check ────────────────────────────
                $accessDays  = array_map('trim', explode(',', $sp['access_days'] ?? ''));
                $dayOk       = empty($accessDays) || in_array($dow, $accessDays, true);

                // ── Time check ───────────────────────────
                $startTime = substr($sp['access_start'] ?? '07:00:00', 0, 8);
                $endTime   = substr($sp['access_end']   ?? '17:00:00', 0, 8);
                $timeOk    = ($time >= $startTime && $time <= $endTime);

                if ($dayOk && $timeOk) {
                    $entryRef = ($direction === 'EXIT')
                                ? $findEntryRef($input, 'sp') : null;
                    $result = [
                        'granted'  => true,
                        'type'     => 'Service Provider',
                        'name'     => $sp['service_name'],
                        'detail'   => ($sp['company_name'] ? $sp['company_name'] . ' — ' : '')
                                    . 'Erf ' . ($sp['resident_erfno'] ?? 'Estate'),
                        'direction'=> $direction,
                    ];
                    logAccess(
                        'service_provider', $sp['service_name'],
                        $gate, $gate_point, $direction,
                        null, $input, $guardId, $guardName, null, $entryRef
                    );
                    $resPhone = getResidentEmailByErf($sp['resident_erfno'] ?? '');
                    if ($resPhone) {
                        $gpLabel = GATE_POINTS[$gate][$gate_point]['label'] ?? $gate_point;
                        if ($direction === 'EXIT') {
                            notifyResidentExit($resPhone, $sp['service_name'], 'service_provider', $gpLabel);
                        } else {
                            notifyResidentEntry($resPhone, $sp['service_name'], 'service_provider', $gpLabel);
                        }
                    }
                } else {
                    $reason = !$dayOk
                        ? "Access not permitted on {$dow}. Allowed: {$sp['access_days']}."
                        : "Access not permitted at {$now->format('H:i')}. Allowed: "
                          . substr($startTime,0,5) . "–" . substr($endTime,0,5) . ".";
                    $result = [
                        'granted'  => false,
                        'type'     => 'Service Provider',
                        'name'     => $sp['service_name'],
                        'detail'   => $reason,
                        'direction'=> $direction,
                    ];
                    logAccess(
                        'service_provider', $sp['service_name'],
                        $gate, $gate_point, $direction,
                        null, $input, $guardId, $guardName, $reason, null
                    );
                }
            } else {
                // SP not found or not approved
                $anySp = db()->prepare(
                    "SELECT approved, expired, start_date, end_date
                     FROM service_providers WHERE unique_code=? LIMIT 1"
                );
                $anySp->execute([$input]);
                $anySp = $anySp->fetch();
                $reason = 'Code not found.';
                if ($anySp) {
                    if ($anySp['expired'])
                        $reason = 'Permit expired.';
                    elseif ($anySp['approved'] !== 'true' && $anySp['approved'] != 1)
                        $reason = 'Permit not yet approved by Security.';
                    else
                        $reason = "Permit valid {$anySp['start_date']} – {$anySp['end_date']}. Today: {$today}.";
                }
                $result = [
                    'granted'  => false,
                    'type'     => 'Service Provider',
                    'name'     => $input,
                    'detail'   => $reason,
                    'direction'=> $direction,
                ];
                logAccess('service_provider', $input, $gate, $gate_point,
                    $direction, null, $input,
                    $guardId, $guardName, $reason, null);
            }

        // ────────────────────────────────────────────────
        // RESIDENT  (plate lookup — always permitted)
        // ────────────────────────────────────────────────
        } elseif ($type === 'plate') {
            $stmt = db()->prepare("
                SELECT rv.plate, r.resident_name, r.resident_erfno, r.address
                FROM resident_vehicles rv
                JOIN residents r ON r.id = rv.resident_id
                WHERE rv.plate = ? AND rv.active = 1 AND r.status = 'active'
            ");
            $stmt->execute([$input]);
            $row = $stmt->fetch();

            if ($row) {
                $entryRef = ($direction === 'EXIT')
                            ? $findEntryRef($input, 'plate') : null;
                $result = [
                    'granted'  => true,
                    'type'     => 'Resident',
                    'name'     => $row['resident_name'],
                    'detail'   => 'Erf ' . $row['resident_erfno'] . ' — ' . $row['address'],
                    'direction'=> $direction,
                ];
                logAccess(
                    'resident', $row['resident_name'],
                    $gate, $gate_point, $direction,
                    $input, null, $guardId, $guardName, null, $entryRef
                );
            } else {
                $reason = 'Plate not registered.';
                $result = [
                    'granted'  => false,
                    'type'     => 'Unknown vehicle',
                    'name'     => $input,
                    'detail'   => $reason,
                    'direction'=> $direction,
                ];
                logAccess('unknown', $input, $gate, $gate_point,
                    $direction, $input, null,
                    $guardId, $guardName, $reason, null);
            }
        }
    } // end POST

    // ── Recent log (last 15 events at this gate point) ────
    $recentLogs = db()->prepare(
        "SELECT * FROM access_log
         WHERE gate = ?
         ORDER BY created_at DESC LIMIT 15"
    );

    $recentLogs->execute([$gate]);
    $recentLogs = $recentLogs->fetchAll();

    // ── On-estate count (unmatched entries) ───────────────
    try {
        $onEstate = db()->query(
            "SELECT COUNT(*) FROM access_log
             WHERE direction = 'ENTRY' AND granted = 1
               AND entry_ref IS NULL
               AND created_at >= CURDATE()"
        )->fetchColumn();
    } catch (Exception $e) {
        $onEstate = '—';
    }

    $gpLabel = GATE_POINTS[$gate][$gate_point]['label'] ?? $gate_point;

    pageHeader('Gate — ' . $gpLabel, 'guard');
    renderHeader('🔐 ' . $gpLabel . ' — ' . $guardName, 'logout.php');
    ?>
    <div class="container">
      <?= getFlash() ?>

      <?php if ($result): ?>
      <?php
        $dirIcon = $result['direction'] === 'EXIT' ? '⬆️' : '⬇️';
        $dirWord = $result['direction'];
        $okColor = $result['granted'] ? '#28a745' : '#dc3545';
        $okIcon  = $result['granted'] ? '✅' : '⛔';
        $okWord  = $result['granted'] ? 'GRANTED' : 'DENIED';
      ?>
      <div class="card" style="border-left:5px solid <?= $okColor ?>;
                               margin-bottom:18px;">
        <div style="text-align:center;font-size:2.2rem;margin-bottom:6px;">
          <?= $okIcon ?> <?= $dirIcon ?>
        </div>
        <div style="text-align:center;font-size:1.2rem;font-weight:700;
                    color:<?= $okColor ?>;">
          <?= $dirWord ?> <?= $okWord ?> — <?= htmlspecialchars($result['type']) ?>
        </div>
        <div style="text-align:center;font-size:1rem;margin-top:6px;">
          <?= htmlspecialchars($result['name']) ?>
        </div>
        <div style="text-align:center;font-size:.85rem;color:#666;margin-top:4px;">
          <?= htmlspecialchars($result['detail']) ?>
        </div>
      </div>
      <?php endif; ?>

      <!-- On-estate counter -->
      <div class="card" style="display:flex;justify-content:space-between;
                                align-items:center;padding:12px 18px;
                                margin-bottom:14px;">
        <div style="font-size:.85rem;color:#666;">On estate today</div>
        <div style="font-size:1.4rem;font-weight:700;
                    color:var(--accent);"><?= $onEstate ?></div>
      </div>

      <!-- ═══ DIRECTION TOGGLE ═══ -->
      <?php
        // Only show toggle if gate point allows both directions
        $showToggle = count($allowedDirs) > 1;
        $activeDir  = $_POST['direction'] ?? $defaultDir;
      ?>
      <?php if ($showToggle): ?>
      <div style="display:flex;gap:0;margin-bottom:16px;border-radius:8px;
                  overflow:hidden;border:2px solid var(--accent);">
        <a href="?action=verify&dir=ENTRY"
           style="flex:1;padding:12px;text-align:center;font-weight:700;
                  font-size:1rem;text-decoration:none;
                  background:<?= $activeDir==='ENTRY' ? 'var(--accent)' : '#fff' ?>;
                  color:<?= $activeDir==='ENTRY' ? '#fff' : 'var(--accent)' ?>;">
          ⬇️ ENTRY
        </a>
        <a href="?action=verify&dir=EXIT"
           style="flex:1;padding:12px;text-align:center;font-weight:700;
                  font-size:1rem;text-decoration:none;
                  background:<?= $activeDir==='EXIT' ? 'var(--accent)' : '#fff' ?>;
                  color:<?= $activeDir==='EXIT' ? '#fff' : 'var(--accent)' ?>;">
          ⬆️ EXIT
        </a>
      </div>
      <?php else: ?>
      <!-- Fixed direction gate — show label only -->
      <div style="background:var(--accent);color:#fff;padding:10px 16px;
                  border-radius:8px;text-align:center;font-weight:700;
                  margin-bottom:16px;font-size:1rem;">
        <?= $allowedDirs[0] === 'EXIT' ? '⬆️ EXIT GATE' : '⬇️ ENTRY GATE' ?>
      </div>
      <?php endif; ?>

      <!-- Current direction hidden field — shared by all forms below -->
      <?php $curDir = $showToggle ? $activeDir : $allowedDirs[0]; ?>

      <!-- ── Visitor QR (3XXXXX) ───────────────────────── -->
      <div class="card">
        <div class="card-title">📱 Visitor Pass (3XXXXX)</div>
        <form method="POST" style="display:flex;gap:8px;">
          <?= csrfField() ?>
          <input type="hidden" name="verify_type"  value="qr">
          <input type="hidden" name="direction"    value="<?= $curDir ?>">
          <div class="form-group" style="flex:1;margin:0;">
            <input type="text" name="verify_input"
                   placeholder="3XXXXX — scan or type"
                   style="text-transform:uppercase;font-family:monospace;
                          font-size:1.1rem;letter-spacing:0.1em;"
                   autocomplete="off" inputmode="numeric" maxlength="6"
                   autofocus>
          </div>
          <button type="submit" class="btn btn-success">Verify</button>
        </form>
      </div>

      <!-- ── Service Provider QR (7XXXXX) ─────────────── -->
      <div class="card">
        <div class="card-title">🔧 Service Provider (7XXXXX)</div>
        <form method="POST" style="display:flex;gap:8px;">
          <?= csrfField() ?>
          <input type="hidden" name="verify_type" value="sp">
          <input type="hidden" name="direction"   value="<?= $curDir ?>">
          <div class="form-group" style="flex:1;margin:0;">
            <input type="text" name="verify_input"
                   placeholder="7XXXXX — scan or type"
                   style="text-transform:uppercase;font-family:monospace;
                          font-size:1.1rem;letter-spacing:0.1em;"
                   autocomplete="off" inputmode="numeric" maxlength="6">
          </div>
          <button type="submit" class="btn btn-primary"
                  style="background:#8e44ad;">Verify</button>
        </form>
      </div>

      <!-- ── Resident plate ────────────────────────────── -->
      <div class="card">
        <div class="card-title">🚗 Resident Vehicle Plate</div>
        <form method="POST" style="display:flex;gap:8px;">
          <?= csrfField() ?>
          <input type="hidden" name="verify_type" value="plate">
          <input type="hidden" name="direction"   value="<?= $curDir ?>">
          <div class="form-group" style="flex:1;margin:0;">
            <input type="text" name="verify_input"
                   placeholder="e.g. CBS 10009"
                   style="text-transform:uppercase;"
                   autocomplete="off">
          </div>
          <button type="submit" class="btn btn-primary">Check</button>
        </form>
      </div>

      <!-- ── Recent events ─────────────────────────────── -->
      <?php if (!empty($recentLogs)): ?>
      <div class="card">
        <div class="card-title">📋 Last 15 Events — <?= htmlspecialchars($gate) ?></div>
        <div class="table-wrap"><table>
          <tr>
            <th>Time</th>
            <th>Dir</th>
            <th>Type</th>
            <th>Name</th>
            <th>Gate Point</th>
            <th>Result</th>
          </tr>
          <?php foreach ($recentLogs as $l): ?>
          <tr>
            <td style="white-space:nowrap;font-size:.82rem;">
              <?= date('H:i', strtotime($l['created_at'])) ?>
            </td>
            <td>
              <span style="font-weight:700;color:<?=
                ($l['direction']??'ENTRY')==='EXIT' ? '#8e44ad' : '#1565c0'
              ?>;">
                <?= ($l['direction']??'ENTRY')==='EXIT' ? '⬆️' : '⬇️' ?>
                <?= htmlspecialchars($l['direction'] ?? 'ENTRY') ?>
              </span>
            </td>
            <td style="font-size:.82rem;">
              <?= htmlspecialchars($l['entry_type'] ?? '') ?>
            </td>
            <td style="font-size:.82rem;">
              <?= htmlspecialchars(
                $l['person_name'] ?? $l['visitor_name'] ?? $l['plate'] ?? '—'
              ) ?>
            </td>
            <td style="font-size:.78rem;color:#888;">
              <?= htmlspecialchars($l['gate_point'] ?? '') ?>
            </td>
            <td>
              <span class="badge badge-<?=
                ($l['granted'] ?? (empty($l['deny_reason']) ? 1 : 0))
                ? 'success' : 'danger'
              ?>">
                <?= ($l['granted'] ?? (empty($l['deny_reason']) ? 1 : 0))
                    ? 'OK' : 'DENIED' ?>
              </span>
            </td>
          </tr>
          <?php endforeach; ?>
        </table></div>
      </div>
      <?php endif; ?>

      <!-- Change gate point without logging out -->
      <div class="card" style="padding:12px 16px;">
        <form method="POST" action="guard.php?action=change_point"
              style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
          <?= csrfField() ?>
          <label style="font-size:.85rem;color:#666;white-space:nowrap;">
            Change gate point:
          </label>
          <select name="gate_point" style="flex:1;padding:6px 10px;
                  border:1px solid #dee2e6;border-radius:6px;">
            <?php foreach (GATE_POINTS[$gate] as $code => $info): ?>
            <option value="<?= $code ?>"
              <?= $code === $gate_point ? 'selected' : '' ?>>
              <?= htmlspecialchars($info['label']) ?>
            </option>
            <?php endforeach; ?>
          </select>
          <button type="submit" class="btn btn-secondary btn-sm">Switch</button>
        </form>
      </div>

    </div>

    <!-- ═══ QR CAMERA SCANNER OVERLAY ═══════════════════════════ -->
    <!-- Uses jsQR — no app install needed, works in mobile browser -->
    <div id="scanner-overlay"
         style="display:none;position:fixed;inset:0;background:#000;z-index:999;
                flex-direction:column;align-items:center;justify-content:center;">
      <div style="color:#fff;font-size:1rem;margin-bottom:12px;">
        📷 Point camera at QR code…
      </div>
      <video id="qr-video"
             style="width:100%;max-width:480px;border-radius:12px;"
             playsinline></video>
      <canvas id="qr-canvas" style="display:none;"></canvas>
      <div id="qr-status"
           style="color:#ffdd00;margin-top:12px;font-size:.9rem;min-height:1.2em;"></div>
      <button onclick="stopQrScan()"
              style="margin-top:16px;padding:14px 32px;background:#ffdd00;color:#000;
                     border:none;border-radius:10px;font-size:1rem;
                     font-weight:800;cursor:pointer;">
        ✕ Cancel
      </button>
    </div>

    <!-- Floating scan button (fixed bottom-right, always visible) -->
    <button onclick="startQrScan()"
            style="position:fixed;bottom:24px;right:20px;
                   width:64px;height:64px;border-radius:50%;
                   background:var(--accent);color:#fff;border:none;
                   font-size:1.6rem;cursor:pointer;
                   box-shadow:0 4px 16px rgba(0,0,0,.3);z-index:100;"
            title="Scan QR code">
      📷
    </button>

    <script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js"></script>
    <script>
    let qrStream  = null;
    let qrLoop    = null;
    let curDir    = '<?= htmlspecialchars($curDir) ?>';

    function startQrScan() {
        const overlay = document.getElementById('scanner-overlay');
        const video   = document.getElementById('qr-video');
        const canvas  = document.getElementById('qr-canvas');
        const status  = document.getElementById('qr-status');
        const ctx     = canvas.getContext('2d');

        overlay.style.display = 'flex';
        status.textContent    = 'Starting camera…';

        navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
            .then(s => {
                qrStream       = s;
                video.srcObject = s;
                video.play();
                status.textContent = 'Scanning…';

                qrLoop = setInterval(() => {
                    if (video.readyState !== video.HAVE_ENOUGH_DATA) return;
                    canvas.width  = video.videoWidth;
                    canvas.height = video.videoHeight;
                    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
                    const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
                    const qr  = jsQR(img.data, img.width, img.height);
                    if (qr && qr.data) {
                        stopQrScan();
                        handleScannedCode(qr.data);
                    }
                }, 200);
            })
            .catch(err => {
                stopQrScan();
                alert('Camera error: ' + err.message
                    + '\nYou can type the code manually instead.');
            });
    }

    function stopQrScan() {
        clearInterval(qrLoop);
        if (qrStream) {
            qrStream.getTracks().forEach(t => t.stop());
            qrStream = null;
        }
        document.getElementById('scanner-overlay').style.display = 'none';
    }

    function handleScannedCode(raw) {
        // QR payload may be a full URL or a raw 6-digit code
        let code = raw.trim();
        try {
            const url = new URL(raw);
            code = url.searchParams.get('code') || code;
        } catch(e) { /* not a URL — use raw */ }

        // Strip non-digits
        code = code.replace(/\D/g, '').toUpperCase();

        if (!/^\d{6}$/.test(code)) {
            alert('Unrecognised QR code: ' + raw);
            return;
        }

        const prefix = code[0];
        let type     = '';
        if (prefix === '3')      type = 'qr';   // visitor
        else if (prefix === '7') type = 'sp';   // service provider
        else {
            alert('Unknown code type: ' + code
                + '\nVisitor codes start with 3, SP codes with 7.');
            return;
        }

        // Auto-submit via a hidden form so the full server-side
        // validation, logging, and result display runs normally
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = 'guard.php?action=verify&dir=' + encodeURIComponent(curDir);

        const fields = {
            verify_type:  type,
            verify_input: code,
            direction:    curDir,
            csrf_token:   '<?= htmlspecialchars(generateCsrfToken()) ?>',
        };
        Object.entries(fields).forEach(([k, v]) => {
            const inp = document.createElement('input');
            inp.type  = 'hidden';
            inp.name  = k;
            inp.value = v;
            form.appendChild(inp);
        });
        document.body.appendChild(form);
        form.submit();
    }
    </script>

    <?php pageFooter(); exit; ?>
<?php } // end verify

// ════════════════════════════════════════════════════════
// CHANGE GATE POINT — without logging out
// ════════════════════════════════════════════════════════
if ($action === 'change_point') {
    requireGuard();
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $gate       = $_SESSION['guard_gate'] ?? 'SSgate';
        $gate_point = $_POST['gate_point']    ?? '';
        $validPts   = array_keys(GATE_POINTS[$gate] ?? []);
        if (in_array($gate_point, $validPts)) {
            $_SESSION['guard_gate_point'] = $gate_point;
            db()->prepare(
                "UPDATE guards SET gate_point=? WHERE id=?"
            )->execute([$gate_point, $_SESSION['guard_id']]);
            setFlash('success', 'Gate point updated to: '
                . (GATE_POINTS[$gate][$gate_point]['label'] ?? $gate_point));
        }
    }
    header('Location: guard.php?action=verify'); exit;
}

// ════════════════════════════════════════════════════════
// RESET PIN (when already logged in)
// ════════════════════════════════════════════════════════
if ($action === 'reset') {
    requireGuard();
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $new = trim($_POST['new_password']     ?? '');
        $con = trim($_POST['confirm_password'] ?? '');
        if (strlen($new) < 4)  { setFlash('error', 'PIN must be at least 4 digits.'); }
        elseif ($new !== $con) { setFlash('error', 'PINs do not match.'); }
        else {
            db()->prepare("UPDATE guards SET pin=? WHERE id=?")
                ->execute([password_hash($new, PASSWORD_BCRYPT),
                           $_SESSION['guard_id']]);
            setFlash('success', 'PIN updated.');
            header('Location: guard.php?action=verify'); exit;
        }
    }
    pageHeader('Change PIN', 'guard');
    renderHeader('🔑 Change PIN', 'guard.php?action=verify');
    ?>
    <div class="container" style="max-width:420px;">
      <div class="card">
        <?= getFlash() ?>
        <form method="POST">
          <?= csrfField() ?>
          <div class="form-group">
            <label>New 4-digit PIN</label>
            <input type="password" name="new_password" required
                   inputmode="numeric" maxlength="4" pattern="\d{4}"
                   style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;">
          </div>
          <div class="form-group">
            <label>Confirm</label>
            <input type="password" name="confirm_password" required
                   inputmode="numeric" maxlength="4" pattern="\d{4}"
                   style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;">
          </div>
          <button type="submit" class="btn btn-primary btn-block">Update</button>
        </form>
      </div>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end reset

header('Location: guard.php?action=verify'); exit;

// ════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════
function guardGrantAccess(array $guard, string $gate,
                          string $gate_point): void {
    session_regenerate_id(true);
    $_SESSION['guard_id']         = $guard['id'];
    $_SESSION['guard_name']       = $guard['name'];
    $_SESSION['guard_gate']       = $gate;
    $_SESSION['guard_gate_point'] = $gate_point;
    $_SESSION['last_activity']    = time();
    unset($_SESSION['guard_login_step'],
          $_SESSION['guard_pending_id'],
          $_SESSION['guard_pending_gate'],
          $_SESSION['guard_pending_gp']);
    header('Location: guard.php?action=verify');
}

function logAccess(
    string  $type,
    string  $name,
    string  $gate,
    string  $gate_point,
    string  $direction,
    ?string $plate,
    ?string $qr,
    int     $guardId,
    string  $guardName,
    ?string $denyReason,
    ?string $entryRef
): void {
    try {
        $eventId = generateEventId();
        $granted = ($denyReason === null || $denyReason === '') ? 1 : 0;

        db()->prepare("
            INSERT INTO access_log
              (event_id, gate, gate_point, direction,
               entry_type, person_name,
               plate, qr_code,
               guard_id, guard_name,
               deny_reason, granted,
               entry_ref, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,NOW())
        ")->execute([
            $eventId, $gate, $gate_point, $direction,
            $type, $name,
            $plate, $qr,
            $guardId, $guardName,
            $denyReason ?: null, $granted,
            $entryRef,
        ]);

        // If this is an EXIT, close the matching ENTRY record
        if ($entryRef && $granted) {
            db()->prepare(
                "UPDATE access_log
                 SET entry_ref = ?
                 WHERE event_id = ? AND direction = 'ENTRY'"
            )->execute([$eventId, $entryRef]);
        }
    } catch (Exception $e) {
        error_log('GEMB logAccess error: ' . $e->getMessage());
    }
}

function getResidentEmailByErf(string $erf): string {
    if (!$erf) return '';
    try {
        $stmt = db()->prepare(
            "SELECT email FROM residents
             WHERE UPPER(resident_erfno) = UPPER(?) AND is_primary = 1
             LIMIT 1"
        );
        $stmt->execute([$erf]);
        return (string)($stmt->fetchColumn() ?: '');
    } catch (Exception $e) {
        return '';
    }
}
