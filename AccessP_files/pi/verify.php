<?php
/**
 * pi/verify.php — Offline gate verification (Raspberry Pi)
 *
 * Security model mirrors guard.php on the cloud:
 *   - Username + PIN (bcrypt verified against synced hash)
 *   - Device cookie (registered on first login, valid 30 days)
 *   - Brute force protection (5 attempts → 15 min lockout)
 *   - Session timeout after 8 hours (full shift)
 */
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/totp_lib.php';
session_start();

$db    = piDb();
$gates = unserialize(PI_GATES);
$ip    = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$ipHash = hash('sha256', $ip);

// ── Helpers ───────────────────────────────────────────────
function piIsLocked(string $username): bool {
    global $db;
    $cutoff = date('Y-m-d H:i:s', strtotime('-' . PI_LOCKOUT_MINS . ' minutes'));
    $stmt = $db->prepare(
        "SELECT COUNT(*) FROM pi_login_attempts
         WHERE username = ? AND attempted_at >= ?"
    );
    $stmt->execute([$username, $cutoff]);
    return (int)$stmt->fetchColumn() >= PI_MAX_ATTEMPTS;
}

function piRecordFailure(string $username, string $ipHash): void {
    global $db;
    $db->prepare(
        "INSERT INTO pi_login_attempts (username, ip_hash) VALUES (?,?)"
    )->execute([$username, $ipHash]);
}

function piAttemptsLeft(string $username): int {
    global $db;
    $cutoff = date('Y-m-d H:i:s', strtotime('-' . PI_LOCKOUT_MINS . ' minutes'));
    $stmt = $db->prepare(
        "SELECT COUNT(*) FROM pi_login_attempts
         WHERE username = ? AND attempted_at >= ?"
    );
    $stmt->execute([$username, $cutoff]);
    return max(0, PI_MAX_ATTEMPTS - (int)$stmt->fetchColumn());
}

function piCheckDeviceCookie(int $guardId): bool {
    global $db;
    $raw = $_COOKIE[PI_DEVICE_COOKIE] ?? '';
    if (!$raw) return false;
    $hash = hash_hmac('sha256', $raw, PI_SYNC_KEY);
    $stmt = $db->prepare(
        "SELECT id FROM pi_device_tokens WHERE guard_id = ? AND token_hash = ? LIMIT 1"
    );
    $stmt->execute([$guardId, $hash]);
    return (bool)$stmt->fetch();
}

function piRegisterDevice(int $guardId): void {
    global $db;
    $raw  = bin2hex(random_bytes(24));
    $hash = hash_hmac('sha256', $raw, PI_SYNC_KEY);

    // ── Enforce single device: wipe ALL previous tokens for this guard ──
    $db->prepare("DELETE FROM pi_device_tokens WHERE guard_id = ?")->execute([$guardId]);

    // Register the new device
    $db->prepare(
        "INSERT INTO pi_device_tokens (guard_id, token_hash) VALUES (?,?)"
    )->execute([$guardId, $hash]);

    setcookie(PI_DEVICE_COOKIE, $raw, time() + PI_DEVICE_EXPIRY, '/', '', false, true);
}

function piSetActiveSession(int $guardId): void {
    global $db;
    $sid = session_id();
    $deviceHash = hash_hmac('sha256', $_COOKIE[PI_DEVICE_COOKIE] ?? '', PI_SYNC_KEY);
    $db->prepare("
        INSERT OR REPLACE INTO pi_active_sessions (guard_id, session_id, device_hash, updated_at)
        VALUES (?, ?, ?, datetime('now','localtime'))
    ")->execute([$guardId, $sid, $deviceHash]);
}

function piSessionIsActive(int $guardId): bool {
    global $db;
    $sid  = session_id();
    $stmt = $db->prepare(
        "SELECT session_id FROM pi_active_sessions WHERE guard_id = ? LIMIT 1"
    );
    $stmt->execute([$guardId]);
    $row = $stmt->fetch();
    if (!$row) return false;
    return hash_equals($row['session_id'], $sid);
}

function piSessionExpired(): bool {
    if (empty($_SESSION['pi_last_activity'])) return false;
    return (time() - $_SESSION['pi_last_activity']) > PI_SESSION_TIMEOUT;
}

// ── Logout ────────────────────────────────────────────────
if (isset($_GET['logout'])) {
    // Clear session
    $_SESSION = [];
    session_destroy();
    header('Location: verify.php'); exit;
}

// ── Session timeout check ─────────────────────────────────
if (!empty($_SESSION['pi_guard_id']) && piSessionExpired()) {
    $_SESSION = [];
    session_destroy();
    session_start();
    $loginError = 'Session expired after 8 hours. Please log in again.';
}

// ── LOGIN POST ────────────────────────────────────────────
$loginError = $loginError ?? '';
$loginStep  = $_SESSION['pi_login_step'] ?? 'credentials';

// Step 1 — Username + PIN
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['pi_login'])) {
    $username = trim($_POST['username'] ?? '');
    $pin      = $_POST['pin'] ?? '';

    if (piIsLocked($username)) {
        $loginError = "Too many failed attempts. Locked for " . PI_LOCKOUT_MINS . " minutes.";
    } else {
        $guard = $db->prepare(
            "SELECT id, username, password, full_name, phone, assigned_gate,
                    totp_secret, totp_confirmed
             FROM guards WHERE username = ? LIMIT 1"
        );
        $guard->execute([$username]);
        $guard = $guard->fetch();

        if ($guard && password_verify($pin, $guard['password'])) {
            if (piCheckDeviceCookie($guard['id'])) {
                // Known device — login directly, wipe other sessions
                $_SESSION['pi_guard_id']      = $guard['id'];
                $_SESSION['pi_guard_name']    = $guard['full_name'];
                $_SESSION['pi_last_activity'] = time();
                unset($_SESSION['pi_login_step'], $_SESSION['pi_pending_guard']);
                piRegisterDevice($guard['id']); // refresh token, wipes all others
                piSetActiveSession($guard['id']);
                header('Location: verify.php'); exit;
            } else {
                // New device — go to OTP step
                $_SESSION['pi_login_step']    = 'otp';
                $_SESSION['pi_pending_guard'] = $guard;
                $loginStep  = 'otp';
                $loginError = '';
            }
        } else {
            piRecordFailure($username, $ipHash);
            $left = piAttemptsLeft($username);
            $loginError = "Invalid username or PIN."
                . ($left <= 2 ? " {$left} attempt(s) remaining." : '');
        }
    }
}

// Step 2 — TOTP (authenticator app)
// Previously this compared against the last 6 digits of the guard's own
// phone number — not a secret, not one-time. TOTP verifies with pure
// local arithmetic (see totp_lib.php), so it works with zero
// connectivity here on the Pi.
//
// IMPORTANT: enrolment (generating a fresh secret + showing a QR code)
// only happens on the cloud side (guard.php), because a freshly
// generated secret needs to reach the cloud database to survive the
// next sync — this Pi's local guards table gets overwritten wholesale
// from the cloud on every sync (see pi/sync.php), so anything enrolled
// only here would be silently lost. If a guard reaches this gate before
// ever completing that one-time cloud setup, they're told to do that
// first rather than getting stuck in a dead end offline.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['pi_otp'])) {
    $otp   = trim($_POST['otp'] ?? '');
    $guard = $_SESSION['pi_pending_guard'] ?? null;

    if (!$guard) {
        $loginStep  = 'credentials';
        $loginError = 'Session expired. Please log in again.';
    } elseif (empty($guard['totp_secret']) || empty($guard['totp_confirmed'])) {
        session_unset(); session_destroy(); session_start();
        $loginStep  = 'credentials';
        $loginError = 'Authenticator app not yet set up for this account. '
                    . 'Please log in once from the cloud portal (with internet '
                    . 'access) to complete one-time setup, then try again here.';
    } elseif (gembTotpVerify($guard['totp_secret'], $otp)) {
        $_SESSION['pi_login_step'] = 'reset';
        $loginStep = 'reset';
        $loginError = '';
    } else {
        // Wrong code — reset session (mirrors security.php behaviour)
        piRecordFailure($guard['username'], $ipHash);
        session_unset(); session_destroy(); session_start();
        $loginStep  = 'credentials';
        $loginError = 'Incorrect code. For security your session has been reset. Please try again.';
    }
}

// Step 3 — Set new PIN (mirrors security.php reset step)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['pi_reset'])) {
    $newPin  = trim($_POST['new_pin']     ?? '');
    $conPin  = trim($_POST['confirm_pin'] ?? '');
    $guard   = $_SESSION['pi_pending_guard'] ?? null;

    if (!$guard) {
        $loginStep = 'credentials';
        $loginError = 'Session expired. Please log in again.';
    } elseif (!preg_match('/^\d{4}$/', $newPin)) {
        $loginError = 'PIN must be exactly 4 digits.';
        $loginStep  = 'reset';
    } elseif ($newPin !== $conPin) {
        $loginError = 'PINs do not match.';
        $loginStep  = 'reset';
    } elseif (password_verify($newPin, $guard['password'])) {
        $loginError = 'New PIN must be different from your current PIN.';
        $loginStep  = 'reset';
    } else {
        $newHash = password_hash($newPin, PASSWORD_BCRYPT);

        // Update PIN in Pi SQLite
        $db->prepare("UPDATE guards SET password = ? WHERE id = ?")
           ->execute([$newHash, $guard['id']]);

        // Push new PIN hash back to cloud so both systems stay in sync
        $updateUrl = rtrim(str_replace('pi_sync_api.php', '', PI_CLOUD_URL), '/') . '/pi_update_pin_api.php';
        $ch = curl_init($updateUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true, CURLOPT_POST => true,
            CURLOPT_POSTFIELDS     => http_build_query(['guard_id' => $guard['id'], 'pin_hash' => $newHash]),
            CURLOPT_HTTPHEADER     => ['Authorization: Bearer ' . PI_SYNC_KEY],
            CURLOPT_TIMEOUT => 8,
        ]);
        curl_exec($ch); curl_close($ch);

        // Register device, set active session, login
        piRegisterDevice($guard['id']);
        $_SESSION['pi_guard_id']      = $guard['id'];
        $_SESSION['pi_guard_name']    = $guard['full_name'];
        $_SESSION['pi_last_activity'] = time();
        unset($_SESSION['pi_login_step'], $_SESSION['pi_pending_guard']);
        piSetActiveSession($guard['id']);
        header('Location: verify.php'); exit;
    }
}

// ── Show login form if not authenticated ──────────────────
showLogin:
if (empty($_SESSION['pi_guard_id'])) {
    $lastSync = $db->query("SELECT value FROM pi_state WHERE key='last_sync'")->fetchColumn();
    $syncAge  = $lastSync ? round((time()-strtotime($lastSync))/60).' min ago' : 'never';
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
      <title>GEMB Gate — Login</title>
      <link rel="manifest" href="/gemb/manifest.json">
      <meta name="mobile-web-app-capable" content="yes">
      <meta name="apple-mobile-web-app-capable" content="yes">
      <meta name="apple-mobile-web-app-title" content="GEMB Gate">
      <meta name="theme-color" content="#003366">
      <link rel="apple-touch-icon" href="/gemb/icons/icon-192.png">
      <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
               background: #000; min-height: 100vh; display: flex; flex-direction: column;
               align-items: center; padding-bottom: 40px; }
        .offline { width: 100%; background: #7a4f00; color: #ffe; text-align: center;
                   padding: 8px 16px; font-size: 0.9rem; font-weight: 600; }
        .band { width: 100%; background: #003366; padding: 36px 24px 28px; text-align: center; }
        .band h1 { font-size: 2.5rem; font-weight: 900; color: #fff; }
        .band p  { color: rgba(255,255,255,0.8); margin-top: 8px; font-size: 1.1rem; }
        .card { width: calc(100% - 32px); max-width: 400px;
                background: rgba(255,255,255,0.10); border-radius: 14px;
                margin: 24px 0 0; padding: 24px; }
        .card label { color: rgba(255,255,255,0.7); font-size: 0.9rem;
                      display: block; margin-bottom: 6px; }
        .card input { width: 100%; padding: 14px 16px; border: none; border-radius: 10px;
                      font-size: 1.1rem; background: rgba(255,255,255,0.15); color: #fff;
                      margin-bottom: 14px; }
        .card input::placeholder { opacity: 0.5; }
        .card button { width: 100%; padding: 18px; background: #ffdd00; color: #000;
                       border: none; border-radius: 10px; font-size: 1.2rem;
                       font-weight: 900; cursor: pointer; }
        .error { width: calc(100% - 32px); max-width: 400px; margin: 16px 0 0;
                 background: #aa0000; color: #fff; padding: 12px 16px;
                 border-radius: 10px; font-size: 0.95rem; font-weight: 600; }
      </style>
    </head>
    <body>
    <div class="offline">📡 OFFLINE MODE — Pi node &nbsp;|&nbsp; Last sync: <?= htmlspecialchars($syncAge) ?></div>
    <div class="band">
      <h1>🔐 GEMB GATE</h1>
      <p>Guard Login</p>
    </div>
    <?php if ($loginError): ?>
    <div class="error"><?= htmlspecialchars($loginError) ?></div>
    <?php endif; ?>
    <?php if ($loginStep === 'otp'): ?>
    <div class="card">
      <p style="color:rgba(255,255,255,0.8);font-size:0.95rem;margin-bottom:16px;
                background:rgba(255,255,255,0.1);padding:12px;border-radius:8px;">
        🔐 <strong>New device detected.</strong><br><br>
        Enter the 6-digit code from your authenticator app.
      </p>
      <form method="POST">
        <label>6-digit code</label>
        <input type="text" name="otp" inputmode="numeric" maxlength="6"
               pattern="\d{6}" placeholder="_ _ _ _ _ _" autofocus
               style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;">
        <input type="hidden" name="pi_otp" value="1">
        <button type="submit">VERIFY CODE ▶</button>
      </form>
      <p style="color:rgba(255,255,255,0.4);font-size:0.8rem;margin-top:12px;text-align:center;">
        <a href="verify.php" style="color:#ffdd00;">← Cancel and start over</a>
      </p>
    </div>

    <?php elseif ($loginStep === 'reset'): ?>
    <div class="card">
      <p style="color:rgba(255,255,255,0.8);font-size:0.95rem;margin-bottom:16px;
                background:rgba(255,255,255,0.1);padding:12px;border-radius:8px;">
        ✅ Identity verified.<br>Please set a new 4-digit PIN for this device.
      </p>
      <form method="POST">
        <label>New PIN (4 digits)</label>
        <input type="password" name="new_pin" inputmode="numeric" maxlength="4"
               pattern="\d{4}" placeholder="••••" autofocus
               style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;">
        <label>Confirm PIN</label>
        <input type="password" name="confirm_pin" inputmode="numeric" maxlength="4"
               pattern="\d{4}" placeholder="••••"
               style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;">
        <input type="hidden" name="pi_reset" value="1">
        <button type="submit">SAVE PIN &amp; LOGIN ▶</button>
      </form>
    </div>

    <?php else: ?>
    <div class="card">
      <form method="POST">
        <label>Username</label>
        <input type="text" name="username" autocomplete="username"
               autocapitalize="none" placeholder="guard username" autofocus>
        <label>PIN</label>
        <input type="password" name="pin" autocomplete="current-password"
               inputmode="numeric" maxlength="4" placeholder="••••"
               style="font-size:1.6rem;letter-spacing:0.4em;text-align:center;">
        <input type="hidden" name="pi_login" value="1">
        <button type="submit">LOGIN ▶</button>
      </form>
    </div>
    <?php endif; ?>
    <script>
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/gemb/sw.js').catch(()=>{});
    }
    </script>
    </body>
    </html>
    <?php
    exit;
}

// ── Guard is logged in ────────────────────────────────────
$guardId   = $_SESSION['pi_guard_id'];
$guardName = $_SESSION['pi_guard_name'];

// Validate this is still the ACTIVE session for this guard
// If another device logged in, this session is no longer active
if (!piSessionIsActive($guardId)) {
    $_SESSION = [];
    session_destroy();
    session_start();
    $loginError = 'You were logged out because this account signed in on another device.';
    // Fall through to show login form
    goto showLogin;
}

$_SESSION['pi_last_activity'] = time();

// ── Input ─────────────────────────────────────────────────
$code      = strtoupper(trim($_GET['code'] ?? ''));
$direction = in_array(strtoupper($_GET['dir'] ?? 'ENTRY'), ['ENTRY','EXIT'], true)
             ? strtoupper($_GET['dir'] ?? 'ENTRY') : 'ENTRY';
$gateKeys  = array_keys($gates);
$gate      = in_array($_GET['gate'] ?? '', $gateKeys, true)
             ? $_GET['gate'] : PI_GATE_NAME;
$gatePoint = preg_replace('/[^A-Z0-9_]/', '', strtoupper($_GET['gp'] ?? '')) ?: null;

$access    = false;
$reason    = '';
$detail    = '';
$name      = '';
$entryType = 'unknown';
$plate     = '';

// ── Sync status ───────────────────────────────────────────
$lastSync = $db->query("SELECT value FROM pi_state WHERE key='last_sync'")->fetchColumn();
$syncAge  = $lastSync ? round((time()-strtotime($lastSync))/60).' min ago' : 'never';

$today = date('Y-m-d');
$time  = date('H:i:s');
$dow   = date('l');

// ── Verify code ───────────────────────────────────────────
if ($code === '') {
    // show form only
} elseif (preg_match('/^3\d{5}$/', $code)) {
    $entryType = 'visitor';
    $vis = $db->prepare("
        SELECT * FROM visitors
        WHERE  code = ? AND status = 'active' AND expired = 0
          AND  date('now','localtime') BETWEEN visit_date
               AND COALESCE(visit_date_to, visit_date)
    ");
    $vis->execute([$code]);
    $vis = $vis->fetch();
    if ($vis) {
        $access = true; $reason = 'Access Granted';
        $name   = $vis['visitor_name'];
        $detail = 'Visiting ' . $vis['resident_name'];
        $plate  = $vis['plate'] ?? '';
    } else {
        $any = $db->prepare("SELECT * FROM visitors WHERE code = ? LIMIT 1");
        $any->execute([$code]); $any = $any->fetch();
        if (!$any)                           $reason = 'Code not found.';
        elseif ($any['expired'])             $reason = 'Pass expired.';
        elseif ($any['status'] !== 'active') $reason = 'Pass not active.';
        else $reason = 'Pass valid '.$any['visit_date'].($any['visit_date_to']?' – '.$any['visit_date_to']:'').'. Today: '.$today.'.';
        $name = $code;
    }

} elseif (preg_match('/^7\d{5}$/', $code)) {
    $entryType = 'service_provider';
    $sp = $db->prepare("
        SELECT * FROM service_providers
        WHERE  unique_code = ? AND (approved='true' OR approved=1)
          AND  expired = 0
          AND  date('now','localtime') BETWEEN start_date AND end_date
    ");
    $sp->execute([$code]); $sp = $sp->fetch();
    if ($sp) {
        $allowedDays = array_filter(array_map('trim', explode(',', $sp['access_days'] ?? '')));
        $dayOk  = empty($allowedDays) || in_array($dow, $allowedDays, true);
        $startT = substr($sp['access_start'] ?? '07:00:00', 0, 8);
        $endT   = substr($sp['access_end']   ?? '17:00:00', 0, 8);
        $timeOk = ($time >= $startT && $time <= $endT);
        if ($dayOk && $timeOk) {
            $access = true; $reason = 'Access Granted';
            $name   = $sp['service_name'];
            $detail = ($sp['company_name'] ? $sp['company_name'].' — ' : '').'Erf '.($sp['resident_erfno'] ?? 'Estate');
        } else {
            $reason = !$dayOk ? "Not permitted on {$dow}." : "Not permitted at {$time}.";
            $name   = $sp['service_name'];
        }
    } else {
        $any = $db->prepare("SELECT * FROM service_providers WHERE unique_code=? LIMIT 1");
        $any->execute([$code]); $any = $any->fetch();
        if (!$any)               $reason = 'Code not found.';
        elseif ($any['expired']) $reason = 'Permit expired.';
        else                     $reason = 'Permit not approved.';
        $name = $code;
    }

} elseif (strlen($code) >= 3 && strlen($code) <= 12) {
    $entryType = 'resident';
    $clean = preg_replace('/\s+/', '', $code);
    $veh = $db->prepare("SELECT * FROM resident_vehicles WHERE REPLACE(UPPER(plate),' ','')=? LIMIT 1");
    $veh->execute([$clean]); $veh = $veh->fetch();
    if ($veh) {
        $access = true; $reason = 'Access Granted';
        $name   = $veh['resident_name'];
        $detail = 'Erf '.$veh['resident_erfno'].($veh['address'] ? ' — '.$veh['address'] : '');
        $plate  = $veh['plate'];
    } else {
        $reason = 'Plate not registered.'; $name = $code;
    }
} else {
    $reason = 'Unrecognised code.'; $name = $code;
}

// ── Log event ─────────────────────────────────────────────
if ($code !== '') {
    try {
        $db->prepare("
            INSERT INTO pi_access_log
              (event_id, gate, gate_point, direction, entry_type, person_name,
               plate, qr_code, guard_id, granted, deny_reason, notes)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        ")->execute([
            'PI-'.strtoupper(substr(md5(uniqid('',true)),0,10)),
            $gate, $gatePoint, $direction, $entryType, $name ?: null,
            $plate ?: null,
            preg_match('/^[37]\d{5}$/', $code) ? $code : null,
            $guardId, $access ? 1 : 0,
            $access ? null : $reason,
            'pi-offline|guard:'.$guardName,
        ]);
    } catch (Exception $e) { error_log('Pi log: '.$e->getMessage()); }
}

// ── Gate trigger ──────────────────────────────────────────
$gateOk = false; $gateMsg = '';
if ($access && $code !== '' && empty($_GET['nogate'])) {
    $ts  = time();
    $sig = hash_hmac('sha256', $ts.PI_GATE_TOKEN, PI_GATE_TOKEN);
    $ch  = curl_init(PI_GATE_URL);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_POST => true,
        CURLOPT_POSTFIELDS     => http_build_query(['token'=>PI_GATE_TOKEN,'ts'=>$ts,'sig'=>$sig]),
        CURLOPT_TIMEOUT        => PI_GATE_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => PI_GATE_TIMEOUT,
        CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0,
    ]);
    $resp = curl_exec($ch); $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch); curl_close($ch);
    if ($curlErr)        $gateMsg = 'cURL: '.$curlErr;
    elseif ($http===200) { $gateOk = true; $gateMsg = 'Opened'; }
    else                 $gateMsg = "HTTP {$http}";
}

// ── Notify resident via cloud relay ──────────────────────
if ($access && $code !== '') {
    $erfno = '';
    if ($entryType === 'visitor' && isset($vis) && $vis) {
        $erfno = $vis['resident_erfno'] ?? '';
    } elseif ($entryType === 'service_provider' && isset($sp) && $sp) {
        $erfno = $sp['resident_erfno'] ?? '';
    }

    if ($erfno) {
        $gateLabel = $gates[$gate] ?? $gate;
        $ch = curl_init(PI_CLOUD_URL . '/../pi_notify_api.php');
        // Build absolute URL cleanly
        $notifyUrl = rtrim(str_replace('pi_sync_api.php', '', PI_CLOUD_URL), '/') . '/pi_notify_api.php';
        $ch = curl_init($notifyUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query([
                'resident_erfno' => $erfno,
                'visitor_name'   => $name,
                'entry_type'     => $entryType,
                'direction'      => $direction,
                'gate_label'     => $gateLabel,
                'timestamp'      => date('d M Y H:i'),
            ]),
            CURLOPT_HTTPHEADER     => ['Authorization: Bearer ' . PI_SYNC_KEY],
            CURLOPT_TIMEOUT        => 6,
            CURLOPT_CONNECTTIMEOUT => 4,
        ]);
        curl_exec($ch);
        curl_close($ch);
    }
}

$showForm = ($code === '');
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
  <title><?= $showForm ? 'GEMB Gate' : ($access ? '✅ GO' : '⛔ STOP') ?></title>
  <link rel="manifest" href="/gemb/manifest.json">
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="GEMB Gate">
  <meta name="theme-color" content="#003366">
  <link rel="apple-touch-icon" href="/gemb/icons/icon-192.png">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
           background: #000; min-height: 100vh; display: flex; flex-direction: column;
           align-items: center; padding-bottom: 40px; }
    .offline-banner { width: 100%; background: #7a4f00; color: #ffe; text-align: center;
                      padding: 8px 16px; font-size: 0.9rem; font-weight: 600; }
    .guard-bar { width: 100%; background: #111; color: rgba(255,255,255,0.6);
                 text-align: center; padding: 6px 16px; font-size: 0.85rem; }
    .guard-bar a { color: #ffdd00; text-decoration: none; margin-left: 12px; font-size: 0.8rem; }
    .result-band { width: 100%; padding: 36px 24px 28px; text-align: center; }
    .result-band.go   { background: #006600; }
    .result-band.stop { background: #aa0000; }
    .result-band.form { background: #003366; }
    .result-headline { font-size: 4rem; font-weight: 900; color: #fff; line-height: 1; }
    .result-sub { font-size: 1.25rem; color: rgba(255,255,255,0.9); margin-top: 12px; font-weight: 600; }
    .gate-chip { display: inline-block; margin-top: 14px; padding: 7px 20px; border-radius: 20px;
                 font-size: 0.95rem; font-weight: 700; }
    .gate-chip.ok   { background: rgba(255,255,255,0.2); color: #fff; }
    .gate-chip.fail { background: rgba(255,220,0,0.3); color: #ffe; }
    .detail-card { width: calc(100% - 32px); max-width: 460px;
                   background: rgba(255,255,255,0.10); border-radius: 14px;
                   margin: 18px 0 0; overflow: hidden; }
    .detail-row { display: flex; justify-content: space-between; padding: 13px 18px;
                  border-bottom: 1px solid rgba(255,255,255,0.08); font-size: 1.05rem; color: #fff; }
    .detail-row:last-child { border-bottom: none; }
    .detail-label { font-weight: 700; opacity: 0.7; min-width: 100px; flex-shrink: 0; }
    .detail-value { text-align: right; word-break: break-word; max-width: 60%; }
    .mono { font-family: 'Courier New', monospace; font-weight: 800;
            font-size: 1.15rem; letter-spacing: 0.18em; }
    .btn-row { width: calc(100% - 32px); max-width: 460px; display: flex; gap: 12px; margin: 16px 0 0; }
    .btn { flex: 1; min-height: 64px; border: none; border-radius: 14px;
           font-size: 1.1rem; font-weight: 800; cursor: pointer; text-decoration: none;
           display: flex; align-items: center; justify-content: center; }
    .btn:active { transform: scale(0.97); }
    .btn-yellow { background: #ffdd00; color: #000; }
    .btn-blue   { background: #0055cc; color: #fff; }
    .btn-red    { background: #880000; color: #fff; }
    .btn-reopen { width: calc(100% - 32px); max-width: 460px; min-height: 56px;
                  background: rgba(255,255,255,0.15); color: #fff;
                  border: 2px solid rgba(255,255,255,0.3); border-radius: 12px;
                  font-size: 1rem; font-weight: 700; cursor: pointer; margin: 12px 0 0;
                  text-decoration: none; display: flex; align-items: center; justify-content: center; }
    .form-card { width: calc(100% - 32px); max-width: 460px;
                 background: rgba(255,255,255,0.10); border-radius: 14px;
                 margin: 20px 0 0; padding: 24px; }
    .form-card label { color: rgba(255,255,255,0.7); font-size: 0.9rem;
                       display: block; margin-bottom: 6px; }
    .form-card input, .form-card select {
      width: 100%; padding: 14px 16px; border: none; border-radius: 10px;
      font-size: 1.15rem; font-weight: 700; letter-spacing: 0.08em;
      background: rgba(255,255,255,0.15); color: #fff; margin-bottom: 14px;
      text-transform: uppercase; }
    .form-card input::placeholder { opacity: 0.5; font-weight: 400; letter-spacing: normal; }
    .form-card select option { background: #222; color: #fff; }
    .form-card button { width: 100%; padding: 18px; background: #ffdd00; color: #000;
                        border: none; border-radius: 10px; font-size: 1.3rem;
                        font-weight: 900; cursor: pointer; }
    .form-hint { color: rgba(255,255,255,0.45); font-size: 0.85rem; margin-top: 12px; text-align: center; }
  </style>
</head>
<body>

<div class="offline-banner">
  📡 OFFLINE MODE — Pi node &nbsp;|&nbsp; Last sync: <?= htmlspecialchars($syncAge) ?>
</div>
<div class="guard-bar">
  👮 <?= htmlspecialchars($guardName) ?> &nbsp;·&nbsp; <?= htmlspecialchars($gates[$gate] ?? $gate) ?>
  <a href="verify.php?logout=1">Logout</a>
</div>

<?php if ($showForm): ?>

<div class="result-band form">
  <div class="result-headline">🔐 GATE</div>
  <div class="result-sub">Offline Verification</div>
</div>

<div class="form-card">
  <form method="GET" action="verify.php">
    <label>QR Code or Plate Number</label>
    <input type="text" name="code" autofocus autocomplete="off"
           inputmode="text" placeholder="e.g. 312345 or ABC123GP">
    <label>Direction</label>
    <select name="dir">
      <option value="ENTRY" <?= $direction==='ENTRY'?'selected':'' ?>>ENTRY</option>
      <option value="EXIT"  <?= $direction==='EXIT' ?'selected':'' ?>>EXIT</option>
    </select>
    <label>Gate</label>
    <select name="gate">
      <?php foreach ($gates as $key => $label): ?>
        <option value="<?= htmlspecialchars($key) ?>" <?= $key===$gate?'selected':'' ?>>
          <?= htmlspecialchars($label) ?>
        </option>
      <?php endforeach; ?>
    </select>
    <button type="submit">VERIFY ▶</button>
  </form>
  <p class="form-hint">Enter the 6-digit visitor/SP code, or a plate number.</p>
</div>

<?php else: ?>

<div class="result-band <?= $access ? 'go' : 'stop' ?>">
  <div class="result-headline"><?= $access ? '✅ GO' : '⛔ STOP' ?></div>
  <div class="result-sub"><?= htmlspecialchars($reason) ?></div>
  <?php if ($access): ?>
    <div class="gate-chip <?= $gateOk ? 'ok' : 'fail' ?>">
      <?= $gateOk ? '🔓 Gate opening…' : '⚠️ Gate: '.htmlspecialchars($gateMsg) ?>
    </div>
  <?php endif; ?>
</div>

<div class="detail-card">
  <div class="detail-row">
    <span class="detail-label">Code</span>
    <span class="detail-value mono"><?= htmlspecialchars($code) ?></span>
  </div>
  <?php if ($name && $name !== $code): ?>
  <div class="detail-row">
    <span class="detail-label">Name</span>
    <span class="detail-value"><?= htmlspecialchars($name) ?></span>
  </div>
  <?php endif; ?>
  <?php if ($detail): ?>
  <div class="detail-row">
    <span class="detail-label">Detail</span>
    <span class="detail-value"><?= htmlspecialchars($detail) ?></span>
  </div>
  <?php endif; ?>
  <?php if ($plate): ?>
  <div class="detail-row">
    <span class="detail-label">Vehicle</span>
    <span class="detail-value"><?= htmlspecialchars(strtoupper($plate)) ?></span>
  </div>
  <?php endif; ?>
  <div class="detail-row">
    <span class="detail-label">Direction</span>
    <span class="detail-value"><?= $direction ?></span>
  </div>
  <div class="detail-row">
    <span class="detail-label">Gate</span>
    <span class="detail-value"><?= htmlspecialchars($gates[$gate] ?? $gate) ?></span>
  </div>
  <div class="detail-row">
    <span class="detail-label">Guard</span>
    <span class="detail-value"><?= htmlspecialchars($guardName) ?></span>
  </div>
  <div class="detail-row">
    <span class="detail-label">Time</span>
    <span class="detail-value"><?= date('d M Y H:i:s') ?></span>
  </div>
</div>

<?php if ($access): ?>
<a href="verify.php?code=<?= urlencode($code) ?>&dir=<?= $direction ?>&gate=<?= $gate ?>&nogate=0"
   class="btn-reopen">
  🔓 <?= $gateOk ? 'Open Gate Again' : 'Retry Gate Open' ?>
</a>
<?php endif; ?>

<div class="btn-row">
  <a href="verify.php?gate=<?= $gate ?>&dir=<?= $direction ?>" class="btn btn-yellow">← New Code</a>
  <a href="verify.php?logout=1" class="btn btn-red">Logout</a>
</div>

<?php endif; ?>

<script>
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/gemb/sw.js').catch(()=>{});
}
</script>

</body>
</html>
