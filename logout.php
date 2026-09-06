<?php
/**
 * logout.php — GEMB Access Control
 * Clears session completely and redirects each role to their own login screen.
 *
 * Security fixes applied (v2):
 *   1. session_unset() + session_destroy() + delete session cookie
 *      — prevents session fixation on re-login
 *   2. Role detected BEFORE session is cleared
 *   3. Cache-control headers — browser will not cache this page
 *   4. Device token cookies intentionally preserved
 *      (they are the legitimate second-factor binding;
 *       clearing them on every logout would force OTP on every return,
 *       which is the wrong UX for a guard who logs in each shift)
 *
 * v3: admin logouts now also clear admins.active_session_token,
 *     freeing the account up for single-active-session enforcement
 *     in requireAdmin(). Scoped to admin only — guard/security/
 *     resident accounts don't carry that column or that check.
 */
require_once __DIR__ . '/config.php';

if (session_status() === PHP_SESSION_NONE) session_start();
// ── Step 1: Determine redirect BEFORE destroying session ──
$redirect = 'https://www.google.co.za/index.html';                 // safe estate-neutral fallback
if      (!empty($_SESSION['admin_id']))    $redirect = 'admin.php?action=login';
elseif  (!empty($_SESSION['resident_id'])) $redirect = 'resident.php?action=login';
elseif  (!empty($_SESSION['guard_id']))    $redirect = 'guard.php?action=login';
elseif  (!empty($_SESSION['security_id'])) $redirect = 'security.php?action=login';
$reason = $_GET['reason'] ?? '';

// ── Step 1b: Free up the single-active-session lock (admin only) ──
if (!empty($_SESSION['admin_id'])) {
    db()->prepare("UPDATE admins SET active_session_token=NULL WHERE id=?")
        ->execute([(int)$_SESSION['admin_id']]);
}

// ── Step 2: Complete session destruction ──────────────────
// a) Wipe all session variables
$_SESSION = [];
// b) Delete the session cookie from the browser
//    (prevents the browser sending a now-invalid session ID on the next request)
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 42000,               // expired in the past
        $params['path'],
        $params['domain'],
        $params['secure'],
        $params['httponly']
    );
}
// c) Destroy the server-side session data
session_destroy();
// ── Step 3: Prevent the browser caching this page ─────────
// Important: a Back button after logout must not reveal a cached
// authenticated page.
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
// ── Step 4: Redirect ──────────────────────────────────────
header('Location: ' . $redirect);
exit;