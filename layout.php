<?php
// ============================================================
// GEMB Access Control — layout.php
// Shared header, footer, auth guards, and CSS design system
// ============================================================
require_once __DIR__ . '/config.php';
date_default_timezone_set('Africa/Johannesburg');

// ── SameSite=Strict on all device cookies ─────────────────
// Called once at file-include time (before any output).
// Re-issues every gemb_* device cookie with SameSite=Strict,
// preventing them being sent in cross-site requests (CSRF layer).

ensureSession();


// ── Security headers ──────────────────────────────────────
if (!headers_sent()) {
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header("Content-Security-Policy: "
         . "default-src 'self'; "
         . "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://chart.googleapis.com; "
         . "style-src 'self' 'unsafe-inline'; "
         . "img-src 'self' data: https://chart.googleapis.com; "
         . "connect-src 'self'; "
         . "frame-ancestors 'none';");
}

// ── Auth guard functions ──────────────────────────────────
function requireAdmin(): void {
    if (session_status() === PHP_SESSION_NONE) session_start();
    checkSessionTimeout();
    if (empty($_SESSION['admin_id'])) {
        header('Location: admin.php?action=login'); exit;
    }

    // Single-active-session enforcement: a newer login from another
    // device overwrites admins.active_session_token, which invalidates
    // every other session for that account on its very next request.
    $tok = $_SESSION['admin_session_token'] ?? '';
    $stmt = db()->prepare("SELECT active_session_token FROM admins WHERE id=? LIMIT 1");
    $stmt->execute([$_SESSION['admin_id']]);
    $current = $stmt->fetchColumn();

    if ($tok === '' || $current === false || !hash_equals((string)$current, $tok)) {
        session_unset();
        session_destroy();
        header('Location: admin.php?action=login&err=elsewhere');
        exit;
    }
}
function requireSecurity(): void {
    if (session_status() === PHP_SESSION_NONE) session_start();
    checkSessionTimeout();
    if (empty($_SESSION['security_id'])) {
        header('Location: security.php?action=login'); exit;
    }
}
function requireGuard(): void {
    if (session_status() === PHP_SESSION_NONE) session_start();
    checkSessionTimeout();
    if (empty($_SESSION['guard_id'])) {
        header('Location: guard.php?action=login'); exit;
    }
}
function requireResident(): void {
    if (session_status() === PHP_SESSION_NONE) session_start();
    checkSessionTimeout();
    if (empty($_SESSION['resident_id'])) {
        header('Location: resident.php?action=login'); exit;
    }
}

// ── Page header ───────────────────────────────────────────
function pageHeader(string $title, string $role = ''): void {
    $GLOBALS['_page_role'] = $role;

    $roleColors = [
        'admin'    => '#c0392b',
        'security' => '#8e44ad',
        'guard'    => '#1a6b3c',
        'resident' => '#1565c0',
        'public'   => '#1a3c5e',
        ''         => '#1a3c5e',
    ];
    $accent = $roleColors[$role] ?? '#1a3c5e';
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title><?= htmlspecialchars($title) ?> | GEMB Access</title>
<link rel="manifest" href="<?= $role === 'resident' ? '/manifest-resident.php' : ($role === 'security' ? '/manifest-security.php' : ($role === 'admin' ? '/manifest-admin.php' : '/manifest-guard.php')) ?>">
<meta name="theme-color" content="<?= $accent ?>">
<style>
/* ── Design tokens ── */
:root {
  --accent:    <?= $accent ?>;
  --bg:        #f4f6f9;
  --card-bg:   #ffffff;
  --text:      #1a1a2e;
  --muted:     #6c757d;
  --border:    #dee2e6;
  --success:   #28a745;
  --danger:    #dc3545;
  --warning:   #ffc107;
  --info:      #17a2b8;
  --radius:    10px;
  --shadow:    0 2px 12px rgba(0,0,0,.08);
  --font:      -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); font-family: var(--font); color: #1a1a2e; color: var(--text); min-height: 100vh; }

/* ── Header ── */
.site-header {
  background: <?= $accent ?>; background: var(--accent); color: #fff; padding: 0 16px;
  display: -webkit-box; display: -webkit-flex; display: flex;
  -webkit-box-align: center; -webkit-align-items: center; align-items: center;
  -webkit-box-pack: justify; -webkit-justify-content: space-between; justify-content: space-between;
  height: 56px; position: -webkit-sticky; position: sticky; top: 0; z-index: 100;
  box-shadow: 0 2px 8px rgba(0,0,0,.2);
}
.site-header h1 { font-size: 1.05rem; font-weight: 600; letter-spacing: .3px; }
.site-header a.logout-btn {
  color: rgba(255,255,255,.85); font-size: .8rem; text-decoration: none;
  border: 1px solid rgba(255,255,255,.4); padding: 4px 10px; border-radius: 20px;
}
.site-header a.logout-btn:hover { background: rgba(255,255,255,.15); }

/* ── Main container ── */
.container { max-width: 860px; margin: 0 auto; padding: 20px 16px 60px; }

/* ── Cards ── */
.card {
  background: var(--card-bg); border-radius: var(--radius);
  box-shadow: var(--shadow); padding: 20px; margin-bottom: 18px;
}
.card-title { font-size: 1rem; font-weight: 600; margin-bottom: 14px; color: <?= $accent ?>; color: var(--accent); }

/* ── Menu grid ── */
.menu-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px,1fr)); gap: 12px; }
.menu-btn {
  display: -webkit-box; display: -webkit-flex; display: flex;
  -webkit-box-orient: vertical; -webkit-box-direction: normal;
  -webkit-flex-direction: column; flex-direction: column;
  -webkit-box-align: center; -webkit-align-items: center; align-items: center;
  -webkit-box-pack: center; -webkit-justify-content: center; justify-content: center;
  background: var(--card-bg); border: 2px solid <?= $accent ?>; border: 2px solid var(--accent);
  border-radius: var(--radius); padding: 18px 10px; text-decoration: none;
  color: <?= $accent ?>; color: var(--accent); font-weight: 600; font-size: .85rem; text-align: center;
  transition: all .2s; gap: 8px;
}
.menu-btn:hover { background: var(--accent); color: #fff; transform: translateY(-2px); box-shadow: var(--shadow); }
.menu-btn .icon { font-size: 1.8rem; }

/* ── Forms ── */
.form-group { margin-bottom: 14px; }
.form-group label { display: block; font-size: .85rem; font-weight: 600; margin-bottom: 5px; color: #6c757d; color: var(--muted); }
.form-group input, .form-group select, .form-group textarea {
  width: 100%; padding: 10px 12px; border: 1px solid #dee2e6; border: 1px solid var(--border);
  border-radius: 6px; font-size: .95rem; font-family: var(--font);
  transition: border-color .2s;
}
.form-group input:focus, .form-group select:focus, .form-group textarea:focus {
  outline: none; border-color: <?= $accent ?>; border-color: var(--accent);
}
.btn {
  display: inline-block; padding: 10px 22px; border-radius: 6px;
  font-size: .95rem; font-weight: 600; cursor: pointer; border: none;
  text-decoration: none; transition: opacity .2s;
}
.btn:hover { opacity: .85; }
.btn-primary   { background: <?= $accent ?>; background: var(--accent); color: #fff; }
.btn-success   { background: var(--success); color: #fff; }
.btn-danger    { background: var(--danger); color: #fff; }
.btn-secondary { background: #6c757d; background: var(--muted); color: #fff; }
.btn-grey      { background: #6c757d; color: #fff; }
.btn-sm        { padding: 5px 12px; font-size: .82rem; }
.btn-block     { display: block; width: 100%; text-align: center; }

/* ── Tables ── */
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: .88rem; }
th { background: <?= $accent ?>; background: var(--accent); color: #fff; padding: 9px 10px; text-align: left; font-weight: 600; }
td { padding: 8px 10px; border-bottom: 1px solid var(--border); }
tr:hover td { background: #f8f9fa; }

/* ── Badges ── */
.badge {
  display: inline-block; padding: 3px 9px; border-radius: 20px;
  font-size: .75rem; font-weight: 700; text-transform: uppercase;
}
.badge-success  { background: #d4edda; color: #155724; }
.badge-danger   { background: #f8d7da; color: #721c24; }
.badge-warning  { background: #fff3cd; color: #856404; }
.badge-info     { background: #d1ecf1; color: #0c5460; }
.badge-muted    { background: #e2e3e5; color: #383d41; }

/* ── Alert boxes ── */
.alert { padding: 12px 16px; border-radius: 6px; margin-bottom: 14px; font-size: .92rem; }
.alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
.alert-danger  { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
.alert-info    { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
.alert-warning { background: #fff3cd; color: #856404; border: 1px solid #ffeeba; }

/* ── Login page ── */
.login-wrap {
  min-height: 100vh; display: -webkit-box; display: -webkit-flex; display: flex;
  -webkit-box-align: center; -webkit-align-items: center; align-items: center;
  -webkit-box-pack: center; -webkit-justify-content: center; justify-content: center;
  background: <?= $accent ?>; background: linear-gradient(135deg, var(--accent) 0%, #1a1a2e 100%); padding: 20px;
}
.login-card {
  background: #fff; border-radius: 14px; padding: 36px 28px;
  width: 100%; max-width: 380px; box-shadow: 0 8px 32px rgba(0,0,0,.25);
}
.login-card h2 { text-align: center; color: <?= $accent ?>; color: var(--accent); margin-bottom: 6px; }
.login-card .subtitle { text-align: center; color: #6c757d; color: var(--muted); font-size: .85rem; margin-bottom: 24px; }
.login-logo { text-align: center; font-size: 3rem; margin-bottom: 10px; }

/* ── POPIA notice ── */
.popia-notice {
  font-size: .75rem; color: #6c757d; color: var(--muted); border-top: 1px solid #dee2e6; border-top: 1px solid var(--border);
  margin-top: 16px; padding-top: 10px; line-height: 1.4;
}

/* ── Footer ── */
.site-footer {
  text-align: center; font-size: .72rem; color: #6c757d; color: var(--muted);
  padding: 14px; border-top: 1px solid #dee2e6; border-top: 1px solid var(--border); margin-top: 30px;
}

/* ── Mobile ── */
@media (max-width: 600px) {
  .menu-grid { grid-template-columns: repeat(2,1fr); }
  .container { padding: 14px 10px 60px; }
  .hide-mobile { display: none; }
}

/* ════════════════════════════════════════════════════════
   ELDERLY-FRIENDLY RESIDENT LAYOUT
   Scoped to .role-resident only — admin/security/guard
   screens are untouched. Targets old devices too (e.g.
   iPhone 4 / iOS 7): single-column flex instead of CSS
   Grid (unsupported pre-iOS 10.3), -webkit- prefixes on
   every flex declaration, and larger everything.
   ════════════════════════════════════════════════════════ */
.role-resident .container { max-width: 480px; }

.role-resident .menu-grid {
  display: -webkit-box; display: -webkit-flex; display: flex;
  -webkit-box-orient: vertical; -webkit-box-direction: normal;
  -webkit-flex-direction: column; flex-direction: column;
  gap: 14px;
}
.role-resident .menu-btn {
  -webkit-box-orient: horizontal; -webkit-box-direction: normal;
  -webkit-flex-direction: row; flex-direction: row;
  -webkit-box-pack: flex-start; -webkit-justify-content: flex-start; justify-content: flex-start;
  min-height: 78px;
  padding: 16px 20px;
  border-width: 3px;
  border-radius: 14px;
  font-size: 1.25rem;
  font-weight: 700;
  gap: 16px;
}
.role-resident .menu-btn .icon { font-size: 2.1rem; }
.role-resident .menu-btn:active { background: <?= $accent ?>; background: var(--accent); color: #fff; }

.role-resident .site-header h1 { font-size: 1.15rem; }
.role-resident .site-header { height: 62px; }
.role-resident .site-header a.logout-btn {
  font-size: 1rem; padding: 8px 16px; border-width: 2px;
}

.role-resident .card { padding: 20px; }
.role-resident .card-title { font-size: 1.1rem; }

.role-resident .form-group label { font-size: 1.05rem; margin-bottom: 8px; }
.role-resident .form-group input,
.role-resident .form-group select,
.role-resident .form-group textarea {
  font-size: 1.2rem;
  padding: 14px 16px;
  min-height: 52px;
  border-width: 2px;
  border-radius: 8px;
}

.role-resident .btn {
  padding: 16px 26px;
  font-size: 1.15rem;
  font-weight: 700;
  border-radius: 10px;
  min-height: 56px;
}
.role-resident .btn-sm {
  padding: 10px 16px;
  font-size: 1rem;
  min-height: 44px;
}

.role-resident .badge {
  font-size: .85rem;
  padding: 5px 12px;
}

.role-resident .alert {
  font-size: 1.05rem;
  padding: 14px 18px;
}

.role-resident .popia-notice,
.role-resident .site-footer {
  font-size: .82rem;
}
</style>
</head>
<body class="role-<?= htmlspecialchars($role ?: 'public') ?>">
    <?php
}

// ── Page footer ───────────────────────────────────────────
function pageFooter(): void {
    $role = $GLOBALS['_page_role'] ?? '';
    ?>
<div class="site-footer">
  GEMB Access Control &nbsp;|&nbsp; POPIA Act 4 of 2013 &nbsp;|&nbsp; PSIRA Act 56 of 2001
</div>
<script>
if ('serviceWorker' in navigator) {
  var sw = <?= $role === 'resident' ? "'/sw-resident.php'" : ($role === 'security' ? "'/sw-security.php'" : ($role === 'admin' ? "'/sw-admin.php'" : "'/sw.php'")) ?>;
  navigator.serviceWorker.register(sw).catch(function(){});
}
</script>
</body>
</html>
    <?php
}

// ── Render page header bar ────────────────────────────────
function renderHeader(string $title, string $logoutUrl = 'logout.php'): void {
    echo '<div class="site-header">';
    echo '<h1>🏌️ ' . htmlspecialchars($title) . '</h1>';
    echo '<a href="' . $logoutUrl . '" class="logout-btn">Logout</a>';
    echo '</div>';
}
