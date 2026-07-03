// ============================================================
// ADD TO layout.php — alongside requireResident(), requireGuard(),
// requireAdmin(), requireSecurity()
// ============================================================
//
// requireVoteSession() — guards vote_cast.php. Checks that a
// valid token-based voting session exists (set by vote_login.php
// on successful token verification). If not, redirects to
// vote_login.php?action=login.
//
// Unlike requireResident()/requireGuard()/etc., this does NOT
// check any DB-backed user table directly — the session keys
// vote_meeting_id and vote_erf are only ever set after vote_login.php
// has already validated the token against vote_tokens.

function requireVoteSession(): void {
    if (session_status() === PHP_SESSION_NONE) session_start();

    if (empty($_SESSION['vote_meeting_id']) || empty($_SESSION['vote_erf'])) {
        header('Location: vote_login.php?action=login');
        exit;
    }

    // Optional: session idle timeout (e.g. 30 minutes of inactivity)
    $idleLimit = 30 * 60;
    if (!empty($_SESSION['vote_last_activity'])
        && (time() - $_SESSION['vote_last_activity']) > $idleLimit) {
        session_unset();
        session_destroy();
        header('Location: vote_login.php?action=login');
        exit;
    }
    $_SESSION['vote_last_activity'] = time();
}
