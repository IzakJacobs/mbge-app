<?php
// ============================================================
// PASTE-IN SNIPPET for security.php — Applications menu button
// ============================================================
//
// STEP 1 — In the MENU action of security.php, directly after the
// $openTickets count block (the try/catch that counts helpdesk
// tickets) and BEFORE pageHeader('Security Menu', 'security');
// paste this count:

    // Applications awaiting site manager action
    try {
        $pendingApps = db()->query(
            "SELECT COUNT(*) FROM applications
             WHERE status IN ('pending_verification','induction_scheduled')"
        )->fetchColumn();
    } catch (Exception $e) {
        $pendingApps = 0;   // engine tables not installed yet — button still works
    }

// STEP 2 — Inside <div class="menu-grid">, paste this button.
// Suggested position: directly after the "SP Approvals" button,
// since verification feeds card issuance:
?>
        <a href="application_admin.php" class="menu-btn">
          <span class="icon">📋</span>Applications
          <?php if ($pendingApps > 0): ?>
            <span class="badge badge-warning"><?= $pendingApps ?></span>
          <?php endif; ?>
        </a>
<?php
// That is the ONLY change security.php needs. All engine logic
// lives in the separate application_* files, which use the same
// layout.php helpers (requireSecurity, csrfField, verifyCsrfToken,
// setFlash/getFlash, pageHeader/renderHeader/pageFooter) and db().
// Nothing else in security.php is touched — zero risk to the
// existing login, approvals, guards, logs or gate override flows.
