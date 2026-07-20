-- ============================================================
-- GEMB Access Control — Security Upgrade Migration
-- Run this against the cPanel MySQL database (gembcoza_gemb)
-- BEFORE uploading the updated PHP files. guard.php, security.php,
-- and pi_sync_api.php all reference columns this script creates —
-- uploading the code first will break login for Guard and Security
-- until this has run.
--
-- All changes are additive (new nullable/zero-default columns, or
-- ALTER MODIFY that only widens an existing column) — safe to run
-- with no downtime and no data loss.
-- ============================================================

START TRANSACTION;

-- ── guards: TOTP second factor ─────────────────────────────
-- totp_secret is set the first time a guard completes one-time
-- authenticator-app setup at guard.php's login flow (cloud only —
-- the offline Pi node never generates its own secret, it only
-- verifies one already synced down). totp_confirmed flips to 1 once
-- that first code is verified.
ALTER TABLE guards
    ADD COLUMN totp_secret VARCHAR(64) NULL,
    ADD COLUMN totp_confirmed TINYINT(1) NOT NULL DEFAULT 0;

-- ── otp_tokens: widen otp column to hold a bcrypt hash ─────
-- Previously stored the 6-digit code in plaintext (CHAR(6)). Now
-- stores password_hash() of the code, matching the pattern the
-- Comms Portal's comms_otp_helper.php already used. A bcrypt hash is
-- ~60 characters, so CHAR(6) must widen to fit it.
ALTER TABLE otp_tokens
    MODIFY COLUMN otp VARCHAR(255) NOT NULL;

-- Any currently-outstanding (used=0, unexpired) OTPs were stored as
-- plaintext under the old schema and cannot be verified as hashes
-- after this migration — they're short-lived (5 minutes) by design,
-- so simply expire them; anyone mid-login just requests a fresh code.
UPDATE otp_tokens SET used = 1 WHERE used = 0;

COMMIT;

-- ============================================================
-- Raspberry Pi gate node (SQLite) — run separately on the Pi itself
-- ============================================================
-- This script only touches the cloud MySQL database. The Pi's local
-- SQLite `guards` table (created by whatever schema piDb() sets up in
-- pi/config.php, which isn't part of this codebase snapshot) needs
-- the same two new columns added by hand on the physical device:
--
--   ALTER TABLE guards ADD COLUMN totp_secret TEXT;
--   ALTER TABLE guards ADD COLUMN totp_confirmed INTEGER NOT NULL DEFAULT 0;
--
-- Run that via sqlite3 on the Pi (or however piDb() is normally
-- migrated) BEFORE the next pi/sync.php pull — pi/sync.php's guards
-- INSERT now includes these two columns and will fail without them.
