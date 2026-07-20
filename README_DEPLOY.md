# GEMB Access Control — Security Upgrade & UI Consistency Fix

Built against the actual, current `Program/AccessP` codebase (confirmed
git-tracked, live at gemb.co.za). Every file below is a targeted edit to
a real file already in your project — nothing here is a parallel/reference
copy this time.

## What changed and why

### 1. Security Officer's "new device" step now sends a real code (`security.php`)
Previously compared the entered code against the last 6 digits of the
officer's own phone number — not a secret, not one-time. Now sends a
genuine random 6-digit code by email, using the exact same
`generateEmailOtp()`/`verifyEmailOtp()` functions `admin.php` already uses
successfully. Requires `security_users.email` to be populated — it
already exists as a column (`forgot.php` already reads it), just wasn't
used at login before.

### 2. Guard's "new device" step now uses TOTP (`guard.php`, `pi/verify.php`)
Same underlying flaw as Security, but fixed differently: Guard can't use
emailed codes, because the offline Pi gate node (`pi/verify.php`) must
keep authenticating with zero internet connectivity, and sending an email
needs a network call. TOTP (Google Authenticator / Authy / Microsoft
Authenticator style) verifies with pure local arithmetic against a secret
already on the device — no network call at verification time — so it's
the one real one-time-code mechanism that also works offline.

- First time a guard hits an unrecognised device, `guard.php` (cloud)
  generates a secret, shows a QR code (using the `phpqrcode` library
  already vendored in your codebase) plus a manual-entry key, and asks
  for one confirmation code.
- After that, it's a normal "enter the 6-digit code" screen, same as
  before — just checked against TOTP instead of a phone digit.
- **Enrolment only ever happens on the cloud side.** The Pi's local
  SQLite `guards` table gets wholesale-replaced on every sync pull from
  the cloud (see `pi/sync.php`) — anything enrolled locally on the Pi
  would be silently destroyed on the next sync. So `pi/verify.php` only
  ever *verifies* an already-confirmed secret; if a guard reaches the
  gate before ever completing setup online, they're told to do that
  first with a clear message, not left stuck.
- The new secret/confirmed columns are added to the pull payload
  (`pi_sync_api.php`) and the local insert (`pi/sync.php`) so they flow
  down to the Pi the same way guard PINs already do.

### 3. OTP codes are now hashed at rest (`twilio_helper.php`)
The Comms Portal's own `comms_otp_helper.php` already stores OTPs as a
`password_hash()`, never plaintext. The main access system's
`twilio_helper.php` (used by Admin/Security/Resident) was storing the
raw 6-digit code in the database. Brought up to the same standard the
Comms Portal already set — same short 5-minute expiry either way, this
just removes a plaintext code from ever sitting in the database.

### 4. Post-login banner now matches each portal's identity (`layout.php`)
`renderHeader()` — the sticky top bar shown on every page after login —
was hardcoded to a golf emoji (🏌️) for all four roles, even though each
role's *login screen* already has a distinct one (⚙️ Admin, 🛡️ Security,
🔐 Guard, 🏠 Resident) and a distinct accent colour. Fixed so the emoji
that greets you at login is the same one that stays with you through the
app — this is what actually delivers "you can tell at a glance which
portal you're in," which your working notes called out as a goal.

Everything else — the design token system, card/button/form styling,
security headers (CSP, HSTS, X-Frame-Options), brute-force lockout,
role-aware session timeouts, single-active-session enforcement for
Admin, the self-service `forgot.php` flow, and the Comms Portal's own
device-token/OTP/lockout implementation — was already solid and wasn't
touched. The five portals (Admin/Security/Guard/Resident via
`layout.php`, Comms via its own separate `comms/layout.php`) already
share a consistent professional visual language; this pass closes the
one real gap in it.

## Files changed

```
totp_lib.php          NEW — vendor into AccessP root (required by guard.php)
pi/totp_lib.php        NEW — byte-identical copy, vendor into pi/ on the Pi
twilio_helper.php      EDITED — OTP storage now hashed
security.php           EDITED — real email OTP replaces static phone check
guard.php               EDITED — TOTP enrolment/verification replaces static phone check
layout.php              EDITED — renderHeader() uses per-role emoji
pi_sync_api.php         EDITED — totp_secret/totp_confirmed added to guards pull payload
pi/sync.php             EDITED — same two columns added to the Pi-side insert
sql/2026_07_gemb_security_upgrade.sql   NEW — cloud MySQL migration
```

## Deploy order — this matters

1. **Run `sql/2026_07_gemb_security_upgrade.sql` against the cPanel MySQL
   database first.** `guard.php`, `security.php`, and `pi_sync_api.php`
   all reference columns this creates — uploading the code before the
   migration will break Guard and Security login in production.
2. Upload the changed root files (`twilio_helper.php`, `security.php`,
   `guard.php`, `layout.php`, `pi_sync_api.php`) plus the new
   `totp_lib.php` to `public_html/` on cPanel.
3. On the Raspberry Pi: add the two columns to its local SQLite `guards`
   table (exact statement is in the SQL file's footer — I don't have
   access to the Pi's schema file directly, since `pi/config.php` isn't
   part of this codebase snapshot, only exists on the physical device).
   Then copy `pi/totp_lib.php`, `pi/verify.php`, and `pi/sync.php` onto
   the Pi, replacing the existing ones.
4. Wait for (or trigger) the next `pi/sync.php` cron run so any guard who
   completes cloud enrolment gets their confirmed secret pulled down.
5. **Backfill `security_users.email`** for any officer who doesn't
   already have one on file — until then, that officer sees "no email on
   file, ask an administrator" instead of getting a code, by design
   (fails closed, doesn't silently skip the check).

## Test plan before going live

- Admin login from a known device — unchanged, should work exactly as
  before.
- Security login from a *new* browser/device with an officer who has an
  email on file — should receive a real emailed code, not a phone-digit
  prompt.
- Security login for an officer with no email on file — should see the
  "ask an administrator" message, not be let through.
- Guard login from a new device for a guard who has never enrolled TOTP
  — should see the QR/manual-key setup screen, and be able to complete
  it with a real authenticator app.
- Guard login from a new device for an already-enrolled guard — should
  see a plain 6-digit code prompt and succeed with the app's current
  code.
- Same guard, same already-confirmed secret, tested at the physical gate
  (Pi) after a sync — should verify locally with the Wi-Fi/data
  disconnected.
- A guard's username that was never enrolled, tried at the Pi directly —
  should see the "set up online first" message, not an error or a stuck
  screen.
- Visually: log into each of the four roles and confirm the top banner
  emoji after login now matches the login screen's emoji, not a golf
  emoji.

## Deliberately not changed — flagged, not fixed

- **Comms Portal's 30-day forced password rotation** (`comms_login.php`'s
  header comment confirms this is still active). NIST SP 800-63B
  recommends against time-based rotation — the same point your working
  notes make about this exact policy. Comms' own OTP/device-token/
  lockout implementation is otherwise already solid (arguably ahead of
  the main access system's, since it already hashes OTPs and rate-limits
  sends). Whether to drop the 30-day rotation is a policy call, not a bug
  fix, so it wasn't changed here — flagging it since you asked for
  "standardise... security... professional" and this is the one place
  Comms still diverges from current best practice.
- **The standalone `login.php`** at the AccessP root (email + 6-digit PIN
  against a `users` table, redirecting to `visitor.php`) appears to be
  orphaned — nothing in the live codebase links to it, and it doesn't
  match `resident.php`'s actual credential model (erf number + occupant
  code, 4-digit PIN, `residents` table). Left untouched; worth confirming
  whether it's dead code or a parallel feature before doing anything with
  it.
