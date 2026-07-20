<?php
/**
 * twilio_helper.php — GEMB notifications and OTP
 *
 * All email is sent via smtpSend() in smtp_mail.php (SMTP AUTH).
 * SMTP credentials are defined as constants in config.php.
 */

// ── Ensure OTP table exists ───────────────────────────────────────────────────
// otp column holds a password_hash() of the code, not the code itself —
// matches the pattern already used by the Comms Portal's own
// comms_otp_helper.php. VARCHAR(255) (not CHAR(6)) because a bcrypt hash
// is ~60 characters. See sql/2026_07_gemb_security_upgrade.sql for the
// migration that widens this column on an existing table.
function ensureOtpTable(): void {
    db()->exec("CREATE TABLE IF NOT EXISTS otp_tokens (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        phone      VARCHAR(20)  NOT NULL,
        otp        VARCHAR(255) NOT NULL,
        expires_at DATETIME     NOT NULL,
        used       TINYINT(1)   DEFAULT 0,
        created_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_phone (phone)
    )");
}

// ── Normalise a SA phone number to E.164 (27XXXXXXXXX) ───────────────────────
function normalisePhone(string $phone): string {
    $phone = preg_replace('/\D/', '', $phone);
    if (substr($phone, 0, 1) === '0')  $phone = '27' . substr($phone, 1);
    if (substr($phone, 0, 2) !== '27') $phone = '27' . $phone;
    return $phone;
}

// ── Send email via SMTP AUTH (smtp_mail.php / smtpSend) ──────────────────────
function sendEmail(string $toEmail, string $subject, string $body): bool {
    if (!$toEmail) {
        error_log('GEMB Email: no recipient address');
        return false;
    }
    require_once __DIR__ . '/smtp_mail.php';
    $html = '<html><body style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px;">'
          . nl2br(htmlspecialchars($body, ENT_QUOTES, 'UTF-8'))
          . '</body></html>';
    return smtpSend($toEmail, $subject, $html);
}

// ── Generate and send a 6-digit OTP via email ─────────────────────────────────
function generateOtp(string $phone, string $email): bool {
    ensureOtpTable();
    $phone = normalisePhone($phone);

    db()->prepare("UPDATE otp_tokens SET used=1 WHERE phone=? AND used=0")
        ->execute([$phone]);

    $otp     = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    $expires = date('Y-m-d H:i:s', time() + 300);

    db()->prepare("INSERT INTO otp_tokens (phone, otp, expires_at) VALUES (?, ?, ?)")
        ->execute([$phone, password_hash($otp, PASSWORD_BCRYPT), $expires]);

    $subject = 'GEMB Access Control - Your Login Code';
    $body    = "GEMB Access Control\n\n"
             . "Your login code: {$otp}\n\n"
             . "Valid for 5 minutes. Do not share this code.\n\n"
             . "GEMB HOA | POPIA Act 4 of 2013";

    return sendEmail($email, $subject, $body);
}

// ── Verify an OTP ─────────────────────────────────────────────────────────────
function verifyOtp(string $phone, string $otp): bool {
    ensureOtpTable();
    $phone = normalisePhone($phone);
    $otp   = preg_replace('/\D/', '', trim($otp));

    $stmt = db()->prepare(
        "SELECT id, otp FROM otp_tokens
         WHERE phone=? AND used=0 AND expires_at > NOW()
         ORDER BY id DESC LIMIT 1"
    );
    $stmt->execute([$phone]);
    $row = $stmt->fetch();

    if (!$row || !password_verify($otp, $row['otp'])) return false;

    db()->prepare("UPDATE otp_tokens SET used=1 WHERE id=?")->execute([$row['id']]);
    return true;
}

// ── EMAIL-KEYED OTP (for admins / email-first accounts) ───────────────────────
// Keys the OTP on a hash of the email address (fits VARCHAR(20), never
// collides with a real phone number because it starts with 'E').
function emailOtpKey(string $email): string {
    return 'E' . substr(md5(strtolower(trim($email))), 0, 15); // 16 chars
}

function generateEmailOtp(string $email): bool {
    ensureOtpTable();
    $email = trim($email);
    if ($email === '') {
        error_log('GEMB Email OTP: no email address supplied');
        return false;
    }
    $key = emailOtpKey($email);

    db()->prepare("UPDATE otp_tokens SET used=1 WHERE phone=? AND used=0")
        ->execute([$key]);

    $otp     = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    $expires = date('Y-m-d H:i:s', time() + 300);

    db()->prepare("INSERT INTO otp_tokens (phone, otp, expires_at) VALUES (?, ?, ?)")
        ->execute([$key, password_hash($otp, PASSWORD_BCRYPT), $expires]);

    $subject = 'GEMB Access Control - Your Login Code';
    $body    = "GEMB Access Control\n\n"
             . "Your login code: {$otp}\n\n"
             . "Valid for 5 minutes. Do not share this code.\n\n"
             . "GEMB HOA | POPIA Act 4 of 2013";

    return sendEmail($email, $subject, $body);
}

function verifyEmailOtp(string $email, string $otp): bool {
    ensureOtpTable();
    $key = emailOtpKey($email);
    $otp = preg_replace('/\D/', '', trim($otp));

    $stmt = db()->prepare(
        "SELECT id, otp FROM otp_tokens
         WHERE phone=? AND used=0 AND expires_at > NOW()
         ORDER BY id DESC LIMIT 1"
    );
    $stmt->execute([$key]);
    $row = $stmt->fetch();

    if (!$row || !password_verify($otp, $row['otp'])) return false;

    db()->prepare("UPDATE otp_tokens SET used=1 WHERE id=?")->execute([$row['id']]);
    return true;
}

// ── Resident entry notification ───────────────────────────────────────────────
function notifyResidentEntry(
    string $residentEmail,
    string $visitorName,
    string $category,
    string $gate,
    string $timestamp = ''
): void {
    if (!$residentEmail) return;
    if (!$timestamp) $timestamp = date('d M Y H:i');

    $label   = $category === 'service_provider' ? 'Service Provider' : 'Visitor';
    $subject = "GEMB - {$label} Arrived";
    $body    = "GEMB Access Control\n\n"
             . "{$label} ARRIVED\n\n"
             . "Name:  {$visitorName}\n"
             . "Gate:  {$gate}\n"
             . "Time:  {$timestamp}\n\n"
             . "GEMB HOA";

    sendEmail($residentEmail, $subject, $body);
}

// ── Resident exit notification ────────────────────────────────────────────────
function notifyResidentExit(
    string $residentEmail,
    string $visitorName,
    string $category,
    string $gate,
    string $timestamp = ''
): void {
    if (!$residentEmail) return;
    if (!$timestamp) $timestamp = date('d M Y H:i');

    $label   = $category === 'service_provider' ? 'Service Provider' : 'Visitor';
    $subject = "GEMB - {$label} Departed";
    $body    = "GEMB Access Control\n\n"
             . "{$label} DEPARTED\n\n"
             . "Name:  {$visitorName}\n"
             . "Gate:  {$gate}\n"
             . "Time:  {$timestamp}\n\n"
             . "GEMB HOA";

    sendEmail($residentEmail, $subject, $body);
}
