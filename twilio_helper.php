<?php
/**
 * twilio_helper.php
 *
 * GEMB notification and OTP handling.
 *
 * Requires:
 *   config.php
 *   smtp_mail.php
 *
 * Database table:
 *   auth_otp_tokens
 */

define('OTP_LIFETIME_SECONDS', 300);

define('OTP_MAX_ATTEMPTS', 5);

define('OTP_SEND_WINDOW_MINS', 15);
define('OTP_MAX_SENDS_PER_WINDOW', 3);
define('OTP_MIN_RESEND_SECONDS', 60);


/*
|--------------------------------------------------------------------------
| Phone handling
|--------------------------------------------------------------------------
*/

function normalisePhone(string $phone): string
{
    $phone = preg_replace('/\D+/', '', $phone);

    if ($phone === '') {
        return '';
    }

    if (str_starts_with($phone, '0')) {
        $phone = '27' . substr($phone, 1);
    }

    if (!str_starts_with($phone, '27')) {
        $phone = '27' . $phone;
    }

    return $phone;
}


/*
|--------------------------------------------------------------------------
| Email transport
|--------------------------------------------------------------------------
*/

function sendEmail(
    string $toEmail,
    string $subject,
    string $body
): bool {
    $toEmail = trim($toEmail);

    if (!filter_var(
        $toEmail,
        FILTER_VALIDATE_EMAIL
    )) {
        error_log(
            'GEMB email rejected: invalid recipient'
        );

        return false;
    }

    require_once __DIR__ . '/smtp_mail.php';

    $html =
        '<html><body ' .
        'style="font-family:Arial,sans-serif;' .
        'max-width:500px;margin:0 auto;padding:20px;">' .
        nl2br(
            htmlspecialchars(
                $body,
                ENT_QUOTES | ENT_SUBSTITUTE,
                'UTF-8'
            )
        ) .
        '</body></html>';

    return smtpSend(
        $toEmail,
        $subject,
        $html
    );
}


/*
|--------------------------------------------------------------------------
| OTP internals
|--------------------------------------------------------------------------
*/

function otpCreateCode(): string
{
    return str_pad(
        (string)random_int(0, 999999),
        6,
        '0',
        STR_PAD_LEFT
    );
}


/**
 * Return whether another OTP may be issued.
 */
function otpCanSend(
    string $subjectKey,
    string $purpose
): bool {
    $stmt = db()->prepare("
        SELECT
            COUNT(*) AS send_count,
            MAX(created_at) AS last_sent
        FROM auth_otp_tokens
        WHERE subject_key = ?
          AND purpose = ?
          AND created_at >= DATE_SUB(
                NOW(),
                INTERVAL ? MINUTE
          )
    ");

    $stmt->execute([
        $subjectKey,
        $purpose,
        OTP_SEND_WINDOW_MINS,
    ]);

    $row = $stmt->fetch();

    if (!$row) {
        return true;
    }

    if (
        (int)$row['send_count'] >=
        OTP_MAX_SENDS_PER_WINDOW
    ) {
        return false;
    }

    if (!empty($row['last_sent'])) {
        $seconds =
            time() -
            strtotime($row['last_sent']);

        if ($seconds < OTP_MIN_RESEND_SECONDS) {
            return false;
        }
    }

    return true;
}


/**
 * Generate an OTP and store only its HMAC.
 */
function otpIssue(
    string $subjectKey,
    string $purpose
): ?string {
    if (!otpCanSend(
        $subjectKey,
        $purpose
    )) {
        return null;
    }

    /*
     * Invalidate any still-active OTP for the same purpose.
     */
    db()->prepare("
        UPDATE auth_otp_tokens
        SET used_at = NOW()
        WHERE subject_key = ?
          AND purpose = ?
          AND used_at IS NULL
    ")->execute([
        $subjectKey,
        $purpose,
    ]);

    $otp = otpCreateCode();

    $hash = hashOtpCode(
        $purpose,
        $otp
    );

    $expires = date(
        'Y-m-d H:i:s',
        time() + OTP_LIFETIME_SECONDS
    );

    db()->prepare("
        INSERT INTO auth_otp_tokens (
            subject_key,
            purpose,
            otp_hash,
            attempts,
            expires_at
        )
        VALUES (?, ?, ?, 0, ?)
    ")->execute([
        $subjectKey,
        $purpose,
        $hash,
        $expires,
    ]);

    return $otp;
}


/**
 * Atomic verification.
 *
 * Returns:
 * [
 *   'ok' => bool,
 *   'reason' => valid|invalid|expired|locked|missing
 *   'attempts_remaining' => int
 * ]
 */
function otpVerify(
    string $subjectKey,
    string $purpose,
    string $submittedOtp
): array {
    $submittedOtp = preg_replace(
        '/\D+/',
        '',
        trim($submittedOtp)
    );

    if (strlen($submittedOtp) !== 6) {
        return [
            'ok' => false,
            'reason' => 'invalid',
            'attempts_remaining' =>
                OTP_MAX_ATTEMPTS,
        ];
    }

    $pdo = db();

    $pdo->beginTransaction();

    try {
        $stmt = $pdo->prepare("
            SELECT
                id,
                otp_hash,
                attempts,
                expires_at
            FROM auth_otp_tokens
            WHERE subject_key = ?
              AND purpose = ?
              AND used_at IS NULL
            ORDER BY id DESC
            LIMIT 1
            FOR UPDATE
        ");

        $stmt->execute([
            $subjectKey,
            $purpose,
        ]);

        $row = $stmt->fetch();

        if (!$row) {
            $pdo->rollBack();

            return [
                'ok' => false,
                'reason' => 'missing',
                'attempts_remaining' => 0,
            ];
        }

        $id = (int)$row['id'];
        $attempts = (int)$row['attempts'];

        if (
            strtotime($row['expires_at']) <= time()
        ) {
            $pdo->prepare("
                UPDATE auth_otp_tokens
                SET used_at = NOW()
                WHERE id = ?
            ")->execute([$id]);

            $pdo->commit();

            return [
                'ok' => false,
                'reason' => 'expired',
                'attempts_remaining' => 0,
            ];
        }

        if ($attempts >= OTP_MAX_ATTEMPTS) {
            $pdo->prepare("
                UPDATE auth_otp_tokens
                SET used_at = NOW()
                WHERE id = ?
            ")->execute([$id]);

            $pdo->commit();

            return [
                'ok' => false,
                'reason' => 'locked',
                'attempts_remaining' => 0,
            ];
        }

        $candidateHash = hashOtpCode(
            $purpose,
            $submittedOtp
        );

        if (
            !hash_equals(
                $row['otp_hash'],
                $candidateHash
            )
        ) {
            $attempts++;

            $usedSql =
                $attempts >= OTP_MAX_ATTEMPTS
                ? ', used_at = NOW()'
                : '';

            $pdo->prepare("
                UPDATE auth_otp_tokens
                SET attempts = ?
                {$usedSql}
                WHERE id = ?
            ")->execute([
                $attempts,
                $id,
            ]);

            $pdo->commit();

            return [
                'ok' => false,
                'reason' =>
                    $attempts >= OTP_MAX_ATTEMPTS
                        ? 'locked'
                        : 'invalid',
                'attempts_remaining' =>
                    max(
                        0,
                        OTP_MAX_ATTEMPTS -
                        $attempts
                    ),
            ];
        }

        /*
         * Successful code is consumed in the same transaction.
         */
        $pdo->prepare("
            UPDATE auth_otp_tokens
            SET used_at = NOW()
            WHERE id = ?
        ")->execute([$id]);

        $pdo->commit();

        return [
            'ok' => true,
            'reason' => 'valid',
            'attempts_remaining' =>
                max(
                    0,
                    OTP_MAX_ATTEMPTS -
                    $attempts
                ),
        ];

    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        error_log(
            'GEMB OTP verification database failure'
        );

        return [
            'ok' => false,
            'reason' => 'error',
            'attempts_remaining' => 0,
        ];
    }
}


/*
|--------------------------------------------------------------------------
| Email OTP
|--------------------------------------------------------------------------
*/

function generateEmailOtp(
    string $email
): bool {
    $email = strtolower(trim($email));

    if (!filter_var(
        $email,
        FILTER_VALIDATE_EMAIL
    )) {
        return false;
    }

    $purpose = 'admin_login';

    $subjectKey = otpSubjectKey(
        'email',
        $email
    );

    $otp = otpIssue(
        $subjectKey,
        $purpose
    );

    if ($otp === null) {
    error_log(
        'GEMB OTP DEBUG: issuance blocked by resend/rate limit'
    );

    return false;
}

    $subject =
        'GEMB Access Control - Your Login Code';

    $body =
        "GEMB Access Control\n\n" .
        "Your login code: {$otp}\n\n" .
        "Valid for 5 minutes. " .
        "Do not share this code.\n\n" .
        "GEMB HOA | POPIA Act 4 of 2013";

    $sent = sendEmail(
        $email,
        $subject,
        $body
    );
    
    if (!$sent) {
    error_log(
        'GEMB OTP DEBUG: OTP created but SMTP send failed'
    );
} else {
    error_log(
        'GEMB OTP DEBUG: SMTP send reported success'
    );
}

    /*
     * A failed transmission must not leave
     * a valid OTP sitting in the database.
     */
    if (!$sent) {
        db()->prepare("
            UPDATE auth_otp_tokens
            SET used_at = NOW()
            WHERE subject_key = ?
              AND purpose = ?
              AND used_at IS NULL
        ")->execute([
            $subjectKey,
            $purpose,
        ]);
    }

    return $sent;
}


function verifyEmailOtpDetailed(
    string $email,
    string $otp
): array {
    $subjectKey = otpSubjectKey(
        'email',
        strtolower(trim($email))
    );

    return otpVerify(
        $subjectKey,
        'admin_login',
        $otp
    );
}


/**
 * Compatibility wrapper for existing callers.
 */
function verifyEmailOtp(
    string $email,
    string $otp
): bool {
    return verifyEmailOtpDetailed(
        $email,
        $otp
    )['ok'];
}


/*
|--------------------------------------------------------------------------
| Phone OTP compatibility
|--------------------------------------------------------------------------
*/

function generateOtp(
    string $phone,
    string $email
): bool {
    $phone = normalisePhone($phone);

    if ($phone === '') {
        return false;
    }

    $subjectKey = otpSubjectKey(
        'phone',
        $phone
    );

    $otp = otpIssue(
        $subjectKey,
        'login'
    );

    if ($otp === null) {
        return false;
    }

    $subject =
        'GEMB Access Control - Your Login Code';

    $body =
        "GEMB Access Control\n\n" .
        "Your login code: {$otp}\n\n" .
        "Valid for 5 minutes. " .
        "Do not share this code.\n\n" .
        "GEMB HOA | POPIA Act 4 of 2013";

    $sent = sendEmail(
        $email,
        $subject,
        $body
    );

    if (!$sent) {
        db()->prepare("
            UPDATE auth_otp_tokens
            SET used_at = NOW()
            WHERE subject_key = ?
              AND purpose = 'login'
              AND used_at IS NULL
        ")->execute([$subjectKey]);
    }

    return $sent;
}


function verifyOtp(
    string $phone,
    string $otp
): bool {
    $phone = normalisePhone($phone);

    if ($phone === '') {
        return false;
    }

    return otpVerify(
        otpSubjectKey(
            'phone',
            $phone
        ),
        'login',
        $otp
    )['ok'];
}


/*
|--------------------------------------------------------------------------
| Resident notifications
|--------------------------------------------------------------------------
*/

function notifyResidentEntry(
    string $residentEmail,
    string $visitorName,
    string $category,
    string $gate,
    string $timestamp = ''
): void {
    if ($residentEmail === '') {
        return;
    }

    if ($timestamp === '') {
        $timestamp = date('d M Y H:i');
    }

    $label =
        $category === 'service_provider'
        ? 'Service Provider'
        : 'Visitor';

    $subject =
        "GEMB - {$label} Arrived";

    $body =
        "GEMB Access Control\n\n" .
        "{$label} ARRIVED\n\n" .
        "Name:  {$visitorName}\n" .
        "Gate:  {$gate}\n" .
        "Time:  {$timestamp}\n\n" .
        "GEMB HOA";

    sendEmail(
        $residentEmail,
        $subject,
        $body
    );
}


function notifyResidentExit(
    string $residentEmail,
    string $visitorName,
    string $category,
    string $gate,
    string $timestamp = ''
): void {
    if ($residentEmail === '') {
        return;
    }

    if ($timestamp === '') {
        $timestamp = date('d M Y H:i');
    }

    $label =
        $category === 'service_provider'
        ? 'Service Provider'
        : 'Visitor';

    $subject =
        "GEMB - {$label} Departed";

    $body =
        "GEMB Access Control\n\n" .
        "{$label} DEPARTED\n\n" .
        "Name:  {$visitorName}\n" .
        "Gate:  {$gate}\n" .
        "Time:  {$timestamp}\n\n" .
        "GEMB HOA";

    sendEmail(
        $residentEmail,
        $subject,
        $body
    );
}