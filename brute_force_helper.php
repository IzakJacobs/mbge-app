<?php
/**
 * brute_force_helper.php
 *
 * GEMB authentication throttling.
 *
 * Two protections:
 *  - account-based throttling against distributed guessing
 *  - IP-based throttling against one source attacking many accounts
 *
 * The login_attempts table must be created during deployment.
 * Runtime code deliberately does not CREATE/ALTER tables.
 */

define('BF_WINDOW_MINS', 15);

define('BF_ACCOUNT_FIRST_LIMIT', 5);
define('BF_IP_LIMIT', 20);

define('BF_IP_LOCKOUT_MINS', 15);


/**
 * Do not trust X-Forwarded-For unless GEMB is explicitly configured
 * behind a trusted reverse proxy.
 */
function bfClientIp(): string
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

    if (!is_string($ip) || $ip === '') {
        return 'unknown';
    }

    return substr($ip, 0, 45);
}


/**
 * Increasing account cooldown.
 *
 * 0-4 failures  : no cooldown
 * 5-7 failures  : 2 minutes
 * 8-9 failures  : 5 minutes
 * 10+ failures  : 15 minutes
 */
function bfAccountCooldownMinutes(int $failures): int
{
    if ($failures >= 10) {
        return 15;
    }

    if ($failures >= 8) {
        return 5;
    }

    if ($failures >= 5) {
        return 2;
    }

    return 0;
}


function bfIsLocked(string $role, string $identifier): array
{
    $identifier = trim($identifier);
    $ip = bfClientIp();

    /*
     * Account-wide count.
     */
    $accountStmt = db()->prepare("
        SELECT
            COUNT(*) AS cnt,
            MAX(attempted_at) AS last_attempt
        FROM login_attempts
        WHERE role = ?
          AND identifier = ?
          AND attempted_at >= DATE_SUB(
                NOW(),
                INTERVAL ? MINUTE
          )
    ");

    $accountStmt->execute([
        $role,
        $identifier,
        BF_WINDOW_MINS,
    ]);

    $account = $accountStmt->fetch() ?: [
        'cnt' => 0,
        'last_attempt' => null,
    ];

    $accountCount = (int)$account['cnt'];
    $accountCooldown = bfAccountCooldownMinutes($accountCount);

    $accountRemaining = 0;

    if (
        $accountCooldown > 0 &&
        !empty($account['last_attempt'])
    ) {
        $accountUnlock =
            strtotime($account['last_attempt']) +
            ($accountCooldown * 60);

        $accountRemaining = max(
            0,
            $accountUnlock - time()
        );
    }


    /*
     * Source-IP count.
     */
    $ipStmt = db()->prepare("
        SELECT
            COUNT(*) AS cnt,
            MAX(attempted_at) AS last_attempt
        FROM login_attempts
        WHERE role = ?
          AND ip_address = ?
          AND attempted_at >= DATE_SUB(
                NOW(),
                INTERVAL ? MINUTE
          )
    ");

    $ipStmt->execute([
        $role,
        $ip,
        BF_WINDOW_MINS,
    ]);

    $ipRow = $ipStmt->fetch() ?: [
        'cnt' => 0,
        'last_attempt' => null,
    ];

    $ipCount = (int)$ipRow['cnt'];
    $ipRemaining = 0;

    if (
        $ipCount >= BF_IP_LIMIT &&
        !empty($ipRow['last_attempt'])
    ) {
        $ipUnlock =
            strtotime($ipRow['last_attempt']) +
            (BF_IP_LOCKOUT_MINS * 60);

        $ipRemaining = max(
            0,
            $ipUnlock - time()
        );
    }


    $remainingSeconds = max(
        $accountRemaining,
        $ipRemaining
    );

    if ($remainingSeconds > 0) {
        $unlockAt = time() + $remainingSeconds;

        return [
            'locked'   => true,
            'minutes'  => max(
                1,
                (int)ceil($remainingSeconds / 60)
            ),
            'until'    => date('H:i', $unlockAt),
            'count'    => $accountCount,
            'ip_count' => $ipCount,
        ];
    }

    return [
        'locked'   => false,
        'count'    => $accountCount,
        'ip_count' => $ipCount,
    ];
}


function bfRecordFailure(
    string $role,
    string $identifier
): void {
    $identifier = trim($identifier);

    db()->prepare("
        INSERT INTO login_attempts (
            role,
            identifier,
            ip_address
        )
        VALUES (?, ?, ?)
    ")->execute([
        $role,
        $identifier,
        bfClientIp(),
    ]);
}


function bfClearAttempts(
    string $role,
    string $identifier
): void {
    db()->prepare("
        DELETE FROM login_attempts
        WHERE role = ?
          AND identifier = ?
    ")->execute([
        $role,
        trim($identifier),
    ]);
}


function bfAttemptsRemaining(
    string $role,
    string $identifier
): int {
    $check = bfIsLocked(
        $role,
        $identifier
    );

    return max(
        0,
        BF_ACCOUNT_FIRST_LIMIT -
        (int)($check['count'] ?? 0)
    );
}


function bfLockoutMessage(array $lockInfo): string
{
    $minutes = max(
        1,
        (int)($lockInfo['minutes'] ?? 1)
    );

    $until = htmlspecialchars(
        (string)($lockInfo['until'] ?? ''),
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );

    return
        'Too many failed login attempts. ' .
        'Please try again at <strong>' .
        $until .
        '</strong> (' .
        $minutes .
        ' minute' .
        ($minutes === 1 ? '' : 's') .
        ' remaining).';
}


function bfWarningMessage(int $remaining): string
{
    if ($remaining === 1) {
        return
            '⚠️ <strong>1 attempt remaining</strong> ' .
            'before login throttling is applied.';
    }

    if ($remaining === 2) {
        return
            '⚠️ 2 attempts remaining before login throttling is applied.';
    }

    return '';
}