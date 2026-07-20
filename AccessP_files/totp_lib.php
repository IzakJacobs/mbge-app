<?php
/**
 * totp_lib.php — GEMB Access Control
 * Pure-PHP TOTP (RFC 6238), zero dependencies.
 *
 * VENDORED FILE: this exact file must exist in TWO places —
 *   - AccessP root (required by guard.php, cloud login)
 *   - pi/ on the Raspberry Pi gate node (required by verify.php)
 * They must stay byte-identical. It has no dependency on config.php,
 * db(), or any network call, so it works with zero connectivity —
 * required for the offline gate server.
 *
 * WHY GUARD GETS TOTP INSTEAD OF EMAIL OTP:
 * Admin, Security, and Resident's "new device" second factor is a
 * genuine emailed 6-digit code (twilio_helper.php) — that needs a
 * network call to send. The Pi's gate node is built specifically to
 * keep authenticating with zero internet connectivity, so an
 * email-based second factor cannot be Guard's mechanism. TOTP verifies
 * with pure local arithmetic against a secret already on the device —
 * no network call at verification time — so it's the only real
 * one-time-code mechanism that also satisfies the offline requirement.
 */

const GEMB_TOTP_STEP_SECONDS = 30;
const GEMB_TOTP_DIGITS       = 6;
const GEMB_TOTP_WINDOW       = 1; // ± 1 step (±30s) tolerance for clock drift

function gembTotpGenerateSecret(int $bytes = 20): string {
    return gembBase32Encode(random_bytes($bytes));
}

function gembTotpProvisioningUri(string $secret, string $accountLabel, string $issuer = 'GEMB Access Control'): string {
    $label = rawurlencode("$issuer:$accountLabel");
    $params = http_build_query([
        'secret'    => $secret,
        'issuer'    => $issuer,
        'digits'    => GEMB_TOTP_DIGITS,
        'period'    => GEMB_TOTP_STEP_SECONDS,
        'algorithm' => 'SHA1',
    ]);
    return "otpauth://totp/{$label}?{$params}";
}

function gembTotpVerify(string $secret, string $code, int $window = GEMB_TOTP_WINDOW): bool {
    $code = preg_replace('/\D/', '', (string)$code);
    if (strlen($code) !== GEMB_TOTP_DIGITS) return false;

    $key = gembBase32Decode($secret);
    if ($key === '') return false;

    $currentStep = (int)floor(time() / GEMB_TOTP_STEP_SECONDS);
    for ($offset = -$window; $offset <= $window; $offset++) {
        $expected = gembTotpCodeForStep($key, $currentStep + $offset);
        if (hash_equals($expected, $code)) {
            return true;
        }
    }
    return false;
}

function gembTotpCodeForStep(string $binaryKey, int $step): string {
    $binStep = pack('N*', 0) . pack('N*', $step); // 8-byte big-endian counter
    $hash = hash_hmac('sha1', $binStep, $binaryKey, true);
    $offset = ord(substr($hash, -1)) & 0x0F;
    $truncated = (
        ((ord($hash[$offset])     & 0x7F) << 24) |
        ((ord($hash[$offset + 1]) & 0xFF) << 16) |
        ((ord($hash[$offset + 2]) & 0xFF) << 8)  |
        (ord($hash[$offset + 3])  & 0xFF)
    );
    $code = $truncated % (10 ** GEMB_TOTP_DIGITS);
    return str_pad((string)$code, GEMB_TOTP_DIGITS, '0', STR_PAD_LEFT);
}

function gembBase32Encode(string $binary): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split($binary) as $byte) {
        $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
    }
    $output = '';
    foreach (str_split($bits, 5) as $chunk) {
        if (strlen($chunk) < 5) $chunk = str_pad($chunk, 5, '0');
        $output .= $alphabet[bindec($chunk)];
    }
    return $output;
}

function gembBase32Decode(string $b32): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $b32 = strtoupper(preg_replace('/[^A-Z2-7]/', '', $b32));
    $bits = '';
    foreach (str_split($b32) as $char) {
        $pos = strpos($alphabet, $char);
        if ($pos === false) continue;
        $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
    }
    $binary = '';
    foreach (str_split($bits, 8) as $byte) {
        if (strlen($byte) < 8) continue; // drop padding remainder
        $binary .= chr(bindec($byte));
    }
    return $binary;
}
