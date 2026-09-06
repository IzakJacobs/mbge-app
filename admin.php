<?php

// ============================================================
// GEMB Access Control — admin.php
// ============================================================

// Production error handling.
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

require_once __DIR__ . '/layout.php';

ensureSession();

/**
 * ============================================================
 * GEMB Access Control — admin.php
 * ============================================================
 *
 * Coordinated security revision.
 *
 * Requires the revised:
 *   config.php
 *   layout.php
 *   brute_force_helper.php
 *   twilio_helper.php
 *   smtp_mail.php
 *   logout.php
 *
 * admins:
 *   id
 *   username
 *   email
 *   phone
 *   password
 *   device_token
 *   password_changed_at
 *   active_session_token
 *
 * guards:
 *   id, username, name, phone, pin, gate
 *
 * security_users:
 *   id, username, name, phone, email, pin,
 *   device_token, password_changed_at
 *
 * helpdesk:
 *   resident_erfno, resident_name, subject,
 *   category, description, priority, status, response
 */


$action = $_GET['action'] ?? 'login';


/*
|--------------------------------------------------------------------------
| Administrator authentication configuration
|--------------------------------------------------------------------------
*/

const ADMIN_DEVICE_COOKIE = 'gemb_admin_device';

const ADMIN_DEVICE_LIFETIME =
    30 * 24 * 60 * 60;

const ADMIN_PASSWORD_MIN_LENGTH = 12;


/*
|--------------------------------------------------------------------------
| Administrator authentication helpers
|--------------------------------------------------------------------------
*/

function adminSetDeviceCookie(string $token): void
{
    setcookie(
        ADMIN_DEVICE_COOKIE,
        $token,
        [
            'expires' => time() + ADMIN_DEVICE_LIFETIME,
            'path' => '/',
            'domain' => '',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict',
        ]
    );

    /*
     * Make the newly-set value available during this request too.
     */
    $_COOKIE[ADMIN_DEVICE_COOKIE] = $token;
}


function adminClearDeviceCookie(): void
{
    setcookie(
        ADMIN_DEVICE_COOKIE,
        '',
        [
            'expires' => time() - 42000,
            'path' => '/',
            'domain' => '',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict',
        ]
    );

    unset($_COOKIE[ADMIN_DEVICE_COOKIE]);
}


function adminNewDeviceToken(): string
{
    return bin2hex(random_bytes(32));
}


function adminPasswordValid(string $password): bool
{
    return strlen($password) >= ADMIN_PASSWORD_MIN_LENGTH;
}


function adminMaskEmail(string $email): string
{
    $email = trim($email);

    if (
        $email === '' ||
        !str_contains($email, '@')
    ) {
        return '';
    }

    [$local, $domain] =
        array_pad(
            explode('@', $email, 2),
            2,
            ''
        );

    if ($local === '' || $domain === '') {
        return '';
    }

    $visible =
        mb_substr($local, 0, min(2, mb_strlen($local)));

    $stars =
        str_repeat(
            '*',
            max(2, mb_strlen($local) - mb_strlen($visible))
        );

    return $visible . $stars . '@' . $domain;
}


function adminClearPendingLogin(): void
{
    unset(
        $_SESSION['admin_login_step'],
        $_SESSION['admin_pending_id'],
        $_SESSION['admin_pending_email'],
        $_SESSION['admin_pending_username'],
        $_SESSION['admin_pending_device_token'],
        $_SESSION['admin_force_initial_password']
    );
}


function adminLoadById(int $adminId): ?array
{
    if ($adminId <= 0) {
        return null;
    }

    $stmt = db()->prepare(
        "SELECT *
         FROM admins
         WHERE id = ?
         LIMIT 1"
    );

    $stmt->execute([$adminId]);

    $row = $stmt->fetch();

    return $row ?: null;
}


/**
 * Grant authenticated administrator access.
 *
 * password_changed_at = NULL means the administrator is using
 * an initial/reset password and must choose their own password.
 *
 * There is deliberately NO arbitrary 30-day password expiry.
 */
function adminGrantAccess(array $adm): void
{
    ensureSession();

    $adminId = (int)($adm['id'] ?? 0);

    if ($adminId <= 0) {
        http_response_code(403);
        exit('Administrator account unavailable.');
    }

    /*
     * Initial/reset password must be changed before portal access.
     */
    if (empty($adm['password_changed_at'])) {
        $_SESSION['admin_login_step'] = 'reset';
        $_SESSION['admin_pending_id'] = $adminId;
        $_SESSION['admin_force_initial_password'] = true;

        header('Location: admin.php?action=login');
        exit;
    }

    /*
     * Authentication boundary: replace session ID.
     */
    session_regenerate_id(true);

    /*
     * Single-active-admin-session token.
     */
    $sessionToken =
        bin2hex(random_bytes(32));

    db()->prepare(
        "UPDATE admins
         SET active_session_token = ?
         WHERE id = ?"
    )->execute([
        $sessionToken,
        $adminId,
    ]);

    $_SESSION['admin_id'] = $adminId;

    $_SESSION['admin_name'] =
        (string)(
            $adm['username']
            ?? 'Administrator'
        );

    $_SESSION['admin_session_token'] =
        $sessionToken;

    $_SESSION['last_activity'] =
        time();

    adminClearPendingLogin();

    header('Location: admin.php?action=menu');
    exit;
}


/*
|--------------------------------------------------------------------------
| LOGIN
|--------------------------------------------------------------------------
*/

if ($action === 'login') {

    /*
     * A logged-in browser goes through requireAdmin() on the
     * menu request, which performs the DB session-token check.
     */
    if (!empty($_SESSION['admin_id'])) {
        header('Location: admin.php?action=menu');
        exit;
    }

    $step =
        $_SESSION['admin_login_step']
        ?? 'credentials';

    $error = '';


    /*
     * Optional message after single-session displacement.
     */
    if (
        isset($_GET['err']) &&
        $_GET['err'] === 'elsewhere'
    ) {
        $error =
            'You have been signed out because this administrator ' .
            'account was signed in from another session.';

        $step = 'credentials';
    }


    /*
     * All authentication state changes are POST + CSRF.
     */
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {

        verifyCsrfToken();

        $formAction =
            $_POST['form_action']
            ?? 'continue';


        /*
         * ------------------------------------------------------------
         * Cancel OTP/reset flow
         * ------------------------------------------------------------
         */
        if ($formAction === 'cancel_login') {

            adminClearPendingLogin();

            header('Location: admin.php?action=login');
            exit;
        }


        /*
         * ------------------------------------------------------------
         * Step 1 — Username + password
         * ------------------------------------------------------------
         */
        if (
            $step === 'credentials' &&
            isset(
                $_POST['username'],
                $_POST['password']
            )
        ) {
            $user =
                trim(
                    (string)$_POST['username']
                );

            /*
             * Passwords are NEVER trim()'d.
             */
            $pass =
                (string)$_POST['password'];


            if ($user === '' || $pass === '') {

                $error = 'Invalid credentials.';

            } else {

                /*
                 * Account + IP throttle.
                 */
                $lockCheck =
                    bfIsLocked(
                        'admin',
                        $user
                    );

                if (!empty($lockCheck['locked'])) {

                    /*
                     * Helper contains controlled formatting only.
                     * Strip tags so all UI output can be escaped uniformly.
                     */
                    $error =
                        strip_tags(
                            bfLockoutMessage(
                                $lockCheck
                            )
                        );

                } else {

                    $stmt = db()->prepare(
                        "SELECT *
                         FROM admins
                         WHERE username = ?
                         LIMIT 1"
                    );

                    $stmt->execute([$user]);

                    $adm =
                        $stmt->fetch();


 if (!$adm) {

    
    bfRecordFailure(
        'admin',
        $user
    );

    $remaining =
        bfAttemptsRemaining(
            'admin',
            $user
        );

    $error =
        'Invalid credentials.';

    if ($remaining <= 2) {
        $warning =
            strip_tags(
                bfWarningMessage(
                    $remaining
                )
            );

        if ($warning !== '') {
            $error .= ' ' . $warning;
        }
    }

} elseif (
    !password_verify(
        $pass,
        (string)$adm['password']
    )
) {

    
    bfRecordFailure(
        'admin',
        $user
    );

    $remaining =
        bfAttemptsRemaining(
            'admin',
            $user
        );

    $error =
        'Invalid credentials.';

    if ($remaining <= 2) {
        $warning =
            strip_tags(
                bfWarningMessage(
                    $remaining
                )
            );

        if ($warning !== '') {
            $error .= ' ' . $warning;
        }
    }

} else {

                        /*
                         * Opportunistically upgrade password hashes if
                         * PASSWORD_DEFAULT changes in a later PHP version.
                         */
                        if (
                            password_needs_rehash(
                                (string)$adm['password'],
                                PASSWORD_DEFAULT
                            )
                        ) {
                            $rehash =
                                password_hash(
                                    $pass,
                                    PASSWORD_DEFAULT
                                );

                            db()->prepare(
                                "UPDATE admins
                                 SET password = ?
                                 WHERE id = ?"
                            )->execute([
                                $rehash,
                                (int)$adm['id'],
                            ]);

                            $adm['password'] =
                                $rehash;
                        }


                        /*
                         * ------------------------------------------------
                         * Check trusted device.
                         *
                         * A missing DB device token is NOT trusted.
                         * First devices therefore require OTP too.
                         * ------------------------------------------------
                         */
                        $browserDeviceToken =
                            isset(
                                $_COOKIE[
                                    ADMIN_DEVICE_COOKIE
                                ]
                            )
                                ? (string)$_COOKIE[
                                    ADMIN_DEVICE_COOKIE
                                ]
                                : '';

                        $storedDeviceHash =
    (string)(
        $adm['device_token']
        ?? ''
    );

$deviceExpiresAt =
    (string)(
        $adm['device_token_expires_at']
        ?? ''
    );

$trustedDevice = false;

if (
    $browserDeviceToken !== '' &&
    $storedDeviceHash !== '' &&
    $deviceExpiresAt !== ''
) {
    $candidateHash =
        hashDeviceToken(
            $browserDeviceToken
        );

    $expiryTimestamp =
        strtotime(
            $deviceExpiresAt
        );

    $trustedDevice =
        $expiryTimestamp !== false &&
        $expiryTimestamp > time() &&
        hash_equals(
            $storedDeviceHash,
            $candidateHash
        );
}


                        /*
                         * Existing trusted device.
                         */
                        if ($trustedDevice) {

                            bfClearAttempts(
                                'admin',
                                $user
                            );

                            adminGrantAccess($adm);
                        }


                        /*
                         * ------------------------------------------------
                         * New/untrusted device.
                         * ------------------------------------------------
                         */
                        $adminEmail =
                            strtolower(
                                trim(
                                    (string)(
                                        $adm['email']
                                        ?? ''
                                    )
                                )
                            );

                        if (
                            !filter_var(
                                $adminEmail,
                                FILTER_VALIDATE_EMAIL
                            )
                        ) {
                            $error =
                                'No valid email address is on file for this ' .
                                'administrator account. Another administrator ' .
                                'must update the email address before this ' .
                                'account can sign in from an untrusted device.';

                        } else {

                            $pendingDeviceToken =
                                adminNewDeviceToken();

                            $_SESSION[
                                'admin_login_step'
                            ] = 'otp';

                            $_SESSION[
                                'admin_pending_id'
                            ] = (int)$adm['id'];

                            $_SESSION[
                                'admin_pending_email'
                            ] = $adminEmail;

                            $_SESSION[
                                'admin_pending_username'
                            ] = $user;

                            $_SESSION[
                                'admin_pending_device_token'
                            ] = $pendingDeviceToken;


                            require_once
                                __DIR__ .
                                '/twilio_helper.php';


                            /*
                             * Do not advance to a dead OTP screen if
                             * SMTP delivery or resend throttling fails.
                             */
                            if (
                                !generateEmailOtp(
                                    $adminEmail
                                )
                            ) {
                                adminClearPendingLogin();

                                $step =
                                    'credentials';

                                $error =
                                    'Unable to send the verification code. ' .
                                    'Please wait briefly and try again.';

                            } else {

                                header(
                                    'Location: admin.php?action=login'
                                );

                                exit;
                            }
                        }
                    }
                }
            }
        }


        /*
         * ------------------------------------------------------------
         * Step 2 — OTP verification
         * ------------------------------------------------------------
         */
        elseif (
            $step === 'otp' &&
            isset($_POST['otp'])
        ) {
            $email =
                (string)(
                    $_SESSION[
                        'admin_pending_email'
                    ]
                    ?? ''
                );

            $pendingAdminId =
                (int)(
                    $_SESSION[
                        'admin_pending_id'
                    ]
                    ?? 0
                );

            $pendingUsername =
                (string)(
                    $_SESSION[
                        'admin_pending_username'
                    ]
                    ?? ''
                );

            $pendingDeviceToken =
                (string)(
                    $_SESSION[
                        'admin_pending_device_token'
                    ]
                    ?? ''
                );


            if (
                $email === '' ||
                $pendingAdminId <= 0 ||
                $pendingDeviceToken === ''
            ) {
                adminClearPendingLogin();

                $step =
                    'credentials';

                $error =
                    'The verification session has expired. ' .
                    'Please sign in again.';

            } else {

                require_once
                    __DIR__ .
                    '/twilio_helper.php';

                $result =
                    verifyEmailOtpDetailed(
                        $email,
                        (string)$_POST['otp']
                    );


                if (empty($result['ok'])) {

                    $remaining =
                        (int)(
                            $result[
                                'attempts_remaining'
                            ]
                            ?? 0
                        );

                    $reason =
                        (string)(
                            $result['reason']
                            ?? 'invalid'
                        );


                    if (
                        $remaining > 0 &&
                        $reason === 'invalid'
                    ) {
                        $error =
                            'Incorrect verification code. ' .
                            $remaining .
                            ' attempt' .
                            ($remaining === 1 ? '' : 's') .
                            ' remaining.';

                    } else {

                        adminClearPendingLogin();

                        $step =
                            'credentials';

                        if ($reason === 'expired') {
                            $error =
                                'The verification code has expired. ' .
                                'Please sign in again.';

                        } elseif ($reason === 'locked') {
                            $error =
                                'Too many incorrect verification attempts. ' .
                                'Please sign in again.';

                        } else {
                            $error =
                                'The verification code is no longer valid. ' .
                                'Please sign in again.';
                        }
                    }

                } else {

                    /*
                     * ------------------------------------------------
                     * OTP succeeded.
                     *
                     * Only now register this browser as trusted.
                     * ------------------------------------------------
                     */
                    $deviceHash =
                        hashDeviceToken(
                            $pendingDeviceToken
                        );

                   db()->prepare(
    "UPDATE admins
     SET device_token = ?,
         device_token_expires_at =
             DATE_ADD(NOW(), INTERVAL 30 DAY)
     WHERE id = ?"
)->execute([
    $deviceHash,
    $pendingAdminId,
]);

                    adminSetDeviceCookie(
                        $pendingDeviceToken
                    );


                    if ($pendingUsername !== '') {
                        bfClearAttempts(
                            'admin',
                            $pendingUsername
                        );
                    }


                    $adm =
                        adminLoadById(
                            $pendingAdminId
                        );

                    /*
                     * Preserve only what adminGrantAccess needs.
                     */
                    unset(
                        $_SESSION[
                            'admin_pending_email'
                        ],
                        $_SESSION[
                            'admin_pending_username'
                        ],
                        $_SESSION[
                            'admin_pending_device_token'
                        ]
                    );

                    if (!$adm) {
                        adminClearPendingLogin();

                        http_response_code(403);
                        exit(
                            'Administrator account unavailable.'
                        );
                    }

                    adminGrantAccess($adm);
                }
            }
        }


        /*
         * ------------------------------------------------------------
         * Step 3 — Initial/reset password
         * ------------------------------------------------------------
         */
        elseif (
            $step === 'reset' &&
            isset(
                $_POST['new_password'],
                $_POST['confirm_password']
            )
        ) {
            /*
             * Do not trim passwords.
             */
            $newPass =
                (string)$_POST[
                    'new_password'
                ];

            $conPass =
                (string)$_POST[
                    'confirm_password'
                ];

            $pendingId =
                (int)(
                    $_SESSION[
                        'admin_pending_id'
                    ]
                    ?? 0
                );


            if ($pendingId <= 0) {

                adminClearPendingLogin();

                header(
                    'Location: admin.php?action=login'
                );

                exit;

            } elseif (
                !adminPasswordValid(
                    $newPass
                )
            ) {
                $error =
                    'Password must contain at least ' .
                    ADMIN_PASSWORD_MIN_LENGTH .
                    ' characters.';

            } elseif (
                $newPass !== $conPass
            ) {
                $error =
                    'Passwords do not match.';

            } else {

                $cur =
                    db()->prepare(
                        "SELECT password
                         FROM admins
                         WHERE id = ?
                         LIMIT 1"
                    );

                $cur->execute([
                    $pendingId
                ]);

                $currentRow =
                    $cur->fetch();


                if (!$currentRow) {

                    adminClearPendingLogin();

                    $error =
                        'Administrator account unavailable.';

                    $step =
                        'credentials';

                } elseif (
                    password_verify(
                        $newPass,
                        (string)$currentRow[
                            'password'
                        ]
                    )
                ) {
                    $error =
                        'New password must be different ' .
                        'from the current password.';

                } else {

                    $newPasswordHash =
                        password_hash(
                            $newPass,
                            PASSWORD_DEFAULT
                        );

                    db()->prepare(
                        "UPDATE admins
                         SET password = ?,
                             password_changed_at = NOW()
                         WHERE id = ?"
                    )->execute([
                        $newPasswordHash,
                        $pendingId,
                    ]);


                    $adm =
                        adminLoadById(
                            $pendingId
                        );

                    unset(
                        $_SESSION[
                            'admin_force_initial_password'
                        ]
                    );

                    if (!$adm) {
                        adminClearPendingLogin();

                        http_response_code(403);
                        exit(
                            'Administrator account unavailable.'
                        );
                    }

                    adminGrantAccess($adm);
                }
            }
        }
    }


    /*
     * ------------------------------------------------------------
     * Render login UI
     * ------------------------------------------------------------
     */

    /*
     * Refresh from session in case POST processing altered it.
     */
    $step =
        $_SESSION['admin_login_step']
        ?? $step;

    pageHeader(
        'Admin Login',
        'admin'
    );
    ?>

    <div class="login-wrap">

      <div class="login-card">

        <div class="login-logo">⚙️</div>

        <h2>System Administrator</h2>

        <div class="subtitle">
          GEMB Access Control
        </div>


        <?php if ($error !== ''): ?>

          <div class="alert alert-danger">
            <?= htmlspecialchars(
                $error,
                ENT_QUOTES | ENT_SUBSTITUTE,
                'UTF-8'
            ) ?>
          </div>

        <?php endif; ?>


        <?php if ($step === 'credentials'): ?>

          <form
              method="POST"
              action="admin.php?action=login"
          >
            <?= csrfField() ?>

            <div class="form-group">
              <label>Username</label>

              <input
                  type="text"
                  name="username"
                  required
                  maxlength="100"
                  autocomplete="username"
              >
            </div>

            <div class="form-group">
              <label>Password</label>

              <input
                  type="password"
                  name="password"
                  required
                  autocomplete="current-password"
              >
            </div>

            <button
                type="submit"
                class="btn btn-primary btn-block"
                style="margin-top:8px;"
            >
              Login
            </button>
          </form>


          <a
              href="forgot.php?role=admin"
              style="
                display:block;
                text-align:center;
                margin-top:14px;
                font-size:.85rem;
                color:var(--muted);
              "
          >
            Forgot password?
          </a>


        <?php elseif ($step === 'otp'): ?>

          <div
              class="alert alert-info"
              style="font-size:.88rem;"
          >
            📧
            <strong>
              New or untrusted device detected.
            </strong>

            <br><br>

            <?php
            $pendingEmail =
                (string)(
                    $_SESSION[
                        'admin_pending_email'
                    ]
                    ?? ''
                );

            $masked =
                adminMaskEmail(
                    $pendingEmail
                );
            ?>

            <?php if ($masked !== ''): ?>

              A <strong>6-digit verification code</strong>
              has been sent to

              <strong>
                <?= htmlspecialchars(
                    $masked,
                    ENT_QUOTES | ENT_SUBSTITUTE,
                    'UTF-8'
                ) ?>
              </strong>.

            <?php else: ?>

              The verification destination is unavailable.

            <?php endif; ?>

            <br><br>

            Enter the code below to verify your identity.
          </div>


          <form
              method="POST"
              action="admin.php?action=login"
          >
            <?= csrfField() ?>

            <div class="form-group">

              <label>
                6-digit verification code
              </label>

              <input
                  type="text"
                  name="otp"
                  required
                  autofocus
                  maxlength="6"
                  pattern="[0-9]{6}"
                  inputmode="numeric"
                  autocomplete="one-time-code"
                  placeholder="_ _ _ _ _ _"
                  style="
                    font-size:1.6rem;
                    letter-spacing:0.4em;
                    text-align:center;
                  "
              >
            </div>

            <button
                type="submit"
                class="btn btn-primary btn-block"
            >
              Verify Code
            </button>
          </form>


          <form
              method="POST"
              action="admin.php?action=login"
              style="margin-top:14px;text-align:center;"
          >
            <?= csrfField() ?>

            <input
                type="hidden"
                name="form_action"
                value="cancel_login"
            >

            <button
                type="submit"
                style="
                  border:0;
                  background:none;
                  color:var(--muted);
                  cursor:pointer;
                  font-size:.85rem;
                "
            >
              ← Cancel and start over
            </button>
          </form>


        <?php elseif ($step === 'reset'): ?>

          <div
              class="alert alert-warning"
              style="font-size:.88rem;"
          >
            🔑
            <strong>Password change required.</strong>

            <br><br>

            This account is using an initial or
            administrator-reset password. Choose a new
            password before continuing.
          </div>


          <form
              method="POST"
              action="admin.php?action=login"
          >
            <?= csrfField() ?>

            <div class="form-group">

              <label>
                New Password
                (minimum <?= ADMIN_PASSWORD_MIN_LENGTH ?> characters)
              </label>

              <input
                  type="password"
                  name="new_password"
                  required
                  autofocus
                  autocomplete="new-password"
                  minlength="<?= ADMIN_PASSWORD_MIN_LENGTH ?>"
              >
            </div>


            <div class="form-group">

              <label>
                Confirm Password
              </label>

              <input
                  type="password"
                  name="confirm_password"
                  required
                  autocomplete="new-password"
                  minlength="<?= ADMIN_PASSWORD_MIN_LENGTH ?>"
              >
            </div>


            <button
                type="submit"
                class="btn btn-primary btn-block"
            >
              Save Password &amp; Login
            </button>
          </form>

        <?php endif; ?>


        <div class="popia-notice">
          Administrator access is logged for
          security and access-control purposes.
        </div>

      </div>

    </div>

    <?php

    pageFooter();
    exit;
}


/*
|--------------------------------------------------------------------------
| Everything below requires a valid authenticated admin session.
|--------------------------------------------------------------------------
*/

requireAdmin();


/*
|--------------------------------------------------------------------------
| MENU
|--------------------------------------------------------------------------
*/

if ($action === 'menu') {

    try {

        $pendingApps =
            db()->query(
                "SELECT
                   (
                     SELECT COUNT(*)
                     FROM applications
                     WHERE app_type IN (
                         'to_let',
                         'tenant',
                         'pet',
                         'estate_agent'
                     )
                     AND status IN (
                         'pending_verification',
                         'induction_scheduled'
                     )
                   )
                   +
                   (
                     SELECT COUNT(*)
                     FROM pets
                     WHERE pet_type = 'visitor'
                     AND status = 'pending'
                   )"
            )->fetchColumn();

        $pendingApps =
            (int)$pendingApps;

    } catch (Throwable $e) {

        /*
         * Engine tables may not yet be installed.
         */
        $pendingApps = 0;
    }


    pageHeader(
        'Admin Menu',
        'admin'
    );

    renderHeader(
        '⚙️ Admin — ' .
        (
            $_SESSION[
                'admin_name'
            ]
            ?? ''
        ),
        'logout.php'
    );
    ?>

    <div class="container">

      <?= getFlash() ?>

      <div class="menu-grid">

        <a
            href="residents_admin.php?action=list"
            class="menu-btn"
        >
          <span class="icon">🏠</span>
          Residents
        </a>


        <a
            href="admin_approvals.php"
            class="menu-btn"
        >
          <span class="icon">📋</span>
          Approvals of Resident Requests

          <?php if ($pendingApps > 0): ?>

            <span class="badge badge-warning">
              <?= $pendingApps ?>
            </span>

          <?php endif; ?>
        </a>


        <a
            href="admin.php?action=add_security"
            class="menu-btn"
        >
          <span class="icon">🛡️</span>
          Site Managers
        </a>


        <a
            href="admin.php?action=add_guard"
            class="menu-btn"
        >
          <span class="icon">👮</span>
          Guards
        </a>


        <a
            href="export.php?action=menu"
            class="menu-btn"
        >
          <span class="icon">📊</span>
          Export
        </a>


        <a
            href="admin.php?action=helpdesk"
            class="menu-btn"
        >
          <span class="icon">🔧</span>
          Helpdesk
        </a>


        <a
            href="document_portal.php"
            class="menu-btn"
        >
          <span class="icon">📤</span>
          Send Documents
        </a>


        <a
            href="document_archive.php"
            class="menu-btn"
        >
          <span class="icon">📄</span>
          Document Archive
        </a>


        <a
            href="admin.php?action=cleanup"
            class="menu-btn"
        >
          <span class="icon">🧹</span>
          Cleanup
        </a>


        <a
            href="admin.php?action=add_admin"
            class="menu-btn"
        >
          <span class="icon">👤</span>
          Admins
        </a>


        <a
            href="admin.php?action=change_pw"
            class="menu-btn"
        >
          <span class="icon">🔑</span>
          Change Password
        </a>

      </div>

    </div>

    <?php

    pageFooter();
    exit;
}


/*
|--------------------------------------------------------------------------
| CHANGE PASSWORD — logged-in administrator
|--------------------------------------------------------------------------
*/

if ($action === 'change_pw') {

    if (
        $_SERVER['REQUEST_METHOD']
        === 'POST'
    ) {
        verifyCsrfToken();

        /*
         * Password input deliberately not trimmed.
         */
        $currentPassword =
            (string)(
                $_POST[
                    'current_password'
                ]
                ?? ''
            );

        $newPassword =
            (string)(
                $_POST[
                    'new_password'
                ]
                ?? ''
            );

        $confirmPassword =
            (string)(
                $_POST[
                    'confirm_password'
                ]
                ?? ''
            );

        $adminId =
            (int)(
                $_SESSION[
                    'admin_id'
                ]
                ?? 0
            );


        $stmt =
            db()->prepare(
                "SELECT password
                 FROM admins
                 WHERE id = ?
                 LIMIT 1"
            );

        $stmt->execute([
            $adminId
        ]);

        $row =
            $stmt->fetch();


        if (
            !$row ||
            !password_verify(
                $currentPassword,
                (string)$row['password']
            )
        ) {
            setFlash(
                'error',
                'Current password is incorrect.'
            );

            header(
                'Location: admin.php?action=change_pw'
            );

            exit;
        }


        if (
            !adminPasswordValid(
                $newPassword
            )
        ) {
            setFlash(
                'error',
                'New password must contain at least ' .
                ADMIN_PASSWORD_MIN_LENGTH .
                ' characters.'
            );

            header(
                'Location: admin.php?action=change_pw'
            );

            exit;
        }


        if (
            $newPassword !==
            $confirmPassword
        ) {
            setFlash(
                'error',
                'New passwords do not match.'
            );

            header(
                'Location: admin.php?action=change_pw'
            );

            exit;
        }


        if (
            password_verify(
                $newPassword,
                (string)$row['password']
            )
        ) {
            setFlash(
                'error',
                'New password must be different from your current password.'
            );

            header(
                'Location: admin.php?action=change_pw'
            );

            exit;
        }


        $newHash =
            password_hash(
                $newPassword,
                PASSWORD_DEFAULT
            );

        $newSessionToken =
            bin2hex(
                random_bytes(32)
            );


        db()->prepare(
            "UPDATE admins
             SET password = ?,
                 password_changed_at = NOW(),
                 active_session_token = ?
             WHERE id = ?"
        )->execute([
            $newHash,
            $newSessionToken,
            $adminId,
        ]);


        /*
         * Session ID and DB-backed active-session token
         * both rotate after a password change.
         */
        session_regenerate_id(true);

        $_SESSION[
            'admin_session_token'
        ] = $newSessionToken;

        $_SESSION[
            'last_activity'
        ] = time();


        setFlash(
            'success',
            'Password updated successfully.'
        );

        header(
            'Location: admin.php?action=menu'
        );

        exit;
    }


    pageHeader(
        'Change Password',
        'admin'
    );

    renderHeader(
        '🔑 Change Password',
        'admin.php?action=menu'
    );
    ?>

    <div
        class="container"
        style="max-width:420px;"
    >

      <div class="card">

        <?= getFlash() ?>

        <form method="POST">

          <?= csrfField() ?>

          <div class="form-group">

            <label>
              Current Password
            </label>

            <input
                type="password"
                name="current_password"
                required
                autocomplete="current-password"
            >
          </div>


          <div class="form-group">

            <label>
              New Password
              (minimum <?= ADMIN_PASSWORD_MIN_LENGTH ?> characters)
            </label>

            <input
                type="password"
                name="new_password"
                required
                minlength="<?= ADMIN_PASSWORD_MIN_LENGTH ?>"
                autocomplete="new-password"
            >
          </div>


          <div class="form-group">

            <label>
              Confirm New Password
            </label>

            <input
                type="password"
                name="confirm_password"
                required
                minlength="<?= ADMIN_PASSWORD_MIN_LENGTH ?>"
                autocomplete="new-password"
            >
          </div>


          <button
              type="submit"
              class="btn btn-primary btn-block"
          >
            Update Password
          </button>

        </form>


        <div class="popia-notice">
          Choose a long, unique password that is not
          used for another account.
        </div>

      </div>

    </div>

    <?php

    pageFooter();
    exit;
}


/*
|--------------------------------------------------------------------------
| ADMINISTRATORS — list / add / edit / delete
|--------------------------------------------------------------------------
|
| Lockout safety:
|
| 1. Cannot delete currently logged-in account.
| 2. Cannot delete last administrator.
| 3. Cannot delete administrator ID 1.
|
| A password reset performed here for another admin:
|
| - revokes the trusted device,
| - revokes the active session,
| - sets password_changed_at = NULL,
| - causes OTP + forced password change on next login.
|
*/

if ($action === 'add_admin') {

    /*
     * ------------------------------------------------------------
     * POST handlers
     * ------------------------------------------------------------
     */
    if (
        $_SERVER['REQUEST_METHOD']
        === 'POST'
    ) {
        verifyCsrfToken();

        $formAction =
            $_POST[
                'form_action'
            ]
            ?? 'add';


        /*
         * --------------------------------------------------------
         * ADD ADMINISTRATOR
         * --------------------------------------------------------
         */
        if ($formAction === 'add') {

            $username =
                trim(
                    (string)(
                        $_POST[
                            'username'
                        ]
                        ?? ''
                    )
                );

            $email =
                strtolower(
                    trim(
                        (string)(
                            $_POST[
                                'email'
                            ]
                            ?? ''
                        )
                    )
                );

            $phone =
                trim(
                    (string)(
                        $_POST[
                            'phone'
                        ]
                        ?? ''
                    )
                );

            /*
             * Password deliberately not trimmed.
             */
            $password =
                (string)(
                    $_POST[
                        'password'
                    ]
                    ?? ''
                );


            if (
                $username === '' ||
                $email === ''
            ) {
                setFlash(
                    'error',
                    'Username and email are required.'
                );

                header(
                    'Location: admin.php?action=add_admin&new=1'
                );

                exit;
            }


            if (
                !filter_var(
                    $email,
                    FILTER_VALIDATE_EMAIL
                )
            ) {
                setFlash(
                    'error',
                    'Please enter a valid email address.'
                );

                header(
                    'Location: admin.php?action=add_admin&new=1'
                );

                exit;
            }


            if (
                !adminPasswordValid(
                    $password
                )
            ) {
                setFlash(
                    'error',
                    'Initial password must contain at least ' .
                    ADMIN_PASSWORD_MIN_LENGTH .
                    ' characters.'
                );

                header(
                    'Location: admin.php?action=add_admin&new=1'
                );

                exit;
            }


            if (
                $phone !== '' &&
                !preg_match(
                    '/^27\d{9}$/',
                    $phone
                )
            ) {
                setFlash(
                    'error',
                    'Phone must be in format 27XXXXXXXXX (11 digits).'
                );

                header(
                    'Location: admin.php?action=add_admin&new=1'
                );

                exit;
            }


            try {

                /*
                 * password_changed_at deliberately NULL.
                 *
                 * The administrator receives OTP on the first device,
                 * then must replace this initial password.
                 */
                db()->prepare(
                    "INSERT INTO admins (
                        username,
                        password,
                        email,
                        phone,
                        password_changed_at,
                        device_token,
                        device_token_expires_at,
                        active_session_token
                    )
                    VALUES (?, ?, ?, ?, NULL, NULL, NULL, NULL)"
                    
                    
                    
                )->execute([
                    $username,
                    password_hash(
                        $password,
                        PASSWORD_DEFAULT
                    ),
                    $email,
                    $phone,
                ]);


                setFlash(
                    'success',
                    'Administrator ' .
                    $username .
                    ' added. They must verify their first device ' .
                    'and change the initial password at first login.'
                );


                header(
                    'Location: admin.php?action=add_admin'
                );

                exit;

            } catch (Throwable $e) {

                setFlash(
                    'error',
                    'Unable to create the administrator. ' .
                    'The username may already exist.'
                );

                header(
                    'Location: admin.php?action=add_admin&new=1'
                );

                exit;
            }
        }


        /*
         * --------------------------------------------------------
         * UPDATE ADMINISTRATOR
         * --------------------------------------------------------
         */
        elseif (
            $formAction === 'update'
        ) {
            $adminId =
                (int)(
                    $_POST['uid']
                    ?? 0
                );

            $selfId =
                (int)(
                    $_SESSION[
                        'admin_id'
                    ]
                    ?? 0
                );

            $username =
                trim(
                    (string)(
                        $_POST[
                            'username'
                        ]
                        ?? ''
                    )
                );

            $email =
                strtolower(
                    trim(
                        (string)(
                            $_POST[
                                'email'
                            ]
                            ?? ''
                        )
                    )
                );

            $phone =
                trim(
                    (string)(
                        $_POST[
                            'phone'
                        ]
                        ?? ''
                    )
                );

            $password =
                (string)(
                    $_POST[
                        'password'
                    ]
                    ?? ''
                );


            if (
                $adminId <= 0 ||
                $username === '' ||
                $email === ''
            ) {
                setFlash(
                    'error',
                    'Username and email are required.'
                );

                header(
                    'Location: admin.php?action=add_admin&edit=' .
                    $adminId
                );

                exit;
            }


            if (
                !filter_var(
                    $email,
                    FILTER_VALIDATE_EMAIL
                )
            ) {
                setFlash(
                    'error',
                    'Please enter a valid email address.'
                );

                header(
                    'Location: admin.php?action=add_admin&edit=' .
                    $adminId
                );

                exit;
            }


            if (
                $phone !== '' &&
                !preg_match(
                    '/^27\d{9}$/',
                    $phone
                )
            ) {
                setFlash(
                    'error',
                    'Phone must be in format 27XXXXXXXXX (11 digits).'
                );

                header(
                    'Location: admin.php?action=add_admin&edit=' .
                    $adminId
                );

                exit;
            }


            if ($password !== '') {

                if ($adminId === $selfId) {

                    setFlash(
                        'error',
                        'Use the Change Password screen to change your own password.'
                    );

                    header(
                        'Location: admin.php?action=add_admin&edit=' .
                        $adminId
                    );

                    exit;
                }


                if (
                    !adminPasswordValid(
                        $password
                    )
                ) {
                    setFlash(
                        'error',
                        'Reset password must contain at least ' .
                        ADMIN_PASSWORD_MIN_LENGTH .
                        ' characters.'
                    );

                    header(
                        'Location: admin.php?action=add_admin&edit=' .
                        $adminId
                    );

                    exit;
                }
            }


            try {
                if ($password !== '') {

    /*
     * Administrator-assisted reset:
     *
     * - new temporary password
     * - revoke trusted device
     * - revoke trusted-device expiry
     * - revoke current session
     * - force password change at next login
     */
    db()->prepare(
        "UPDATE admins
         SET username = ?,
             email = ?,
             phone = ?,
             password = ?,
             password_changed_at = NULL,
             device_token = NULL,
             device_token_expires_at = NULL,
             active_session_token = NULL
         WHERE id = ?"
    )->execute([
        $username,
        $email,
        $phone,
        password_hash(
            $password,
            PASSWORD_DEFAULT
        ),
        $adminId,
    ]);


    setFlash(
        'success',
        'Administrator updated. Their existing session and ' .
        'trusted device were revoked, and they must change ' .
        'the reset password at next login.'
    );

} else {

    db()->prepare(
        "UPDATE admins
         SET username = ?,
             email = ?,
             phone = ?
         WHERE id = ?"
    )->execute([
        $username,
        $email,
        $phone,
        $adminId,
    ]);


    /*
     * Keep displayed session name in sync if the
     * currently logged-in admin edits their username.
     */
    if ($adminId === $selfId) {
        $_SESSION['admin_name'] = $username;
    }


    setFlash(
        'success',
        'Administrator updated.'
    );
}

            } catch (Throwable $e) {

                setFlash(
                    'error',
                    'Unable to update the administrator. ' .
                    'The username may already exist.'
                );
            }


            header(
                'Location: admin.php?action=add_admin'
            );

            exit;
        }


        /*
         * --------------------------------------------------------
         * DELETE ADMINISTRATOR
         * --------------------------------------------------------
         */
        elseif (
            $formAction === 'delete'
        ) {
            $adminId =
                (int)(
                    $_POST[
                        'uid'
                    ]
                    ?? 0
                );
                
            $selfId =
                (int)(
                    $_SESSION[
                        'admin_id'
                    ]
                    ?? 0
                );

            $count =
                (int)(
                    db()->query(
                        "SELECT COUNT(*)
                         FROM admins"
                    )->fetchColumn()
                );


            if ($adminId === 1) {

                setFlash(
                    'error',
                    'Administrator ID 1 is the protected bootstrap account and cannot be deleted.'
                );

            } elseif (
                $adminId === $selfId
            ) {

                setFlash(
                    'error',
                    'You cannot delete the account you are currently logged in with.'
                );

            } elseif ($count <= 1) {

                setFlash(
                    'error',
                    'Cannot delete the last remaining administrator.'
                );

            } elseif ($adminId <= 0) {

                setFlash(
                    'error',
                    'Invalid administrator.'
                );

            } else {

                try {

                    db()->prepare(
                        "DELETE FROM admins
                         WHERE id = ?"
                    )->execute([
                        $adminId
                    ]);


                    setFlash(
                        'success',
                        'Administrator removed.'
                    );

                } catch (Throwable $e) {

                    setFlash(
                        'error',
                        'This administrator is protected and cannot be deleted.'
                    );
                }
            }


            header(
                'Location: admin.php?action=add_admin'
            );

            exit;
        }


        header(
            'Location: admin.php?action=add_admin'
        );

        exit;
    }


    /*
     * ------------------------------------------------------------
     * ADD PAGE
     * ------------------------------------------------------------
     */
    if (isset($_GET['new'])) {

        pageHeader(
            'Add Administrator',
            'admin'
        );

        renderHeader(
            '➕ Add Administrator',
            'admin.php?action=add_admin'
        );
        ?>

        <div
            class="container"
            style="max-width:560px;"
        >

          <div class="card">

            <?= getFlash() ?>


            <div
                class="alert alert-info"
                style="
                  margin-bottom:16px;
                  font-size:.88rem;
                "
            >
              This creates a
              <strong>new administrator</strong>
              with full management-portal access.

              <br><br>

              On the first login, the administrator must
              verify their device using a code sent to the
              email address below and then replace the
              initial password.
            </div>


            <form
                method="POST"
                action="admin.php?action=add_admin"
            >

              <?= csrfField() ?>

              <input
                  type="hidden"
                  name="form_action"
                  value="add"
              >


              <div class="form-group">

                <label>
                  Username *
                </label>

                <input
                    type="text"
                    name="username"
                    required
                    maxlength="100"
                    autocomplete="off"
                >
              </div>


              <div class="form-group">

                <label>
                  Email *
                  <small style="color:#888;">
                    (verification codes are sent here)
                  </small>
                </label>

                <input
                    type="email"
                    name="email"
                    required
                    placeholder="name@example.com"
                >
              </div>


              <div class="form-group">

                <label>
                  Phone
                  (optional, 27XXXXXXXXX)
                </label>

                <input
                    type="tel"
                    name="phone"
                    placeholder="e.g. 27821234567"
                    pattern="27[0-9]{9}"
                    title="Format: 27 followed by 9 digits"
                >
              </div>


              <div class="form-group">

                <label>
                  Initial Password *
                  (minimum <?= ADMIN_PASSWORD_MIN_LENGTH ?> characters)
                </label>

                <input
                    type="password"
                    name="password"
                    required
                    autocomplete="new-password"
                    minlength="<?= ADMIN_PASSWORD_MIN_LENGTH ?>"
                >
              </div>


              <button
                  type="submit"
                  class="btn btn-primary btn-block"
              >
                Create Administrator
              </button>

            </form>


            <div class="popia-notice">
              Administrator data is processed for
              access-control and estate-management purposes.
            </div>

          </div>

        </div>

        <?php

        pageFooter();
        exit;
    }


    /*
     * ------------------------------------------------------------
     * EDIT PAGE
     * ------------------------------------------------------------
     */
    if (isset($_GET['edit'])) {

        $adminId =
            (int)$_GET['edit'];

        $stmt =
            db()->prepare(
                "SELECT
                    id,
                    username,
                    email,
                    phone
                 FROM admins
                 WHERE id = ?
                 LIMIT 1"
            );

        $stmt->execute([
            $adminId
        ]);

        $adm =
            $stmt->fetch();


        if (!$adm) {

            setFlash(
                'error',
                'Administrator not found.'
            );

            header(
                'Location: admin.php?action=add_admin'
            );

            exit;
        }


        $isSelf =
            (int)$adm['id']
            ===
            (int)(
                $_SESSION[
                    'admin_id'
                ]
                ?? 0
            );


        pageHeader(
            'Edit Administrator',
            'admin'
        );

        renderHeader(
            '✏️ Edit — ' .
            (string)$adm['username'],
            'admin.php?action=add_admin'
        );
        ?>

        <div
            class="container"
            style="max-width:560px;"
        >

          <div class="card">

            <?= getFlash() ?>


            <div
                style="
                  background:#f5f7fa;
                  border-radius:8px;
                  padding:10px 14px;
                  margin-bottom:16px;
                  font-size:.88rem;
                "
            >
              <strong>Username:</strong>

              <span
                  style="
                    font-family:monospace;
                    font-size:1.05rem;
                    font-weight:800;
                    color:var(--accent);
                  "
              >
                <?= htmlspecialchars(
                    (string)$adm['username'],
                    ENT_QUOTES | ENT_SUBSTITUTE,
                    'UTF-8'
                ) ?>
              </span>
            </div>


            <form
                method="POST"
                action="admin.php?action=add_admin"
            >

              <?= csrfField() ?>

              <input
                  type="hidden"
                  name="form_action"
                  value="update"
              >

              <input
                  type="hidden"
                  name="uid"
                  value="<?= (int)$adm['id'] ?>"
              >


              <div class="form-group">

                <label>
                  Username *
                </label>

                <input
                    type="text"
                    name="username"
                    required
                    autocomplete="off"
                    maxlength="100"
                    value="<?= htmlspecialchars(
                        (string)$adm['username'],
                        ENT_QUOTES | ENT_SUBSTITUTE,
                        'UTF-8'
                    ) ?>"
                >
              </div>


              <div class="form-group">

                <label>
                  Email *
                  <small style="color:#888;">
                    (verification codes are sent here)
                  </small>
                </label>

                <input
                    type="email"
                    name="email"
                    required
                    value="<?= htmlspecialchars(
                        (string)(
                            $adm['email']
                            ?? ''
                        ),
                        ENT_QUOTES | ENT_SUBSTITUTE,
                        'UTF-8'
                    ) ?>"
                >
              </div>


              <div class="form-group">

                <label>
                  Phone
                  (optional, 27XXXXXXXXX)
                </label>

                <input
                    type="tel"
                    name="phone"
                    pattern="27[0-9]{9}"
                    title="Format: 27 followed by 9 digits"
                    value="<?= htmlspecialchars(
                        (string)(
                            $adm['phone']
                            ?? ''
                        ),
                        ENT_QUOTES | ENT_SUBSTITUTE,
                        'UTF-8'
                    ) ?>"
                >
              </div>


              <?php if ($isSelf): ?>

                <div class="alert alert-info">
                  To change your own password, use the
                  <strong>Change Password</strong>
                  screen from the Admin menu.
                </div>

              <?php else: ?>

                <div class="form-group">

                  <label>
                    Reset Password
                    (leave blank to keep current)
                  </label>

                  <input
                      type="password"
                      name="password"
                      autocomplete="new-password"
                      minlength="<?= ADMIN_PASSWORD_MIN_LENGTH ?>"
                      placeholder="Leave blank to keep current"
                  >

                  <small style="color:#888;">
                    Setting a reset password signs this administrator
                    out, revokes their trusted device, and requires
                    verification plus a new password on next login.
                  </small>

                </div>

              <?php endif; ?>


              <button
                  type="submit"
                  class="btn btn-primary btn-block"
              >
                Save Changes
              </button>

            </form>


            <div class="popia-notice">
              Administrator data is processed for
              access-control and estate-management purposes.
            </div>

          </div>

        </div>

        <?php

        pageFooter();
        exit;
    }


    /*
     * ------------------------------------------------------------
     * LIST PAGE
     * ------------------------------------------------------------
     */
    $search =
        trim(
            (string)(
                $_GET['q']
                ?? ''
            )
        );

    if (
        mb_strlen($search)
        === 1
    ) {
        $search = '';
    }


    if ($search !== '') {

        $stmt =
            db()->prepare(
                "SELECT
                    id,
                    username,
                    email,
                    phone
                 FROM admins
                 WHERE
                    username LIKE ?
                    OR email LIKE ?
                    OR phone LIKE ?
                 ORDER BY username"
            );

        $like =
            '%' . $search . '%';

        $stmt->execute([
            $like,
            $like,
            $like,
        ]);

    } else {

        $stmt =
            db()->query(
                "SELECT
                    id,
                    username,
                    email,
                    phone
                 FROM admins
                 ORDER BY username"
            );
    }


    $admins =
        $stmt->fetchAll();

    $selfId =
        (int)(
            $_SESSION[
                'admin_id'
            ]
            ?? 0
        );

    $count =
        (int)(
            db()->query(
                "SELECT COUNT(*)
                 FROM admins"
            )->fetchColumn()
        );


    pageHeader(
        'Administrators',
        'admin'
    );

    renderHeader(
        '👤 Administrators',
        'admin.php?action=menu'
    );
    ?>

    <div class="container">

      <?= getFlash() ?>


      <div
          class="card"
          style="
            display:flex;
            gap:10px;
            flex-wrap:wrap;
            align-items:center;
          "
      >

        <form
            method="GET"
            style="
              flex:1;
              display:flex;
              gap:8px;
            "
        >

          <input
              type="hidden"
              name="action"
              value="add_admin"
          >

          <input
              type="text"
              name="q"
              value="<?= htmlspecialchars(
                  $search,
                  ENT_QUOTES | ENT_SUBSTITUTE,
                  'UTF-8'
              ) ?>"
              placeholder="Search username, email or phone… (min 2 chars)"
              minlength="2"
              style="
                flex:1;
                padding:8px 12px;
                border:1px solid #dee2e6;
                border-radius:6px;
              "
          >

          <button
              type="submit"
              class="btn btn-primary"
          >
            Search
          </button>


          <?php if ($search !== ''): ?>

            <a
                href="admin.php?action=add_admin"
                class="btn btn-secondary"
            >
              Clear
            </a>

          <?php endif; ?>

        </form>


        <a
            href="admin.php?action=add_admin&new=1"
            class="btn btn-success"
        >
          + Add Administrator
        </a>

      </div>


      <div
          style="
            font-size:.85rem;
            color:#666;
            margin-bottom:12px;
          "
      >
        <?= $count ?>
        administrator<?= $count === 1 ? '' : 's' ?>
        total

        <?php if ($search !== ''): ?>

          &nbsp;|&nbsp;
          Search:

          <strong>
            <?= htmlspecialchars(
                $search,
                ENT_QUOTES | ENT_SUBSTITUTE,
                'UTF-8'
            ) ?>
          </strong>

        <?php endif; ?>
      </div>


      <div class="card">

        <?php if (empty($admins)): ?>

          <p style="color:#666;">
            No administrators found.
          </p>

        <?php else: ?>

          <div class="table-wrap">

            <table>

              <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Phone</th>
                <th>Actions</th>
              </tr>


              <?php foreach ($admins as $administrator): ?>

                <?php
                $isSelf =
                    (int)$administrator['id']
                    ===
                    $selfId;

                $isBootstrap =
                    (int)$administrator['id']
                    === 1;

                $isLast =
                    $count <= 1;

                $blockDelete =
                    $isSelf ||
                    $isLast ||
                    $isBootstrap;

                if ($isBootstrap) {
                    $blockReason =
                        'Protected bootstrap administrator (ID 1) — cannot be deleted';

                } elseif ($isSelf) {
                    $blockReason =
                        'You cannot delete the account you are logged in with';

                } else {
                    $blockReason =
                        'Cannot delete the last remaining administrator';
                }
                ?>

                <tr>

                  <td>

                    <span style="font-weight:700;">
                      <?= htmlspecialchars(
                          (string)$administrator[
                              'username'
                          ],
                          ENT_QUOTES | ENT_SUBSTITUTE,
                          'UTF-8'
                      ) ?>
                    </span>


                    <?php if ($isBootstrap): ?>

                      <span
                          class="badge badge-warning"
                          style="margin-left:4px;"
                      >
                        PROTECTED
                      </span>

                    <?php endif; ?>


                    <?php if ($isSelf): ?>

                      <span
                          class="badge badge-info"
                          style="margin-left:4px;"
                      >
                        YOU
                      </span>

                    <?php endif; ?>

                  </td>


                  <td>
                    <?= htmlspecialchars(
                        (string)(
                            $administrator[
                                'email'
                            ]
                            ?? ''
                        ),
                        ENT_QUOTES | ENT_SUBSTITUTE,
                        'UTF-8'
                    ) ?>
                  </td>


                  <td>
                    <?= htmlspecialchars(
                        (string)(
                            $administrator[
                                'phone'
                            ]
                            ?? ''
                        ),
                        ENT_QUOTES | ENT_SUBSTITUTE,
                        'UTF-8'
                    ) ?>
                  </td>


                  <td>

                    <div
                        style="
                          display:flex;
                          gap:4px;
                          flex-wrap:wrap;
                        "
                    >

                      <a
                          href="admin.php?action=add_admin&edit=<?= (int)$administrator['id'] ?>"
                          class="btn btn-primary btn-sm"
                      >
                        Edit
                      </a>


                      <?php if ($blockDelete): ?>

                        <button
                            class="btn btn-sm btn-danger"
                            style="
                              opacity:.4;
                              cursor:not-allowed;
                            "
                            title="<?= htmlspecialchars(
                                $blockReason,
                                ENT_QUOTES | ENT_SUBSTITUTE,
                                'UTF-8'
                            ) ?>"
                            disabled
                        >
                          Delete
                        </button>

                      <?php else: ?>

                        <form
                            method="POST"
                            action="admin.php?action=add_admin"
                            style="display:inline"
                            onsubmit="return confirm('Permanently delete this administrator? This cannot be undone.');"
                        >

                          <?= csrfField() ?>

                          <input
                              type="hidden"
                              name="form_action"
                              value="delete"
                          >

                          <input
                              type="hidden"
                              name="uid"
                              value="<?= (int)$administrator['id'] ?>"
                          >

                          <button
                              type="submit"
                              class="btn btn-danger btn-sm"
                          >
                            Delete
                          </button>

                        </form>

                      <?php endif; ?>

                    </div>

                  </td>

                </tr>

              <?php endforeach; ?>

            </table>

          </div>

        <?php endif; ?>

      </div>

    </div>

    <?php

    pageFooter();
    exit;
}


/*
|--------------------------------------------------------------------------
| SITE MANAGERS
|--------------------------------------------------------------------------
|
| Existing non-admin authentication behaviour is intentionally retained.
| Their login system should be reviewed separately before changing its
| session/device architecture.
|
*/

if ($action === 'add_security') {

    if (
        $_SERVER['REQUEST_METHOD']
        === 'POST'
    ) {
        verifyCsrfToken();

        $formAction =
            $_POST[
                'form_action'
            ]
            ?? 'add';


        /*
         * Add Site Manager
         */
        if ($formAction === 'add') {

            $pin =
                trim(
                    (string)(
                        $_POST[
                            'pin'
                        ]
                        ?? ''
                    )
                );

            $email =
                strtolower(
                    trim(
                        (string)(
                            $_POST[
                                'email'
                            ]
                            ?? ''
                        )
                    )
                );

            $username =
                trim(
                    (string)(
                        $_POST[
                            'username'
                        ]
                        ?? ''
                    )
                );

            $name =
                trim(
                    (string)(
                        $_POST[
                            'name'
                        ]
                        ?? ''
                    )
                );

            $phone =
                trim(
                    (string)(
                        $_POST[
                            'phone'
                        ]
                        ?? ''
                    )
                );


            if (
                $username === '' ||
                $name === ''
            ) {
                setFlash(
                    'error',
                    'Name and username are required.'
                );

                header(
                    'Location: admin.php?action=add_security'
                );

                exit;
            }


            if (
                !preg_match(
                    '/^\d{4,8}$/',
                    $pin
                )
            ) {
                setFlash(
                    'error',
                    'PIN must be 4–8 digits.'
                );

                header(
                    'Location: admin.php?action=add_security'
                );

                exit;
            }


            if (
                !filter_var(
                    $email,
                    FILTER_VALIDATE_EMAIL
                )
            ) {
                setFlash(
                    'error',
                    'A valid email address is required for account recovery.'
                );

                header(
                    'Location: admin.php?action=add_security'
                );

                exit;
            }


            if (
                $phone !== '' &&
                !preg_match(
                    '/^27\d{9}$/',
                    $phone
                )
            ) {
                setFlash(
                    'error',
                    'Phone must be in format 27XXXXXXXXX (11 digits).'
                );

                header(
                    'Location: admin.php?action=add_security'
                );

                exit;
            }


            try {

                db()->prepare(
                    "INSERT INTO security_users (
                        username,
                        name,
                        phone,
                        email,
                        pin,
                        password_changed_at
                    )
                    VALUES (?, ?, ?, ?, ?, NOW())"
                )->execute([
                    $username,
                    $name,
                    $phone,
                    $email,
                    password_hash(
                        $pin,
                        PASSWORD_DEFAULT
                    ),
                ]);


                setFlash(
                    'success',
                    'Site Manager added.'
                );

            } catch (Throwable $e) {

                setFlash(
                    'error',
                    'Unable to add Site Manager. The username may already exist.'
                );
            }
        }


        /*
         * Update Site Manager
         */
        elseif (
            $formAction === 'update'
        ) {
            $userId =
                (int)(
                    $_POST[
                        'uid'
                    ]
                    ?? 0
                );

            $name =
                trim(
                    (string)(
                        $_POST[
                            'name'
                        ]
                        ?? ''
                    )
                );

            $username =
                trim(
                    (string)(
                        $_POST[
                            'username'
                        ]
                        ?? ''
                    )
                );

            $phone =
                trim(
                    (string)(
                        $_POST[
                            'phone'
                        ]
                        ?? ''
                    )
                );

            $email =
                strtolower(
                    trim(
                        (string)(
                            $_POST[
                                'email'
                            ]
                            ?? ''
                        )
                    )
                );

            $pin =
                trim(
                    (string)(
                        $_POST[
                            'pin'
                        ]
                        ?? ''
                    )
                );


            if (
                $userId <= 0 ||
                $name === '' ||
                $username === ''
            ) {
                setFlash(
                    'error',
                    'Name and username are required.'
                );

                header(
                    'Location: admin.php?action=add_security&edit=' .
                    $userId
                );

                exit;
            }


            if (
                !filter_var(
                    $email,
                    FILTER_VALIDATE_EMAIL
                )
            ) {
                setFlash(
                    'error',
                    'A valid email address is required for account recovery.'
                );

                header(
                    'Location: admin.php?action=add_security&edit=' .
                    $userId
                );

                exit;
            }


            if (
                $phone !== '' &&
                !preg_match(
                    '/^27\d{9}$/',
                    $phone
                )
            ) {
                setFlash(
                    'error',
                    'Phone must be in format 27XXXXXXXXX (11 digits).'
                );

                header(
                    'Location: admin.php?action=add_security&edit=' .
                    $userId
                );

                exit;
            }


            try {

                if ($pin !== '') {

                    if (
                        !preg_match(
                            '/^\d{4,8}$/',
                            $pin
                        )
                    ) {
                        setFlash(
                            'error',
                            'PIN must be 4–8 digits.'
                        );

                        header(
                            'Location: admin.php?action=add_security&edit=' .
                            $userId
                        );

                        exit;
                    }


                    db()->prepare(
                        "UPDATE security_users
                         SET name = ?,
                             username = ?,
                             phone = ?,
                             email = ?,
                             pin = ?,
                             device_token = NULL,
                             password_changed_at = NOW()
                         WHERE id = ?"
                    )->execute([
                        $name,
                        $username,
                        $phone,
                        $email,
                        password_hash(
                            $pin,
                            PASSWORD_DEFAULT
                        ),
                        $userId,
                    ]);


                    setFlash(
                        'success',
                        'Site Manager updated. PIN reset; their trusted device was revoked.'
                    );

                } else {

                    db()->prepare(
                        "UPDATE security_users
                         SET name = ?,
                             username = ?,
                             phone = ?,
                             email = ?
                         WHERE id = ?"
                    )->execute([
                        $name,
                        $username,
                        $phone,
                        $email,
                        $userId,
                    ]);


                    setFlash(
                        'success',
                        'Site Manager updated.'
                    );
                }

            } catch (Throwable $e) {

                setFlash(
                    'error',
                    'Unable to update Site Manager. The username may already exist.'
                );
            }
        }


        /*
         * Delete Site Manager
         */
        elseif (
            $formAction === 'delete'
        ) {
            $userId =
                (int)(
                    $_POST[
                        'uid'
                    ]
                    ?? 0
                );

            if ($userId > 0) {
                db()->prepare(
                    "DELETE FROM security_users
                     WHERE id = ?"
                )->execute([
                    $userId
                ]);

                setFlash(
                    'success',
                    'Site Manager removed.'
                );
            }
        }


        header(
            'Location: admin.php?action=add_security'
        );

        exit;
    }


    /*
     * Fetch after POST processing.
     */
    $users =
        db()->query(
            "SELECT *
             FROM security_users
             ORDER BY name"
        )->fetchAll();


    $editUser = null;

    if (isset($_GET['edit'])) {

        $stmt =
            db()->prepare(
                "SELECT
                    id,
                    username,
                    name,
                    phone,
                    email
                 FROM security_users
                 WHERE id = ?
                 LIMIT 1"
            );

        $stmt->execute([
            (int)$_GET['edit']
        ]);

        $editUser =
            $stmt->fetch()
            ?: null;
    }


    pageHeader(
        'Site Managers',
        'admin'
    );

    renderHeader(
        '🛡️ Site Managers',
        'admin.php?action=menu'
    );
    ?>

    <div class="container">

      <?= getFlash() ?>


      <div class="card">

        <div class="card-title">
          Site Managers
        </div>


        <?php if (empty($users)): ?>

          <p style="color:#666;">
            None added yet.
          </p>

        <?php else: ?>

          <div class="table-wrap">

            <table>

              <tr>
                <th>Name</th>
                <th>Username</th>
                <th>Phone</th>
                <th>Email</th>
                <th>Action</th>
              </tr>


              <?php foreach ($users as $user): ?>

                <tr>

                  <td>
                    <?= htmlspecialchars(
                        (string)$user['name'],
                        ENT_QUOTES | ENT_SUBSTITUTE,
                        'UTF-8'
                    ) ?>
                  </td>

                  <td>
                    <?= htmlspecialchars(
                        (string)$user['username'],
                        ENT_QUOTES | ENT_SUBSTITUTE,
                        'UTF-8'
                    ) ?>
                  </td>

                  <td>
                    <?= htmlspecialchars(
                        (string)(
                            $user['phone']
                            ?? ''
                        ),
                        ENT_QUOTES | ENT_SUBSTITUTE,
                        'UTF-8'
                    ) ?>
                  </td>

                  <td>
                    <?= htmlspecialchars(
                        (string)(
                            $user['email']
                            ?? ''
                        ),
                        ENT_QUOTES | ENT_SUBSTITUTE,
                        'UTF-8'
                    ) ?>
                  </td>

                  <td>

                    <a
                        href="admin.php?action=add_security&edit=<?= (int)$user['id'] ?>"
                        class="btn btn-primary btn-sm"
                    >
                      Edit
                    </a>

                    <form
                        method="POST"
                        onsubmit="return confirm('Delete this Site Manager?');"
                        style="display:inline"
                    >

                      <?= csrfField() ?>

                      <input
                          type="hidden"
                          name="form_action"
                          value="delete"
                      >

                      <input
                          type="hidden"
                          name="uid"
                          value="<?= (int)$user['id'] ?>"
                      >

                      <button
                          type="submit"
                          class="btn btn-danger btn-sm"
                      >
                        Delete
                      </button>

                    </form>

                  </td>

                </tr>

              <?php endforeach; ?>

            </table>

          </div>

        <?php endif; ?>

      </div>


      <div class="card">

        <div class="card-title">
          <?= $editUser
              ? 'Edit Site Manager'
              : 'Add Site Manager'
          ?>
        </div>


        <form method="POST">

          <?= csrfField() ?>

          <input
              type="hidden"
              name="form_action"
              value="<?= $editUser ? 'update' : 'add' ?>"
          >


          <?php if ($editUser): ?>

            <input
                type="hidden"
                name="uid"
                value="<?= (int)$editUser['id'] ?>"
            >

          <?php endif; ?>


          <div class="form-group">

            <label>
              Full Name
            </label>

            <input
                type="text"
                name="name"
                required
                value="<?= htmlspecialchars(
                    (string)(
                        $editUser['name']
                        ?? ''
                    ),
                    ENT_QUOTES | ENT_SUBSTITUTE,
                    'UTF-8'
                ) ?>"
            >
          </div>


          <div class="form-group">

            <label>
              Username
            </label>

            <input
                type="text"
                name="username"
                required
                autocomplete="off"
                value="<?= htmlspecialchars(
                    (string)(
                        $editUser['username']
                        ?? ''
                    ),
                    ENT_QUOTES | ENT_SUBSTITUTE,
                    'UTF-8'
                ) ?>"
            >
          </div>


          <div class="form-group">

            <label>
              Phone (27XXXXXXXXX)
            </label>

            <input
                type="tel"
                name="phone"
                placeholder="e.g. 27821234567"
                pattern="27[0-9]{9}"
                title="Format: 27 followed by 9 digits"
                value="<?= htmlspecialchars(
                    (string)(
                        $editUser['phone']
                        ?? ''
                    ),
                    ENT_QUOTES | ENT_SUBSTITUTE,
                    'UTF-8'
                ) ?>"
            >
          </div>


          <div class="form-group">

            <label>
              Email
              <small style="color:#888;">
                (for account recovery)
              </small>
            </label>

            <input
                type="email"
                name="email"
                required
                placeholder="name@example.com"
                value="<?= htmlspecialchars(
                    (string)(
                        $editUser['email']
                        ?? ''
                    ),
                    ENT_QUOTES | ENT_SUBSTITUTE,
                    'UTF-8'
                ) ?>"
            >
          </div>


          <div class="form-group">

            <label>
              <?= $editUser
                  ? 'New PIN (leave blank to keep current)'
                  : 'PIN (4–8 digits)'
              ?>
            </label>

            <input
                type="password"
                name="pin"
                <?= $editUser ? '' : 'required' ?>
                inputmode="numeric"
                maxlength="8"
                pattern="[0-9]{4,8}"
                placeholder="e.g. 1234"
                style="
                  font-size:1.4rem;
                  letter-spacing:0.3em;
                  text-align:center;
                "
            >

            <small style="color:#888;">
              <?= $editUser
                  ? 'Changing the PIN revokes the currently trusted device.'
                  : 'Used to log in to the Site Manager portal.'
              ?>
            </small>

          </div>


          <button
              type="submit"
              class="btn btn-primary"
          >
            <?= $editUser
                ? 'Save Changes'
                : 'Add Site Manager'
            ?>
          </button>


          <?php if ($editUser): ?>

            <a
                href="admin.php?action=add_security"
                style="
                  margin-left:12px;
                  font-size:.85rem;
                  color:var(--muted);
                "
            >
              Cancel
            </a>

          <?php endif; ?>

        </form>


        <div class="popia-notice">
          Staff data is processed for
          access-control purposes.
        </div>

      </div>

    </div>

    <?php

    pageFooter();
    exit;
}


/*
|--------------------------------------------------------------------------
| GUARDS
|--------------------------------------------------------------------------
*/

if ($action === 'add_guard') {

    if (
        $_SERVER['REQUEST_METHOD']
        === 'POST'
    ) {
        verifyCsrfToken();

        $formAction =
            $_POST[
                'form_action'
            ]
            ?? 'add';


        if ($formAction === 'add') {

            $pin =
                trim(
                    (string)(
                        $_POST[
                            'pin'
                        ]
                        ?? ''
                    )
                );

            $username =
                trim(
                    (string)(
                        $_POST[
                            'username'
                        ]
                        ?? ''
                    )
                );

            $name =
                trim(
                    (string)(
                        $_POST[
                            'name'
                        ]
                        ?? ''
                    )
                );

            $phone =
                trim(
                    (string)(
                        $_POST[
                            'phone'
                        ]
                        ?? ''
                    )
                );

            $gate =
                (string)(
                    $_POST[
                        'gate'
                    ]
                    ?? 'SSgate'
                );

            $validGates = [
                'SSgate',
                'CSgate',
                'entry',
            ];


            if (
                $username === '' ||
                $name === ''
            ) {
                setFlash(
                    'error',
                    'Name and username are required.'
                );

                header(
                    'Location: admin.php?action=add_guard'
                );

                exit;
            }


            if (
                !preg_match(
                    '/^\d{4}$/',
                    $pin
                )
            ) {
                setFlash(
                    'error',
                    'PIN must be exactly 4 digits.'
                );

                header(
                    'Location: admin.php?action=add_guard'
                );

                exit;
            }


            if (
                $phone !== '' &&
                !preg_match(
                    '/^27\d{9}$/',
                    $phone
                )
            ) {
                setFlash(
                    'error',
                    'Phone must be in format 27XXXXXXXXX (11 digits).'
                );

                header(
                    'Location: admin.php?action=add_guard'
                );

                exit;
            }


            if (
                !in_array(
                    $gate,
                    $validGates,
                    true
                )
            ) {
                $gate = 'SSgate';
            }


            try {

                db()->prepare(
                    "INSERT INTO guards (
                        username,
                        name,
                        phone,
                        pin,
                        gate
                    )
                    VALUES (?, ?, ?, ?, ?)"
                )->execute([
                    $username,
                    $name,
                    $phone,
                    password_hash(
                        $pin,
                        PASSWORD_DEFAULT
                    ),
                    $gate,
                ]);


                setFlash(
                    'success',
                    'Guard added successfully.'
                );

            } catch (Throwable $e) {

                setFlash(
                    'error',
                    'Unable to add guard. The username may already exist.'
                );
            }
        }


        elseif (
            $formAction === 'delete'
        ) {
            $guardId =
                (int)(
                    $_POST[
                        'uid'
                    ]
                    ?? 0
                );

            if ($guardId > 0) {

                db()->prepare(
                    "DELETE FROM guards
                     WHERE id = ?"
                )->execute([
                    $guardId
                ]);

                setFlash(
                    'success',
                    'Guard removed.'
                );
            }
        }


        header(
            'Location: admin.php?action=add_guard'
        );

        exit;
    }


    $guards =
        db()->query(
            "SELECT *
             FROM guards
             ORDER BY name"
        )->fetchAll();


    pageHeader(
        'Guards',
        'admin'
    );

    renderHeader(
        '👮 Manage Guards',
        'admin.php?action=menu'
    );
    ?>

    <div class="container">

      <?= getFlash() ?>


      <div class="card">

        <div class="card-title">
          Guards
        </div>


        <?php if (empty($guards)): ?>

          <p style="color:#666;">
            None added yet.
          </p>

        <?php else: ?>

          <div class="table-wrap">

            <table>

              <tr>
                <th>Name</th>
                <th>Username</th>
                <th>Gate</th>
                <th>Phone</th>
                <th>Action</th>
              </tr>


              <?php foreach ($guards as $guard): ?>

                <tr>

                  <td>
                    <?= htmlspecialchars(
                        (string)$guard['name'],
                        ENT_QUOTES | ENT_SUBSTITUTE,
                        'UTF-8'
                    ) ?>
                  </td>


                  <td>
                    <?= htmlspecialchars(
                        (string)$guard['username'],
                        ENT_QUOTES | ENT_SUBSTITUTE,
                        'UTF-8'
                    ) ?>
                  </td>


                  <td>

                    <span class="badge badge-info">

                      <?= htmlspecialchars(
                          (string)(
                              $guard[
                                  'gate'
                              ]
                              ?? 'Any'
                          ),
                          ENT_QUOTES | ENT_SUBSTITUTE,
                          'UTF-8'
                      ) ?>

                    </span>

                  </td>


                  <td>
                    <?= htmlspecialchars(
                        (string)(
                            $guard[
                                'phone'
                            ]
                            ?? ''
                        ),
                        ENT_QUOTES | ENT_SUBSTITUTE,
                        'UTF-8'
                    ) ?>
                  </td>


                  <td>

                    <form
                        method="POST"
                        onsubmit="return confirm('Delete this guard?');"
                        style="display:inline"
                    >

                      <?= csrfField() ?>

                      <input
                          type="hidden"
                          name="form_action"
                          value="delete"
                      >

                      <input
                          type="hidden"
                          name="uid"
                          value="<?= (int)$guard['id'] ?>"
                      >

                      <button
                          type="submit"
                          class="btn btn-danger btn-sm"
                      >
                        Delete
                      </button>

                    </form>

                  </td>

                </tr>

              <?php endforeach; ?>

            </table>

          </div>

        <?php endif; ?>

      </div>


      <div class="card">

        <div class="card-title">
          Add Guard
        </div>


        <form method="POST">

          <?= csrfField() ?>

          <input
              type="hidden"
              name="form_action"
              value="add"
          >


          <div class="form-group">

            <label>
              Full Name
            </label>

            <input
                type="text"
                name="name"
                required
            >
          </div>


          <div class="form-group">

            <label>
              Username
            </label>

            <input
                type="text"
                name="username"
                required
                autocomplete="off"
            >
          </div>


          <div class="form-group">

            <label>
              Phone (27XXXXXXXXX)
            </label>

            <input
                type="tel"
                name="phone"
                placeholder="e.g. 27821234567"
                pattern="27[0-9]{9}"
                title="Format: 27 followed by 9 digits"
            >
          </div>


          <div class="form-group">

            <label>
              4-digit PIN
            </label>

            <input
                type="password"
                name="pin"
                required
                inputmode="numeric"
                maxlength="4"
                pattern="[0-9]{4}"
                placeholder="e.g. 1234"
                style="
                  font-size:1.6rem;
                  letter-spacing:0.4em;
                  text-align:center;
                "
            >

            <small style="color:#888;">
              Guard logs in using the username
              and this 4-digit PIN.
            </small>

          </div>


          <div class="form-group">

            <label>
              Gate Assignment
            </label>

            <select name="gate">

              <option value="SSgate">
                SSgate — Schoeman Street
              </option>

              <option value="CSgate">
                CSgate — Church Street
              </option>

              <option value="entry">
                Any Gate
              </option>

            </select>

          </div>


          <button
              type="submit"
              class="btn btn-primary"
          >
            Add Guard
          </button>

        </form>


        <div class="popia-notice">
          Staff data is processed for
          access-control purposes.
        </div>

      </div>

    </div>

    <?php

    pageFooter();
    exit;
}


/*
|--------------------------------------------------------------------------
| HELPDESK
|--------------------------------------------------------------------------
*/

if ($action === 'helpdesk') {

    if (
        $_SERVER['REQUEST_METHOD']
        === 'POST'
    ) {
        verifyCsrfToken();

        $validStatuses = [
            'open',
            'in_progress',
            'resolved',
            'closed',
        ];

        $requestedStatus =
            (string)(
                $_POST[
                    'status'
                ]
                ?? ''
            );

        $status =
            in_array(
                $requestedStatus,
                $validStatuses,
                true
            )
                ? $requestedStatus
                : 'open';

        $ticketId =
            (int)(
                $_POST[
                    'ticket_id'
                ]
                ?? 0
            );

        $response =
            trim(
                (string)(
                    $_POST[
                        'response'
                    ]
                    ?? ''
                )
            );


        if ($ticketId > 0) {

            db()->prepare(
                "UPDATE helpdesk
                 SET response = ?,
                     status = ?
                 WHERE id = ?"
            )->execute([
                $response,
                $status,
                $ticketId,
            ]);


            setFlash(
                'success',
                'Ticket updated.'
            );
        }


        header(
            'Location: admin.php?action=helpdesk'
        );

        exit;
    }


    $tickets =
        db()->query(
            "SELECT *
             FROM helpdesk
             ORDER BY
                FIELD(
                    status,
                    'open',
                    'in_progress',
                    'resolved',
                    'closed'
                ),
                FIELD(
                    priority,
                    'urgent',
                    'high',
                    'normal',
                    'low'
                ),
                created_at DESC"
        )->fetchAll();


    pageHeader(
        'Helpdesk',
        'admin'
    );

    renderHeader(
        '🔧 Helpdesk Tickets',
        'admin.php?action=menu'
    );
    ?>

    <div class="container">

      <?= getFlash() ?>


      <?php if (empty($tickets)): ?>

        <div class="card">
          <p style="color:#666;">
            No tickets yet.
          </p>
        </div>

      <?php endif; ?>


      <?php foreach ($tickets as $ticket): ?>

        <?php
        $ticketStatus =
            (string)(
                $ticket[
                    'status'
                ]
                ?? 'open'
            );

        $ticketPriority =
            (string)(
                $ticket[
                    'priority'
                ]
                ?? 'normal'
            );

        if ($ticketStatus === 'open') {
            $borderColor = '#ffc107';

        } elseif (
            in_array(
                $ticketStatus,
                [
                    'resolved',
                    'closed',
                ],
                true
            )
        ) {
            $borderColor = '#28a745';

        } else {
            $borderColor = '#17a2b8';
        }


        if ($ticketPriority === 'urgent') {
            $priorityBadge = 'danger';

        } elseif (
            $ticketPriority === 'high'
        ) {
            $priorityBadge = 'warning';

        } else {
            $priorityBadge = 'info';
        }


        if (
            in_array(
                $ticketStatus,
                [
                    'resolved',
                    'closed',
                ],
                true
            )
        ) {
            $statusBadge = 'success';

        } elseif (
            $ticketStatus === 'open'
        ) {
            $statusBadge = 'warning';

        } else {
            $statusBadge = 'info';
        }
        ?>


        <div
            class="card"
            style="
              border-left:4px solid <?= htmlspecialchars(
                  $borderColor,
                  ENT_QUOTES | ENT_SUBSTITUTE,
                  'UTF-8'
              ) ?>;
            "
        >

          <div
              style="
                display:flex;
                justify-content:space-between;
                flex-wrap:wrap;
                gap:6px;
                margin-bottom:6px;
              "
          >

            <div>

              <strong>
                <?= htmlspecialchars(
                    (string)(
                        $ticket[
                            'subject'
                        ]
                        ?? ''
                    ),
                    ENT_QUOTES | ENT_SUBSTITUTE,
                    'UTF-8'
                ) ?>
              </strong>


              <span
                  style="
                    color:#666;
                    font-size:.82rem;
                    margin-left:6px;
                  "
              >
                <?= htmlspecialchars(
                    (string)(
                        $ticket[
                            'category'
                        ]
                        ?? ''
                    ),
                    ENT_QUOTES | ENT_SUBSTITUTE,
                    'UTF-8'
                ) ?>
              </span>


              <div
                  style="
                    font-size:.8rem;
                    color:#999;
                  "
              >
                Erf
                <?= htmlspecialchars(
                    (string)(
                        $ticket[
                            'resident_erfno'
                        ]
                        ?? ''
                    ),
                    ENT_QUOTES | ENT_SUBSTITUTE,
                    'UTF-8'
                ) ?>
                —
                <?= htmlspecialchars(
                    (string)(
                        $ticket[
                            'resident_name'
                        ]
                        ?? ''
                    ),
                    ENT_QUOTES | ENT_SUBSTITUTE,
                    'UTF-8'
                ) ?>
              </div>

            </div>


            <div
                style="
                  display:flex;
                  gap:6px;
                  align-items:center;
                "
            >

              <span
                  class="badge badge-<?= $priorityBadge ?>"
              >
                <?= htmlspecialchars(
                    $ticketPriority,
                    ENT_QUOTES | ENT_SUBSTITUTE,
                    'UTF-8'
                ) ?>
              </span>


              <span
                  class="badge badge-<?= $statusBadge ?>"
              >
                <?= htmlspecialchars(
                    $ticketStatus,
                    ENT_QUOTES | ENT_SUBSTITUTE,
                    'UTF-8'
                ) ?>
              </span>

            </div>

          </div>


          <div
              style="
                font-size:.85rem;
                margin-bottom:10px;
              "
          >
            <?= htmlspecialchars(
                (string)(
                    $ticket[
                        'description'
                    ]
                    ?? ''
                ),
                ENT_QUOTES | ENT_SUBSTITUTE,
                'UTF-8'
            ) ?>
          </div>


          <form
              method="POST"
              style="
                display:flex;
                gap:8px;
                flex-wrap:wrap;
              "
          >

            <?= csrfField() ?>

            <input
                type="hidden"
                name="ticket_id"
                value="<?= (int)$ticket['id'] ?>"
            >


            <input
                type="text"
                name="response"
                value="<?= htmlspecialchars(
                    (string)(
                        $ticket[
                            'response'
                        ]
                        ?? ''
                    ),
                    ENT_QUOTES | ENT_SUBSTITUTE,
                    'UTF-8'
                ) ?>"
                placeholder="Response to resident…"
                style="
                  flex:1;
                  padding:6px 10px;
                  border:1px solid #dee2e6;
                  border-radius:6px;
                  font-size:.88rem;
                "
            >


            <select
                name="status"
                style="
                  padding:6px;
                  border:1px solid #dee2e6;
                  border-radius:6px;
                "
            >

              <option
                  value="open"
                  <?= $ticketStatus === 'open'
                      ? 'selected'
                      : ''
                  ?>
              >
                Open
              </option>

              <option
                  value="in_progress"
                  <?= $ticketStatus === 'in_progress'
                      ? 'selected'
                      : ''
                  ?>
              >
                In Progress
              </option>

              <option
                  value="resolved"
                  <?= $ticketStatus === 'resolved'
                      ? 'selected'
                      : ''
                  ?>
              >
                Resolved
              </option>

              <option
                  value="closed"
                  <?= $ticketStatus === 'closed'
                      ? 'selected'
                      : ''
                  ?>
              >
                Closed
              </option>

            </select>


            <button
                type="submit"
                class="btn btn-primary btn-sm"
            >
              Update
            </button>

          </form>

        </div>

      <?php endforeach; ?>

    </div>

    <?php

    pageFooter();
    exit;
}


/*
|--------------------------------------------------------------------------
| CLEANUP
|--------------------------------------------------------------------------
*/

if ($action === 'cleanup') {

    if (
        $_SERVER['REQUEST_METHOD']
        === 'POST'
    ) {
        verifyCsrfToken();

        $days =
            (int)(
                $_POST[
                    'days'
                ]
                ?? 90
            );

        /*
         * Server-side enforcement rather than relying only
         * on the HTML min/max attributes.
         */
        $days =
            max(
                30,
                min(
                    365,
                    $days
                )
            );


        /*
         * Calculate cutoffs in PHP instead of inserting a bound
         * parameter into an INTERVAL expression.
         */
        $dateCutoff =
            date(
                'Y-m-d',
                time() -
                ($days * 86400)
            );

        $dateTimeCutoff =
            date(
                'Y-m-d H:i:s',
                time() -
                ($days * 86400)
            );


        db()->prepare(
            "DELETE FROM visitors
             WHERE visit_date < ?"
        )->execute([
            $dateCutoff
        ]);


        db()->prepare(
            "DELETE FROM service_providers
             WHERE end_date < ?"
        )->execute([
            $dateCutoff
        ]);


        db()->prepare(
            "DELETE FROM access_log
             WHERE created_at < ?"
        )->execute([
            $dateTimeCutoff
        ]);


        db()->prepare(
            "DELETE FROM notifications
             WHERE created_at < ?"
        )->execute([
            $dateTimeCutoff
        ]);


        setFlash(
            'success',
            'Cleanup complete. Records older than ' .
            $days .
            ' days were removed.'
        );


        header(
            'Location: admin.php?action=cleanup'
        );

        exit;
    }


    pageHeader(
        'Cleanup',
        'admin'
    );

    renderHeader(
        '🧹 Data Cleanup',
        'admin.php?action=menu'
    );
    ?>

    <div
        class="container"
        style="max-width:480px;"
    >

      <?= getFlash() ?>


      <div class="card">

        <div class="card-title">
          POPIA Data Purge
        </div>


        <p
            style="
              font-size:.88rem;
              color:#666;
              margin-bottom:16px;
            "
        >
          Removes expired records older than the
          selected period. This action is irreversible.
        </p>


        <form
            method="POST"
            onsubmit="return confirm('Permanently delete old records? This cannot be undone.');"
        >

          <?= csrfField() ?>


          <div class="form-group">

            <label>
              Delete records older than (days)
            </label>

            <input
                type="number"
                name="days"
                value="90"
                min="30"
                max="365"
                required
            >

          </div>


          <button
              type="submit"
              class="btn btn-danger btn-block"
          >
            Run Cleanup
          </button>

        </form>

      </div>

    </div>

    <?php

    pageFooter();
    exit;
}


/*
|--------------------------------------------------------------------------
| Unknown action
|--------------------------------------------------------------------------
*/

header(
    'Location: admin.php?action=menu'
);

exit;