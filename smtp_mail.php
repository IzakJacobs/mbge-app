<?php
/**
 * smtp_mail.php
 *
 * GEMB unified authenticated SMTP transport.
 */

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as MailerException;


function smtpSend(
    string $to,
    string $subject,
    string $html
): bool {
    $to = trim($to);

    if (!filter_var(
        $to,
        FILTER_VALIDATE_EMAIL
    )) {
        error_log(
            'smtpSend rejected invalid recipient'
        );

        return false;
    }

    $host = defined('SMTP_HOST')
        ? SMTP_HOST
        : '';

    $port = defined('SMTP_PORT')
        ? (int)SMTP_PORT
        : 587;

    $user = defined('SMTP_USER')
        ? SMTP_USER
        : '';

    $pass = defined('SMTP_PASS')
        ? SMTP_PASS
        : '';

    $from = defined('SMTP_FROM')
        ? SMTP_FROM
        : $user;

    $name = defined('SMTP_NAME')
        ? SMTP_NAME
        : 'GEMB Estate';


    if (
        $host === '' ||
        $user === '' ||
        $pass === ''
    ) {
        error_log(
            'smtpSend SMTP configuration incomplete'
        );

        return false;
    }

    if (!filter_var(
        $from,
        FILTER_VALIDATE_EMAIL
    )) {
        error_log(
            'smtpSend invalid configured sender'
        );

        return false;
    }


    /*
     * Load PHPMailer.
     */
    $dir = __DIR__ . '/phpmailer/';

    foreach (
        [
            'Exception.php',
            'PHPMailer.php',
            'SMTP.php',
        ] as $requiredFile
    ) {
        if (!is_file(
            $dir . $requiredFile
        )) {
            error_log(
                'smtpSend PHPMailer installation incomplete'
            );

            return false;
        }
    }

    require_once $dir . 'Exception.php';
    require_once $dir . 'PHPMailer.php';
    require_once $dir . 'SMTP.php';


    /*
     * Prevent CR/LF injection while retaining UTF-8.
     */
    $subject = str_replace(
        ["\r", "\n"],
        '',
        trim($subject)
    );

    if ($subject === '') {
        $subject = 'Estate Communication';
    }


    /*
     * Plain-text alternative.
     */
    $plain = str_replace(
        [
            '<br>',
            '<br/>',
            '<br />',
            '</p>',
            '</div>',
            '</h1>',
            '</h2>',
            '</h3>',
            '</li>',
        ],
        "\n",
        $html
    );

    $plain = html_entity_decode(
        strip_tags($plain),
        ENT_QUOTES | ENT_HTML5,
        'UTF-8'
    );

    $plain = preg_replace(
        '/[ \t]+/',
        ' ',
        $plain
    );

    $plain = preg_replace(
        '/\n{3,}/',
        "\n\n",
        trim($plain)
    );


    $mail = new PHPMailer(true);

    try {
        $mail->isSMTP();

        $mail->Host       = $host;
        $mail->Port       = $port;
        $mail->SMTPAuth   = true;
        $mail->Username   = $user;
        $mail->Password   = $pass;

        $mail->CharSet    = 'UTF-8';
        $mail->Timeout    = 15;

        /*
         * Do not disable TLS peer verification.
         */
        if ($port === 465) {
            $mail->SMTPSecure =
                PHPMailer::ENCRYPTION_SMTPS;
        } else {
            $mail->SMTPSecure =
                PHPMailer::ENCRYPTION_STARTTLS;
        }

        $mail->setFrom(
            $from,
            str_replace(
                ["\r", "\n"],
                '',
                $name
            )
        );

        $mail->addAddress($to);

        $mail->isHTML(true);

        $mail->Subject = $subject;
        $mail->Body    = $html;
        $mail->AltBody = $plain;

        $mail->send();

        return true;

    } catch (MailerException $e) {

    error_log(
        'smtpSend authenticated SMTP transmission failed'
    );

    return false;
}
}