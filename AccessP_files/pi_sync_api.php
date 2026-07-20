<?php
/**
 * pi_sync_api.php — Raspberry Pi sync endpoint (cloud side)
 *
 * GET  ?action=pull  → JSON payload of active passes, residents, vehicles, guards
 * POST ?action=push  → accepts offline access_log events buffered on the Pi
 *
 * Auth: Authorization: Bearer <PI_SYNC_KEY>  (set in config.php)
 */
require_once __DIR__ . '/config.php';
date_default_timezone_set('Africa/Johannesburg');
header('Content-Type: application/json');

// ── Auth ──────────────────────────────────────────────────
$provided = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if (!defined('PI_SYNC_KEY')
    || PI_SYNC_KEY === ''
    || PI_SYNC_KEY === 'CHANGE_ME_GENERATE_WITH_PHP_RANDOM_BYTES'
    || !hash_equals('Bearer ' . PI_SYNC_KEY, $provided)) {
    http_response_code(401);
    exit(json_encode(['error' => 'Unauthorized']));
}

$action = strtolower($_GET['action'] ?? 'pull');

// ════════════════════════════════════════════════════════
// PULL  — Pi fetches this to refresh its local database
// ════════════════════════════════════════════════════════
if ($action === 'pull') {
  try {

    // Active visitor passes: current + up to 7 days ahead
    $visitors = db()->query("
        SELECT id, code, visitor_name, resident_name, resident_erfno,
               plate, visit_date, visit_date_to, status, expired
        FROM   visitors
        WHERE  status = 'active'
          AND  expired = 0
          AND  COALESCE(visit_date_to, visit_date) >= CURDATE()
          AND  visit_date <= DATE_ADD(CURDATE(), INTERVAL 7 DAY)
    ")->fetchAll();

    // Approved, non-expired service provider permits
    $sps = db()->query("
        SELECT id, unique_code, service_name, company_name,
               resident_erfno, resident_name, start_date, end_date,
               approved, expired, access_days, access_start, access_end
        FROM   service_providers
        WHERE  (approved = 'true' OR approved = 1)
          AND  expired = 0
          AND  end_date >= CURDATE()
    ")->fetchAll();

    // Active residents — erfno + email only (minimal PII)
    $residents = db()->query("
        SELECT id, resident_erfno, resident_name, email, is_primary
        FROM   residents
        WHERE  status = 'active'
    ")->fetchAll();

    // Active resident vehicles (for LPR/plate lookups)
    $vehicles = db()->query("
        SELECT rv.id, rv.resident_id, rv.plate,
               r.resident_name, r.resident_erfno, r.address
        FROM   resident_vehicles rv
        JOIN   residents r ON r.id = rv.resident_id
        WHERE  rv.active = 1 AND r.status = 'active'
    ")->fetchAll();

    // Guards — column names: name, pin, gate (not full_name/password/assigned_gate)
    // totp_secret/totp_confirmed only sync down once a guard has completed
    // enrolment via the cloud login (guard.php) — the Pi never generates
    // its own secret, see totp_lib.php's header comment.
    $guards = db()->query("
        SELECT id, username, pin AS password, name AS full_name,
               gate AS assigned_gate, gate_point, phone,
               totp_secret, totp_confirmed
        FROM   guards
    ")->fetchAll();

    echo json_encode([
        'sync_time'         => date('c'),
        'visitors'          => $visitors,
        'service_providers' => $sps,
        'residents'         => $residents,
        'vehicles'          => $vehicles,
        'guards'            => $guards,
    ]);

  } catch (Exception $e) {
      http_response_code(500);
      echo json_encode(['error' => 'pull_failed', 'detail' => $e->getMessage()]);
  }

// ════════════════════════════════════════════════════════
// PUSH  — Pi uploads events logged while offline
// ════════════════════════════════════════════════════════
} elseif ($action === 'push' && $_SERVER['REQUEST_METHOD'] === 'POST') {

    $body   = json_decode(file_get_contents('php://input'), true) ?? [];
    $events = is_array($body['events'] ?? null) ? $body['events'] : [];
    $ok     = 0;
    $errors = [];

    foreach ($events as $i => $ev) {
        // Sanitise each field — never trust Pi-originated data
        $eventId   = preg_replace('/[^A-Z0-9\-]/', '', strtoupper($ev['event_id']   ?? ''));
        $gate      = in_array($ev['gate'] ?? '', ['SSgate','CSgate','Unknown'], true)
                     ? $ev['gate'] : 'Unknown';
        $gatePoint = preg_replace('/[^A-Z0-9_]/', '', strtoupper($ev['gate_point']  ?? ''));
        $direction = in_array($ev['direction'] ?? '', ['ENTRY','EXIT'], true)
                     ? $ev['direction'] : 'ENTRY';
        $entryType = in_array($ev['entry_type'] ?? '', ['resident','visitor','service_provider','unknown'], true)
                     ? $ev['entry_type'] : 'unknown';
        $personName = mb_substr(strip_tags($ev['person_name'] ?? ''), 0, 100);
        $plate      = preg_replace('/[^A-Z0-9 ]/', '', strtoupper($ev['plate']      ?? ''));
        $qrCode     = preg_replace('/[^A-Z0-9\-]/', '', strtoupper($ev['qr_code']   ?? ''));
        $guardId    = filter_var($ev['guard_id'] ?? null, FILTER_VALIDATE_INT) ?: null;
        $granted    = isset($ev['granted']) ? (int)(bool)$ev['granted'] : 1;
        $denyReason = mb_substr(strip_tags($ev['deny_reason'] ?? ''), 0, 150);
        $createdAt  = preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $ev['created_at'] ?? '')
                      ? $ev['created_at'] : date('Y-m-d H:i:s');

        if (!$eventId) {
            $eventId = 'PI-' . strtoupper(substr(md5(uniqid('', true)), 0, 10));
        }

        try {
            db()->prepare("
                INSERT IGNORE INTO access_log
                  (event_id, gate, gate_point, direction, entry_type,
                   person_name, plate, qr_code, guard_id, granted,
                   deny_reason, notes, created_at)
                VALUES (?,?,?,?,?, ?,?,?,?,?, ?,?,?)
            ")->execute([
                $eventId, $gate, $gatePoint ?: null, $direction, $entryType,
                $personName ?: null, $plate ?: null, $qrCode ?: null,
                $guardId, $granted,
                $denyReason ?: null, '[PI-OFFLINE]', $createdAt,
            ]);
            $ok++;
        } catch (Exception $e) {
            $errors[] = "row {$i}: " . $e->getMessage();
            error_log('GEMB pi_sync push error: ' . $e->getMessage());
        }
    }

    echo json_encode(['pushed' => $ok, 'errors' => $errors]);

} else {
    http_response_code(400);
    echo json_encode(['error' => 'Unknown action']);
}
