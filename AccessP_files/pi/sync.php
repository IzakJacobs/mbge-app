<?php
/**
 * pi/sync.php — Raspberry Pi sync cron script
 *
 * Run every 5 minutes via cron:
 *   * /5 * * * * php /var/www/html/gemb/sync.php >> /var/log/gemb_sync.log 2>&1
 *
 * Does two things:
 *   1. PUSH  — sends any offline-logged events to the cloud
 *   2. PULL  — fetches fresh visitors/SPs/residents/vehicles/guards from cloud
 */
require_once __DIR__ . '/config.php';

$log = [];
$ts  = date('Y-m-d H:i:s');

function syncLog(string $msg): void {
    global $log, $ts;
    $line = "[{$ts}] {$msg}";
    $log[] = $line;
    echo $line . PHP_EOL;
}

// ── Connectivity check ────────────────────────────────────
function cloudReachable(): bool {
    $ch = curl_init(PI_CLOUD_URL . '?action=pull');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 8,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_HTTPHEADER     => ['Authorization: Bearer ' . PI_SYNC_KEY],
    ]);
    curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return $code > 0; // any HTTP response means cloud is reachable
}

if (!cloudReachable()) {
    syncLog('Cloud unreachable — skipping sync (Pi is in offline mode)');
    exit(0);
}

$db = piDb();

// ════════════════════════════════════════════════════════
// STEP 1 — PUSH offline events to cloud
// ════════════════════════════════════════════════════════
$unpushed = $db->query(
    "SELECT * FROM pi_access_log WHERE pushed = 0 ORDER BY created_at LIMIT 500"
)->fetchAll();

if ($unpushed) {
    $ch = curl_init(PI_CLOUD_URL . '?action=push');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode(['events' => $unpushed]),
        CURLOPT_HTTPHEADER     => [
            'Authorization: Bearer ' . PI_SYNC_KEY,
            'Content-Type: application/json',
        ],
        CURLOPT_TIMEOUT        => 30,
    ]);
    $resp = curl_exec($ch);
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($http === 200) {
        $result  = json_decode($resp, true);
        $pushed  = $result['pushed'] ?? 0;
        $ids     = array_column($unpushed, 'event_id');
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $db->prepare(
            "UPDATE pi_access_log SET pushed = 1 WHERE event_id IN ({$placeholders})"
        )->execute($ids);
        syncLog("Pushed {$pushed}/" . count($unpushed) . " offline events to cloud");
    } else {
        syncLog("Push failed — HTTP {$http}: {$resp}");
    }
} else {
    syncLog('No offline events to push');
}

// ════════════════════════════════════════════════════════
// STEP 2 — PULL fresh data from cloud
// ════════════════════════════════════════════════════════
$ch = curl_init(PI_CLOUD_URL . '?action=pull');
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER     => ['Authorization: Bearer ' . PI_SYNC_KEY],
    CURLOPT_TIMEOUT        => 30,
]);
$resp = curl_exec($ch);
$http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$err  = curl_error($ch);
curl_close($ch);

if ($http !== 200) {
    syncLog("Pull failed — HTTP {$http} {$err}");
    exit(1);
}

$data = json_decode($resp, true);
if (!$data || !isset($data['visitors'])) {
    syncLog('Pull returned invalid JSON');
    exit(1);
}

// ── Replace each table atomically ─────────────────────────
$db->beginTransaction();
try {

    // Visitors
    $db->exec("DELETE FROM visitors");
    $ins = $db->prepare("
        INSERT INTO visitors
          (id, code, visitor_name, resident_name, resident_erfno,
           plate, visit_date, visit_date_to, status, expired)
        VALUES (?,?,?,?,?, ?,?,?,?,?)
    ");
    foreach ($data['visitors'] as $v) {
        $ins->execute([
            $v['id'], $v['code'], $v['visitor_name'], $v['resident_name'],
            $v['resident_erfno'], $v['plate'] ?? null,
            $v['visit_date'], $v['visit_date_to'] ?? null,
            $v['status'] ?? 'active', (int)($v['expired'] ?? 0),
        ]);
    }
    syncLog(count($data['visitors']) . ' visitors loaded');

    // Service providers
    $db->exec("DELETE FROM service_providers");
    $ins = $db->prepare("
        INSERT INTO service_providers
          (id, unique_code, service_name, company_name, resident_erfno, resident_name,
           start_date, end_date, approved, expired, access_days, access_start, access_end)
        VALUES (?,?,?,?,?,?, ?,?,?,?,?,?,?)
    ");
    foreach ($data['service_providers'] as $sp) {
        $ins->execute([
            $sp['id'], $sp['unique_code'], $sp['service_name'], $sp['company_name'] ?? null,
            $sp['resident_erfno'] ?? null, $sp['resident_name'] ?? null,
            $sp['start_date'], $sp['end_date'],
            $sp['approved'] ?? '1', (int)($sp['expired'] ?? 0),
            $sp['access_days'] ?? null,
            $sp['access_start'] ?? '07:00:00',
            $sp['access_end']   ?? '17:00:00',
        ]);
    }
    syncLog(count($data['service_providers']) . ' service providers loaded');

    // Residents
    $db->exec("DELETE FROM residents");
    $ins = $db->prepare("
        INSERT INTO residents (id, resident_erfno, resident_name, email, is_primary)
        VALUES (?,?,?,?,?)
    ");
    foreach ($data['residents'] as $r) {
        $ins->execute([
            $r['id'], $r['resident_erfno'], $r['resident_name'],
            $r['email'] ?? null, (int)($r['is_primary'] ?? 0),
        ]);
    }
    syncLog(count($data['residents']) . ' residents loaded');

    // Vehicles
    $db->exec("DELETE FROM resident_vehicles");
    $ins = $db->prepare("
        INSERT INTO resident_vehicles (id, resident_id, plate, resident_name, resident_erfno, address)
        VALUES (?,?,?,?,?,?)
    ");
    foreach ($data['vehicles'] as $v) {
        $ins->execute([
            $v['id'], $v['resident_id'], strtoupper($v['plate']),
            $v['resident_name'], $v['resident_erfno'], $v['address'] ?? null,
        ]);
    }
    syncLog(count($data['vehicles']) . ' vehicles loaded');

    // Guards
    // NOTE: requires the Pi's local guards table to have totp_secret
    // (TEXT, nullable) and totp_confirmed (INTEGER, default 0) columns —
    // run once on the Pi if not already present:
    //   ALTER TABLE guards ADD COLUMN totp_secret TEXT;
    //   ALTER TABLE guards ADD COLUMN totp_confirmed INTEGER NOT NULL DEFAULT 0;
    $db->exec("DELETE FROM guards");
    $ins = $db->prepare("
        INSERT INTO guards (id, username, password, full_name, phone, assigned_gate, gate_point, totp_secret, totp_confirmed)
        VALUES (?,?,?,?,?,?,?,?,?)
    ");
    foreach ($data['guards'] as $g) {
        $ins->execute([
            $g['id'], $g['username'], $g['password'], $g['full_name'],
            $g['phone'] ?? null,
            $g['assigned_gate'] ?? 'Any', $g['gate_point'] ?? null,
            $g['totp_secret'] ?? null, (int)($g['totp_confirmed'] ?? 0),
        ]);
    }
    syncLog(count($data['guards']) . ' guards loaded');

    // Record sync time
    $db->prepare(
        "INSERT OR REPLACE INTO pi_state (key, value) VALUES ('last_sync', ?)"
    )->execute([date('c')]);

    $db->commit();
    syncLog('Sync complete — ' . $data['sync_time']);

} catch (Exception $e) {
    $db->rollBack();
    syncLog('Sync FAILED (rolled back): ' . $e->getMessage());
    exit(1);
}
