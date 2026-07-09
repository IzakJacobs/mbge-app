<?php
// ============================================================
// admin_votes.php — Voting Engine Module (Admin only)
// GEMB Access Control System
// Version 2.0  |  2026-06-14
//
// Motions now live inside a Meeting (voting register), e.g.
// "AGM November 2026". Every action here is scoped to a
// meeting via ?meeting_id=, and motions are numbered
// sequentially (1, 2, 3...) within that meeting.
//
// Actions:
//   list      — view all motions for a meeting (default)
//   create    — new motion form (within a meeting)
//   edit      — edit draft motion
//   open      — draft → open (voting begins)
//   close     — open → closed (computes and writes result)
//   delete    — delete draft motion only
//   proxies   — register / view proxy votes for a motion
//   capture   — admin captures manual or proxy vote per erf
//   results   — full result display + CSV download
//   csv       — download results CSV
//
// Security:
//   requireAdmin() at chokepoint
//   verifyCsrfToken() on every POST
//   PDO prepared statements throughout
//   htmlspecialchars() on all output
//   Status transitions validated server-side
//   One-vote-per-erf enforced at DB level (unique key)
// ============================================================

require_once 'layout.php';
if (session_status() === PHP_SESSION_NONE) session_start();

requireAdmin();

$action    = $_GET['action']     ?? 'list';
$motionId  = (int)($_GET['id']         ?? 0);
$meetingId = (int)($_GET['meeting_id'] ?? 0);
$adminId   = (int)($_SESSION['admin_id'] ?? 0);

// Resolution type labels and thresholds
const RESOLUTION_TYPES = [
    'ordinary' => ['label' => 'Ordinary Resolution', 'threshold' => 50.01],
    'material' => ['label' => 'Material Resolution',  'threshold' => 60.00],
    'moi'      => ['label' => 'MOI / Condonation',    'threshold' => 75.00],
];

// ── Helper: load a meeting or redirect ────────────────────
function loadMeeting(int $id): array {
    $stmt = db()->prepare("SELECT * FROM meetings WHERE id = ?");
    $stmt->execute([$id]);
    $m = $stmt->fetch();
    if (!$m) {
        setFlash('error', 'Meeting not found.');
        header('Location: admin_meetings.php?action=list'); exit;
    }
    return $m;
}

// ── Helper: load a motion or redirect ─────────────────────
function loadMotion(int $id): array {
    $stmt = db()->prepare("SELECT * FROM motions WHERE id = ?");
    $stmt->execute([$id]);
    $m = $stmt->fetch();
    if (!$m) {
        setFlash('error', 'Motion not found.');
        header('Location: admin_meetings.php?action=list'); exit;
    }
    return $m;
}

// ── Helper: compute live vote counts for a motion ─────────
function voteCounts(int $motionId): array {
    $stmt = db()->prepare(
        "SELECT
           SUM(vc.capture_method = 'online')  AS online,
           SUM(vc.capture_method = 'manual')  AS manual,
           SUM(vc.capture_method = 'proxy')   AS proxy,
           SUM(vt.vote_option = 'for')        AS cnt_for,
           SUM(vt.vote_option = 'against')    AS cnt_against,
           SUM(vt.vote_option = 'abstain')    AS cnt_abstain,
           SUM(vt.vote_option = 'noshow')     AS cnt_noshow,
           SUM(vt.is_blank = 1)               AS cnt_blank,
           COUNT(vc.id)                        AS total_voted
         FROM vote_cast vc
         JOIN vote_tally vt ON vt.cast_id = vc.id
         WHERE vc.motion_id = ?"
    );
    $stmt->execute([$motionId]);
    $r = $stmt->fetch();

    $online   = (int)$r['online'];
    $manual   = (int)$r['manual'];
    $proxy    = (int)$r['proxy'];
    $for      = (int)$r['cnt_for'];
    $against  = (int)$r['cnt_against'];
    $abstain  = (int)$r['cnt_abstain'];
    $noshow   = (int)$r['cnt_noshow'];
    $blank    = (int)$r['cnt_blank'];
    $total    = (int)$r['total_voted'];

    $physical       = $online + $manual;
    $forAgainst     = $for + $against;
    $resultPct      = $forAgainst > 0 ? round($for / $forAgainst * 100, 2) : 0;

    return compact('online','manual','proxy','for','against',
                   'abstain','noshow','blank','total',
                   'physical','forAgainst','resultPct');
}

// ── Helper: check quorum ───────────────────────────────────
function checkQuorum(array $counts, array $motion): array {
    $physicalOk = $counts['physical'] >= (int)$motion['quorum_physical'];
    $totalOk    = $counts['total']    >= (int)$motion['quorum_total'];
    $met        = $physicalOk && $totalOk;
    return [
        'met'        => $met,
        'physicalOk' => $physicalOk,
        'totalOk'    => $totalOk,
    ];
}

// ============================================================
// LIST — motions for a single meeting
// ============================================================
if ($action === 'list') {

    if ($meetingId <= 0) {
        header('Location: admin_meetings.php?action=list'); exit;
    }

    $meeting = loadMeeting($meetingId);

    $stmt = db()->prepare(
        "SELECT m.*,
                (SELECT COUNT(*) FROM vote_cast vc WHERE vc.motion_id = m.id) AS votes_cast,
                (SELECT COUNT(*) FROM vote_proxy vp WHERE vp.motion_id = m.id) AS proxies
         FROM motions m
         WHERE m.meeting_id = ?
         ORDER BY m.motion_number ASC"
    );
    $stmt->execute([$meetingId]);
    $motions = $stmt->fetchAll();

    $meetingStatusClass = match($meeting['status']) {
        'open'   => 'badge-green',
        'closed' => 'badge-grey',
        default  => 'badge-amber',
    };

    pageHeader('Voting — Motions', 'admin');
    renderHeader('🗳️ Voting', 'logout.php');
    ?>

    <main class="pc-main">
      <div class="card card-wide">
        <div class="card-toolbar">
          <div>
            <h2 class="card-title">🗳️ <?= htmlspecialchars($meeting['title']) ?></h2>
            <p style="margin-top:4px;">
              <span class="badge <?= $meetingStatusClass ?>"><?= ucfirst($meeting['status']) ?></span>
              <?php if ($meeting['meeting_date']): ?>
                &nbsp;<span class="muted-note"><?= date('d M Y', strtotime($meeting['meeting_date'])) ?></span>
              <?php endif; ?>
            </p>
          </div>
          <?php if ($meeting['status'] !== 'closed'): ?>
            <a href="admin_votes.php?action=create&meeting_id=<?= $meetingId ?>" class="btn btn-primary">＋ New Motion</a>
          <?php endif; ?>
        </div>

        <?= getFlash() ?>

        <?php if (empty($motions)): ?>
          <p class="muted-note">No motions yet for this meeting.
             <?php if ($meeting['status'] !== 'closed'): ?>Click <strong>New Motion</strong> to add agenda items requiring a vote.<?php endif; ?>
          </p>
        <?php else: ?>
        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Motion</th>
                <th>Status</th>
                <th>Proxies</th>
                <th>Votes Cast</th>
                <th>Opens</th>
                <th>Closes</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
            <?php foreach ($motions as $m): ?>
              <?php
                $statusClass = match($m['status']) {
                    'open'   => 'badge-green',
                    'closed' => 'badge-grey',
                    default  => 'badge-amber',
                };
              ?>
              <tr>
                <td><?= (int)$m['motion_number'] ?></td>
                <td><strong><?= htmlspecialchars($m['title']) ?></strong></td>
                <td><span class="badge <?= $statusClass ?>"><?= ucfirst($m['status']) ?></span></td>
                <td class="text-center"><?= (int)$m['proxies'] ?></td>
                <td class="text-center"><?= (int)$m['votes_cast'] ?></td>
                <td><?= $m['opens_at']  ? date('d M Y H:i', strtotime($m['opens_at']))  : '<span class="muted-note">Immediate</span>' ?></td>
                <td><?= $m['closes_at'] ? date('d M Y H:i', strtotime($m['closes_at'])) : '<span class="muted-note">No auto-close</span>' ?></td>
                <td>
                  <div class="btn-group-sm">

                    <?php if ($m['status'] === 'draft'): ?>
                      <a href="admin_votes.php?action=edit&id=<?= $m['id'] ?>&meeting_id=<?= $meetingId ?>" class="btn btn-sm btn-amber">⚙️ Edit</a>
                      <?php if ($meeting['status'] !== 'closed'): ?>
                      <form method="POST" action="admin_votes.php?action=open&id=<?= $m['id'] ?>&meeting_id=<?= $meetingId ?>" style="display:inline;">
                        <?= csrfField() ?>
                        <button type="submit" class="btn btn-sm btn-green"
                                onclick="return confirm('Open this motion for voting? Residents will be able to cast votes immediately.')">
                          ▶ Open
                        </button>
                      </form>
                      <?php endif; ?>
                      <form method="POST" action="admin_votes.php?action=delete&id=<?= $m['id'] ?>&meeting_id=<?= $meetingId ?>" style="display:inline;">
                        <?= csrfField() ?>
                        <button type="submit" class="btn btn-sm btn-red"
                                onclick="return confirm('Delete this motion permanently?')">
                          🗑 Delete
                        </button>
                      </form>
                    <?php endif; ?>

                    <?php if ($m['status'] === 'open'): ?>
                      <a href="admin_votes.php?action=proxies&id=<?= $m['id'] ?>&meeting_id=<?= $meetingId ?>" class="btn btn-sm btn-navy">📋 Proxies</a>
                      <a href="admin_votes.php?action=capture&id=<?= $m['id'] ?>&meeting_id=<?= $meetingId ?>" class="btn btn-sm btn-blue">✏️ Capture Vote</a>
                      <a href="admin_votes.php?action=results&id=<?= $m['id'] ?>&meeting_id=<?= $meetingId ?>" class="btn btn-sm btn-blue">📊 Live</a>
                      <form method="POST" action="admin_votes.php?action=close&id=<?= $m['id'] ?>&meeting_id=<?= $meetingId ?>" style="display:inline;">
                        <?= csrfField() ?>
                        <button type="submit" class="btn btn-sm btn-red"
                                onclick="return confirm('Close voting and compute the final result? This cannot be undone.')">
                          ⏹ Close
                        </button>
                      </form>
                    <?php endif; ?>

                    <?php if ($m['status'] === 'closed'): ?>
                      <a href="admin_votes.php?action=results&id=<?= $m['id'] ?>&meeting_id=<?= $meetingId ?>" class="btn btn-sm btn-blue">📊 Results</a>
                      <a href="admin_votes.php?action=csv&id=<?= $m['id'] ?>&meeting_id=<?= $meetingId ?>" class="btn btn-sm btn-green">⬇ CSV</a>
                    <?php endif; ?>

                  </div>
                </td>
              </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </div>
        <?php endif; ?>

        <div class="btn-group" style="margin-top:20px;">
          <a href="admin_meetings.php?action=list" class="btn btn-navy">← Back to Meetings</a>
        </div>
      </div>
    </main>

    <?php pageFooter(); exit;
}

// ============================================================
// CREATE — new motion within a meeting
// ============================================================
if ($action === 'create') {

    if ($meetingId <= 0) {
        header('Location: admin_meetings.php?action=list'); exit;
    }

    $meeting = loadMeeting($meetingId);
    if ($meeting['status'] === 'closed') {
        setFlash('error', 'This meeting is closed. Motions cannot be added.');
        header("Location: admin_votes.php?action=list&meeting_id={$meetingId}"); exit;
    }

    $errors = [];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $title   = trim($_POST['title']           ?? '');
        $desc    = trim($_POST['description']      ?? '');
        $type    = trim($_POST['resolution_type']  ?? '');
        $opens   = trim($_POST['opens_at']         ?? '');
        $closes  = trim($_POST['closes_at']        ?? '');
        $erven   = (int)($_POST['total_erven']     ?? 394);
        $qPhys   = (int)($_POST['quorum_physical'] ?? 50);
        $qTotal  = (int)($_POST['quorum_total']    ?? 80);

        if ($title === '')                         $errors[] = 'Motion title is required.';
        if (!array_key_exists($type, RESOLUTION_TYPES)) $errors[] = 'Select a valid resolution type.';
        if ($qPhys < 1)                            $errors[] = 'Physical quorum must be at least 1.';
        if ($qTotal < $qPhys)                      $errors[] = 'Total quorum must be ≥ physical quorum.';
        if ($closes !== '' && $opens !== '' && $closes <= $opens) $errors[] = 'Close time must be after open time.';

        if (empty($errors)) {
            // Next sequential motion number within this meeting
            $numStmt = db()->prepare("SELECT COALESCE(MAX(motion_number), 0) + 1 FROM motions WHERE meeting_id=?");
            $numStmt->execute([$meetingId]);
            $nextNumber = (int)$numStmt->fetchColumn();

            db()->prepare(
                "INSERT INTO motions
                 (meeting_id, motion_number, title, description, resolution_type, status, created_by,
                  opens_at, closes_at, total_erven, quorum_physical, quorum_total)
                 VALUES (?,?,?,?,?,'draft',?,?,?,?,?,?)"
            )->execute([
                $meetingId, $nextNumber,
                $title, $desc ?: null, $type, $adminId,
                $opens ?: null, $closes ?: null,
                $erven, $qPhys, $qTotal,
            ]);
            setFlash('success', "Motion {$nextNumber} created as draft. Review and open when ready.");
            header("Location: admin_votes.php?action=list&meeting_id={$meetingId}"); exit;
        }
    }

    // Preview of the motion number this will become
    $numStmt = db()->prepare("SELECT COALESCE(MAX(motion_number), 0) + 1 FROM motions WHERE meeting_id=?");
    $numStmt->execute([$meetingId]);
    $previewNumber = (int)$numStmt->fetchColumn();

    pageHeader('New Motion', 'admin');
    renderHeader('🗳️ New Motion', 'logout.php');
    ?>

    <main class="pc-main">
      <div class="card card-wide">
        <h2 class="card-title">🗳️ Create Motion <span class="muted-note">— <?= htmlspecialchars($meeting['title']) ?>, Motion <?= $previewNumber ?></span></h2>

        <?php if (!empty($errors)): ?>
          <div class="alert alert-danger">
            <?php foreach ($errors as $e): ?><p><?= htmlspecialchars($e) ?></p><?php endforeach; ?>
          </div>
        <?php endif; ?>

        <form method="POST">
          <?= csrfField() ?>

          <div class="form-group">
            <label>Motion Title <span class="required">*</span></label>
            <input type="text" name="title" maxlength="255" required
                   value="<?= htmlspecialchars($_POST['title'] ?? '') ?>">
          </div>

          <div class="form-group">
            <label>Description / Background <span class="muted-note">(optional)</span></label>
            <textarea name="description" rows="4" maxlength="2000"
                      placeholder="Provide context for voters..."><?= htmlspecialchars($_POST['description'] ?? '') ?></textarea>
          </div>

          <div class="form-group">
            <label>Resolution Type <span class="required">*</span></label>
            <select name="resolution_type" required>
              <option value="">— Select —</option>
              <?php foreach (RESOLUTION_TYPES as $val => $rt): ?>
                <option value="<?= $val ?>" <?= ($_POST['resolution_type'] ?? '') === $val ? 'selected' : '' ?>>
                  <?= $rt['label'] ?> (<?= $rt['threshold'] ?>% required)
                </option>
              <?php endforeach; ?>
            </select>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label>Opens At <span class="muted-note">(blank = open immediately when activated)</span></label>
              <input type="datetime-local" name="opens_at" value="<?= htmlspecialchars($_POST['opens_at'] ?? '') ?>">
            </div>
            <div class="form-group">
              <label>Closes At <span class="muted-note">(blank = admin closes manually)</span></label>
              <input type="datetime-local" name="closes_at" value="<?= htmlspecialchars($_POST['closes_at'] ?? '') ?>">
            </div>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label>Total Eligible Erven</label>
              <input type="number" name="total_erven" min="1" max="9999"
                     value="<?= (int)($_POST['total_erven'] ?? 394) ?>">
              <small class="muted-note">Default 394 — change only if membership has changed.</small>
            </div>
          </div>

          <div style="background:#f8f9fa;border-radius:8px;padding:14px 16px;margin-bottom:16px;">
            <strong style="font-size:.9rem;">Quorum Settings</strong>
            <p class="muted-note" style="margin:4px 0 10px;">
              Both conditions must be met: physical present ≥ minimum AND total (physical+proxy) ≥ minimum.
            </p>
            <div class="form-row">
              <div class="form-group">
                <label>Minimum Physical Present (online + manual)</label>
                <input type="number" name="quorum_physical" min="1" max="394"
                       value="<?= (int)($_POST['quorum_physical'] ?? 50) ?>">
              </div>
              <div class="form-group">
                <label>Minimum Total (physical + proxy)</label>
                <input type="number" name="quorum_total" min="1" max="394"
                       value="<?= (int)($_POST['quorum_total'] ?? 80) ?>">
              </div>
            </div>
          </div>

          <div class="btn-group">
            <button type="submit" class="btn btn-primary">Create Motion →</button>
            <a href="admin_votes.php?action=list&meeting_id=<?= $meetingId ?>" class="btn btn-navy">Cancel</a>
          </div>
        </form>
      </div>
    </main>

    <?php pageFooter(); exit;
}

// ============================================================
// EDIT — draft only
// ============================================================
if ($action === 'edit' && $motionId > 0) {

    $motion    = loadMotion($motionId);
    $meetingId = (int)$motion['meeting_id'];

    if ($motion['status'] !== 'draft') {
        setFlash('error', 'Only draft motions can be edited.');
        header("Location: admin_votes.php?action=list&meeting_id={$meetingId}"); exit;
    }

    $errors = [];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $title   = trim($_POST['title']           ?? '');
        $desc    = trim($_POST['description']      ?? '');
        $type    = trim($_POST['resolution_type']  ?? '');
        $opens   = trim($_POST['opens_at']         ?? '');
        $closes  = trim($_POST['closes_at']        ?? '');
        $erven   = (int)($_POST['total_erven']     ?? 394);
        $qPhys   = (int)($_POST['quorum_physical'] ?? 50);
        $qTotal  = (int)($_POST['quorum_total']    ?? 80);

        if ($title === '')                              $errors[] = 'Motion title is required.';
        if (!array_key_exists($type, RESOLUTION_TYPES)) $errors[] = 'Select a valid resolution type.';
        if ($qPhys < 1)                                 $errors[] = 'Physical quorum must be at least 1.';
        if ($qTotal < $qPhys)                           $errors[] = 'Total quorum must be ≥ physical quorum.';

        if (empty($errors)) {
            db()->prepare(
                "UPDATE motions SET title=?, description=?, resolution_type=?,
                 opens_at=?, closes_at=?, total_erven=?, quorum_physical=?, quorum_total=?
                 WHERE id=? AND status='draft'"
            )->execute([
                $title, $desc ?: null, $type,
                $opens ?: null, $closes ?: null,
                $erven, $qPhys, $qTotal, $motionId,
            ]);
            setFlash('success', 'Motion updated.');
            header("Location: admin_votes.php?action=list&meeting_id={$meetingId}"); exit;
        }

        $motion['title']           = $title;
        $motion['description']     = $desc;
        $motion['resolution_type'] = $type;
        $motion['opens_at']        = $opens;
        $motion['closes_at']       = $closes;
        $motion['total_erven']     = $erven;
        $motion['quorum_physical'] = $qPhys;
        $motion['quorum_total']    = $qTotal;
    }

    $opensVal  = $motion['opens_at']  ? date('Y-m-d\TH:i', strtotime($motion['opens_at']))  : '';
    $closesVal = $motion['closes_at'] ? date('Y-m-d\TH:i', strtotime($motion['closes_at'])) : '';

    pageHeader('Edit Motion', 'admin');
    renderHeader('🗳️ Edit Motion', 'logout.php');
    ?>

    <main class="pc-main">
      <div class="card card-wide">
        <h2 class="card-title">⚙️ Edit Motion <span class="muted-note">— Motion <?= (int)$motion['motion_number'] ?></span></h2>

        <?php if (!empty($errors)): ?>
          <div class="alert alert-danger">
            <?php foreach ($errors as $e): ?><p><?= htmlspecialchars($e) ?></p><?php endforeach; ?>
          </div>
        <?php endif; ?>

        <form method="POST">
          <?= csrfField() ?>
          <div class="form-group">
            <label>Motion Title <span class="required">*</span></label>
            <input type="text" name="title" maxlength="255" required value="<?= htmlspecialchars($motion['title']) ?>">
          </div>
          <div class="form-group">
            <label>Description / Background</label>
            <textarea name="description" rows="4" maxlength="2000"><?= htmlspecialchars($motion['description'] ?? '') ?></textarea>
          </div>
          <div class="form-group">
            <label>Resolution Type <span class="required">*</span></label>
            <select name="resolution_type" required>
              <?php foreach (RESOLUTION_TYPES as $val => $rt): ?>
                <option value="<?= $val ?>" <?= $motion['resolution_type'] === $val ? 'selected' : '' ?>>
                  <?= $rt['label'] ?> (<?= $rt['threshold'] ?>% required)
                </option>
              <?php endforeach; ?>
            </select>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>Opens At</label>
              <input type="datetime-local" name="opens_at" value="<?= htmlspecialchars($opensVal) ?>">
            </div>
            <div class="form-group">
              <label>Closes At</label>
              <input type="datetime-local" name="closes_at" value="<?= htmlspecialchars($closesVal) ?>">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>Total Eligible Erven</label>
              <input type="number" name="total_erven" min="1" max="9999" value="<?= (int)$motion['total_erven'] ?>">
            </div>
          </div>
          <div style="background:#f8f9fa;border-radius:8px;padding:14px 16px;margin-bottom:16px;">
            <strong style="font-size:.9rem;">Quorum Settings</strong>
            <div class="form-row" style="margin-top:10px;">
              <div class="form-group">
                <label>Minimum Physical Present</label>
                <input type="number" name="quorum_physical" min="1" max="394" value="<?= (int)$motion['quorum_physical'] ?>">
              </div>
              <div class="form-group">
                <label>Minimum Total (physical + proxy)</label>
                <input type="number" name="quorum_total" min="1" max="394" value="<?= (int)$motion['quorum_total'] ?>">
              </div>
            </div>
          </div>
          <div class="btn-group">
            <button type="submit" class="btn btn-primary">Save Changes</button>
            <a href="admin_votes.php?action=list&meeting_id=<?= $meetingId ?>" class="btn btn-navy">← Back</a>
          </div>
        </form>
      </div>
    </main>

    <?php pageFooter(); exit;
}

// ============================================================
// OPEN — draft → open
// ============================================================
if ($action === 'open' && $motionId > 0) {
    $motion    = loadMotion($motionId);
    $meetingId = (int)$motion['meeting_id'];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        if ($motion['status'] !== 'draft') {
            setFlash('error', 'Only draft motions can be opened.');
        } else {
            db()->prepare("UPDATE motions SET status='open', updated_at=NOW() WHERE id=? AND status='draft'")
               ->execute([$motionId]);
            setFlash('success', 'Motion is now open for voting.');
        }
    }
    header("Location: admin_votes.php?action=list&meeting_id={$meetingId}"); exit;
}

// ============================================================
// DELETE — draft only
// ============================================================
if ($action === 'delete' && $motionId > 0) {
    $motion    = loadMotion($motionId);
    $meetingId = (int)$motion['meeting_id'];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        if ($motion['status'] !== 'draft') {
            setFlash('error', 'Only draft motions can be deleted.');
        } else {
            db()->prepare("DELETE FROM motions WHERE id=? AND status='draft'")->execute([$motionId]);
            setFlash('success', 'Motion deleted.');
        }
    }
    header("Location: admin_votes.php?action=list&meeting_id={$meetingId}"); exit;
}

// ============================================================
// CLOSE — open → closed + compute result
// ============================================================
if ($action === 'close' && $motionId > 0) {
    $motion    = loadMotion($motionId);
    $meetingId = (int)$motion['meeting_id'];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        if ($motion['status'] !== 'open') {
            setFlash('error', 'Only open motions can be closed.');
            header("Location: admin_votes.php?action=list&meeting_id={$meetingId}"); exit;
        }

        $counts   = voteCounts($motionId);
        $quorum   = checkQuorum($counts, $motion);
        $rt       = RESOLUTION_TYPES[$motion['resolution_type']];
        $threshold = $rt['threshold'];
        $passed   = $quorum['met'] && $counts['resultPct'] >= $threshold;

        $pdo = db();
        $pdo->beginTransaction();
        try {
            // Write result snapshot
            $pdo->prepare(
                "INSERT INTO vote_result
                 (motion_id, total_erven, count_online, count_manual, count_proxy,
                  count_for, count_against, count_abstain, count_noshow, count_blank,
                  physical_present, total_voted, quorum_met, threshold_pct, result_pct,
                  passed, closed_by)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            )->execute([
                $motionId,
                $motion['total_erven'],
                $counts['online'],
                $counts['manual'],
                $counts['proxy'],
                $counts['for'],
                $counts['against'],
                $counts['abstain'],
                $counts['noshow'],
                $counts['blank'],
                $counts['physical'],
                $counts['total'],
                $quorum['met'] ? 1 : 0,
                $threshold,
                $counts['resultPct'],
                $passed ? 1 : 0,
                $adminId,
            ]);

            // Close the motion
            $pdo->prepare("UPDATE motions SET status='closed', updated_at=NOW() WHERE id=?")
               ->execute([$motionId]);

            $pdo->commit();
            $outcome = $passed ? 'PASSED ✅' : 'FAILED ❌';
            setFlash('success', "Voting closed. Motion {$outcome} — see Results for full detail.");
        } catch (Exception $e) {
            $pdo->rollBack();
            setFlash('error', 'Error computing result. Please try again.');
        }
    }
    header("Location: admin_votes.php?action=results&id={$motionId}&meeting_id={$meetingId}"); exit;
}

// ============================================================
// PROXIES — register and view proxy votes
// ============================================================
if ($action === 'proxies' && $motionId > 0) {

    $motion    = loadMotion($motionId);
    $meetingId = (int)$motion['meeting_id'];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $erf     = strtoupper(trim($_POST['erf_number']       ?? ''));
        $holder  = trim($_POST['proxy_holder']                ?? '');
        $holderErf = strtoupper(trim($_POST['proxy_holder_erf'] ?? ''));
        $formRef = trim($_POST['form_reference']              ?? '');
        $notes   = trim($_POST['notes']                       ?? '');

        $perrors = [];
        if ($erf === '')    $perrors[] = 'Erf number is required.';
        if ($holder === '') $perrors[] = 'Proxy holder name is required.';

        // Check erf has not already voted
        if (empty($perrors)) {
            $already = db()->prepare("SELECT id FROM vote_cast WHERE motion_id=? AND erf_number=?");
            $already->execute([$motionId, $erf]);
            if ($already->fetch()) $perrors[] = "Erf {$erf} has already cast a vote — proxy cannot be registered.";
        }

        if (empty($perrors)) {
            try {
                db()->prepare(
                    "INSERT INTO vote_proxy
                     (motion_id, erf_number, proxy_holder, proxy_holder_erf, form_reference, captured_by, notes)
                     VALUES (?,?,?,?,?,?,?)"
                )->execute([
                    $motionId, $erf, $holder,
                    $holderErf ?: null, $formRef ?: null,
                    $adminId, $notes ?: null,
                ]);
                setFlash('success', "Proxy registered for Erf {$erf}.");
            } catch (Exception $e) {
                setFlash('error', "Proxy already registered for Erf {$erf}.");
            }
            header("Location: admin_votes.php?action=proxies&id={$motionId}&meeting_id={$meetingId}"); exit;
        }
        $_SESSION['perrors'] = $perrors;
        $_SESSION['ppost']   = $_POST;
        header("Location: admin_votes.php?action=proxies&id={$motionId}&meeting_id={$meetingId}"); exit;
    }

    $proxies = db()->prepare(
        "SELECT * FROM vote_proxy WHERE motion_id=? ORDER BY captured_at DESC"
    );
    $proxies->execute([$motionId]);
    $proxies = $proxies->fetchAll();

    $perrors = $_SESSION['perrors'] ?? [];
    $ppost   = $_SESSION['ppost']   ?? [];
    unset($_SESSION['perrors'], $_SESSION['ppost']);

    pageHeader('Proxy Votes', 'admin');
    renderHeader('📋 Proxy Votes', 'logout.php');
    ?>

    <main class="pc-main">

      <div class="card card-wide" style="margin-bottom:16px;">
        <div class="card-toolbar">
          <div>
            <h2 class="card-title">📋 Proxy Register — Motion <?= (int)$motion['motion_number'] ?>: <?= htmlspecialchars($motion['title']) ?></h2>
            <span class="badge badge-green">Open</span>
            &nbsp; <span class="muted-note"><?= count($proxies) ?> proxy vote<?= count($proxies) != 1 ? 's' : '' ?> registered</span>
          </div>
        </div>
      </div>

      <!-- Existing proxies -->
      <?php if (!empty($proxies)): ?>
      <div class="card card-wide" style="margin-bottom:16px;">
        <h3 class="section-title">Registered Proxies</h3>
        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr><th>Erf</th><th>Proxy Holder</th><th>Holder Erf</th><th>Form Ref</th><th>Captured</th><th>Notes</th></tr>
            </thead>
            <tbody>
            <?php foreach ($proxies as $p): ?>
              <tr>
                <td><strong><?= htmlspecialchars($p['erf_number']) ?></strong></td>
                <td><?= htmlspecialchars($p['proxy_holder']) ?></td>
                <td><?= htmlspecialchars($p['proxy_holder_erf'] ?? '—') ?></td>
                <td><?= htmlspecialchars($p['form_reference']  ?? '—') ?></td>
                <td style="font-size:.8rem;"><?= date('d M Y H:i', strtotime($p['captured_at'])) ?></td>
                <td style="font-size:.8rem;"><?= htmlspecialchars($p['notes'] ?? '') ?></td>
              </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>
      <?php endif; ?>

      <!-- Register new proxy -->
      <?php if ($motion['status'] === 'open'): ?>
      <div class="card card-wide">
        <h3 class="section-title">Register New Proxy</h3>

        <?php if (!empty($perrors)): ?>
          <div class="alert alert-danger">
            <?php foreach ($perrors as $e): ?><p><?= htmlspecialchars($e) ?></p><?php endforeach; ?>
          </div>
        <?php endif; ?>

        <?= getFlash() ?>

        <form method="POST">
          <?= csrfField() ?>
          <div class="form-row">
            <div class="form-group">
              <label>Erf Number <span class="required">*</span>
                <span class="muted-note">(erf granting the proxy)</span>
              </label>
              <input type="text" name="erf_number" style="text-transform:uppercase;"
                     value="<?= htmlspecialchars(strtoupper($ppost['erf_number'] ?? '')) ?>"
                     placeholder="e.g. E15227" maxlength="20">
            </div>
            <div class="form-group">
              <label>Proxy Holder Name <span class="required">*</span></label>
              <input type="text" name="proxy_holder" maxlength="100"
                     value="<?= htmlspecialchars($ppost['proxy_holder'] ?? '') ?>"
                     placeholder="Full name of person holding proxy">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>Proxy Holder Erf <span class="muted-note">(if also a member)</span></label>
              <input type="text" name="proxy_holder_erf" style="text-transform:uppercase;"
                     value="<?= htmlspecialchars(strtoupper($ppost['proxy_holder_erf'] ?? '')) ?>"
                     placeholder="e.g. E15300" maxlength="20">
            </div>
            <div class="form-group">
              <label>Form Reference <span class="muted-note">(paper form number)</span></label>
              <input type="text" name="form_reference" maxlength="50"
                     value="<?= htmlspecialchars($ppost['form_reference'] ?? '') ?>"
                     placeholder="e.g. PROXY-2026-001">
            </div>
          </div>
          <div class="form-group">
            <label>Notes <span class="muted-note">(optional)</span></label>
            <input type="text" name="notes" maxlength="255"
                   value="<?= htmlspecialchars($ppost['notes'] ?? '') ?>">
          </div>
          <div class="btn-group">
            <button type="submit" class="btn btn-primary">Register Proxy</button>
            <a href="admin_votes.php?action=list&meeting_id=<?= $meetingId ?>" class="btn btn-navy">← Back to Motions</a>
          </div>
        </form>
      </div>
      <?php endif; ?>

    </main>

    <?php pageFooter(); exit;
}

// ============================================================
// CAPTURE — admin captures manual or proxy vote per erf
// ============================================================
if ($action === 'capture' && $motionId > 0) {

    $motion    = loadMotion($motionId);
    $meetingId = (int)$motion['meeting_id'];

    if ($motion['status'] !== 'open') {
        setFlash('error', 'Votes can only be captured for open motions.');
        header("Location: admin_votes.php?action=list&meeting_id={$meetingId}"); exit;
    }

    $cerrors = [];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $erf    = strtoupper(trim($_POST['erf_number']     ?? ''));
        $method = trim($_POST['capture_method']            ?? '');
        $vote   = trim($_POST['vote_option']               ?? '');
        $blank  = empty($vote) ? 1 : 0;
        if ($blank) $vote = 'abstain';

        $validMethods = ['manual', 'proxy'];
        $validVotes   = ['for', 'against', 'abstain', 'noshow'];

        if ($erf === '')                       $cerrors[] = 'Erf number is required.';
        if (!in_array($method, $validMethods)) $cerrors[] = 'Select a valid capture method.';
        if (!in_array($vote, $validVotes))     $cerrors[] = 'Select a valid vote option.';

        // If proxy method — check proxy is registered
        $proxyId = null;
        if (empty($cerrors) && $method === 'proxy') {
            $pcheck = db()->prepare("SELECT id FROM vote_proxy WHERE motion_id=? AND erf_number=?");
            $pcheck->execute([$motionId, $erf]);
            $prow = $pcheck->fetch();
            if (!$prow) {
                $cerrors[] = "No proxy is registered for Erf {$erf}. Register the proxy first.";
            } else {
                $proxyId = $prow['id'];
            }
        }

        // Check not already voted
        if (empty($cerrors)) {
            $already = db()->prepare("SELECT id FROM vote_cast WHERE motion_id=? AND erf_number=?");
            $already->execute([$motionId, $erf]);
            if ($already->fetch()) $cerrors[] = "Erf {$erf} has already cast a vote for this motion.";
        }

        if (empty($cerrors)) {
            // ── Retry with backoff for transient DB errors only ──
            $maxAttempts = 3;
            $attempt     = 0;

            while ($attempt < $maxAttempts) {
                $attempt++;
                try {
                    $pdo = db();
                    $pdo->beginTransaction();

                    $ins = $pdo->prepare(
                        "INSERT INTO vote_cast
                         (motion_id, erf_number, capture_method, cast_by_role, cast_by_id, proxy_id, ip_address)
                         VALUES (?,?,?,'admin',?,?,?)"
                    );
                    $ins->execute([
                        $motionId, $erf, $method, $adminId,
                        $proxyId, $_SERVER['REMOTE_ADDR'] ?? null,
                    ]);
                    $castId = (int)$pdo->lastInsertId();

                    $pdo->prepare(
                        "INSERT INTO vote_tally (cast_id, vote_option, is_blank) VALUES (?,?,?)"
                    )->execute([$castId, $vote, $blank]);

                    $pdo->commit();
                    setFlash('success', "Vote captured for Erf {$erf} — " . strtoupper($vote) . " (" . ucfirst($method) . ").");
                    header("Location: admin_votes.php?action=capture&id={$motionId}&meeting_id={$meetingId}"); exit;

                } catch (\Throwable $e) {
                    if (isset($pdo) && $pdo->inTransaction()) $pdo->rollBack();

                    if (str_contains($e->getMessage(), 'Duplicate') || str_contains($e->getMessage(), '1062')) {
                        setFlash('error', "Erf {$erf} has already cast a vote.");
                        header("Location: admin_votes.php?action=capture&id={$motionId}&meeting_id={$meetingId}"); exit;
                    }

                    $transient = str_contains($e->getMessage(), 'Lock wait timeout')
                              || str_contains($e->getMessage(), 'Deadlock')
                              || str_contains($e->getMessage(), '1205')
                              || str_contains($e->getMessage(), '1213')
                              || str_contains($e->getMessage(), 'server has gone away')
                              || str_contains($e->getMessage(), 'Lost connection')
                              || str_contains($e->getMessage(), 'Too many connections');

                    if ($transient && $attempt < $maxAttempts) {
                        usleep(random_int(100000, 300000));
                        continue;
                    }

                    setFlash('error', 'Error capturing vote. Please try again.');
                    header("Location: admin_votes.php?action=capture&id={$motionId}&meeting_id={$meetingId}"); exit;
                }
            }
        }
    }

    // Recent captures
    $recent = db()->prepare(
        "SELECT vc.erf_number, vc.capture_method, vt.vote_option, vt.is_blank, vc.cast_at
         FROM vote_cast vc
         JOIN vote_tally vt ON vt.cast_id = vc.id
         WHERE vc.motion_id=? AND vc.capture_method IN ('manual','proxy')
         ORDER BY vc.cast_at DESC LIMIT 20"
    );
    $recent->execute([$motionId]);
    $recent = $recent->fetchAll();

    $counts = voteCounts($motionId);
    $quorum = checkQuorum($counts, $motion);

    pageHeader('Capture Vote', 'admin');
    renderHeader('✏️ Capture Vote', 'logout.php');
    ?>

    <main class="pc-main">

      <!-- Live count strip -->
      <div class="card card-wide" style="margin-bottom:16px;">
        <h2 class="card-title" style="margin-bottom:10px;">
          🗳️ Motion <?= (int)$motion['motion_number'] ?>: <?= htmlspecialchars($motion['title']) ?>
          <span class="badge badge-green" style="margin-left:8px;">Open</span>
        </h2>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:10px;margin-top:8px;">
          <?php
            $tiles = [
              ['Online',   $counts['online'],   '#1565c0'],
              ['Manual',   $counts['manual'],   '#6a1b9a'],
              ['Proxy',    $counts['proxy'],    '#e65100'],
              ['For',      $counts['for'],      '#2e7d32'],
              ['Against',  $counts['against'],  '#c62828'],
              ['Abstain',  $counts['abstain'],  '#757575'],
              ['Physical', $counts['physical'], '#0277bd'],
              ['Total',    $counts['total'],    '#1a237e'],
            ];
            foreach ($tiles as [$label, $val, $color]):
          ?>
          <div style="background:#fff;border:2px solid <?= $color ?>;border-radius:8px;
                      padding:10px;text-align:center;">
            <div style="font-size:1.5rem;font-weight:800;color:<?= $color ?>;"><?= $val ?></div>
            <div style="font-size:.75rem;color:#666;"><?= $label ?></div>
          </div>
          <?php endforeach; ?>
        </div>
        <!-- Quorum status -->
        <div style="margin-top:12px;padding:10px 14px;border-radius:6px;
                    background:<?= $quorum['met'] ? '#e8f5e9' : '#fff3e0' ?>;
                    border:1px solid <?= $quorum['met'] ? '#a5d6a7' : '#ffcc02' ?>;">
          <strong>Quorum:</strong>
          <?php if ($quorum['met']): ?>
            ✅ Met — <?= $counts['physical'] ?> physical (min <?= $motion['quorum_physical'] ?>)
            + <?= $counts['proxy'] ?> proxy = <?= $counts['total'] ?> total (min <?= $motion['quorum_total'] ?>)
          <?php else: ?>
            ⚠️ Not yet met —
            Physical: <?= $counts['physical'] ?>/<?= $motion['quorum_physical'] ?>
            <?= $quorum['physicalOk'] ? '✅' : '❌' ?> &nbsp;·&nbsp;
            Total: <?= $counts['total'] ?>/<?= $motion['quorum_total'] ?>
            <?= $quorum['totalOk'] ? '✅' : '❌' ?>
          <?php endif; ?>
        </div>
      </div>

      <!-- Capture form -->
      <div class="card card-wide" style="margin-bottom:16px;">
        <h3 class="section-title">Capture Vote</h3>

        <?php if (!empty($cerrors)): ?>
          <div class="alert alert-danger">
            <?php foreach ($cerrors as $e): ?><p><?= htmlspecialchars($e) ?></p><?php endforeach; ?>
          </div>
        <?php endif; ?>

        <?= getFlash() ?>

        <form method="POST">
          <?= csrfField() ?>
          <div class="form-row">
            <div class="form-group">
              <label>Erf Number <span class="required">*</span></label>
              <input type="text" name="erf_number" required style="text-transform:uppercase;"
                     placeholder="e.g. E15227" maxlength="20"
                     value="<?= htmlspecialchars(strtoupper($_POST['erf_number'] ?? '')) ?>">
            </div>
            <div class="form-group">
              <label>Capture Method <span class="required">*</span></label>
              <select name="capture_method" required>
                <option value="">— Select —</option>
                <option value="manual" <?= ($_POST['capture_method'] ?? '') === 'manual' ? 'selected' : '' ?>>
                  Manual (written / show of hands)
                </option>
                <option value="proxy"  <?= ($_POST['capture_method'] ?? '') === 'proxy'  ? 'selected' : '' ?>>
                  Proxy (pre-submitted form)
                </option>
              </select>
            </div>
          </div>
          <div class="form-group">
            <label>Vote <span class="required">*</span>
              <span class="muted-note">(leave blank to record as Abstain)</span>
            </label>
            <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:6px;">
              <?php
                $voteOpts = [
                  'for'     => ['label'=>'For',     'color'=>'#2e7d32'],
                  'against' => ['label'=>'Against', 'color'=>'#c62828'],
                  'abstain' => ['label'=>'Abstain', 'color'=>'#757575'],
                  'noshow'  => ['label'=>'No Show', 'color'=>'#9e9e9e'],
                ];
                foreach ($voteOpts as $val => $opt):
              ?>
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;
                             padding:10px 18px;border:2px solid <?= $opt['color'] ?>;
                             border-radius:8px;font-weight:600;
                             <?= ($_POST['vote_option'] ?? '') === $val ? 'background:' . $opt['color'] . ';color:#fff;' : 'color:' . $opt['color'] . ';' ?>">
                <input type="radio" name="vote_option" value="<?= $val ?>"
                       <?= ($_POST['vote_option'] ?? '') === $val ? 'checked' : '' ?>
                       style="accent-color:<?= $opt['color'] ?>;">
                <?= $opt['label'] ?>
              </label>
              <?php endforeach; ?>
            </div>
          </div>
          <div class="btn-group" style="margin-top:12px;">
            <button type="submit" class="btn btn-primary"
                    onclick="return confirm('Confirm vote capture for this erf? This cannot be changed.')">
              Capture Vote ✔
            </button>
            <a href="admin_votes.php?action=list&meeting_id=<?= $meetingId ?>" class="btn btn-navy">← Back to Motions</a>
          </div>
        </form>
      </div>

      <!-- Recent captures -->
      <?php if (!empty($recent)): ?>
      <div class="card card-wide">
        <h3 class="section-title">Recent Captures (Manual &amp; Proxy)</h3>
        <div class="table-responsive">
          <table class="data-table">
            <thead><tr><th>Erf</th><th>Method</th><th>Vote</th><th>Time</th></tr></thead>
            <tbody>
            <?php foreach ($recent as $rc): ?>
              <tr>
                <td><strong><?= htmlspecialchars($rc['erf_number']) ?></strong></td>
                <td><span class="badge badge-info"><?= ucfirst($rc['capture_method']) ?></span></td>
                <td>
                  <?php
                    $vColor = match($rc['vote_option']) {
                        'for'     => '#2e7d32',
                        'against' => '#c62828',
                        default   => '#757575',
                    };
                  ?>
                  <span style="color:<?= $vColor ?>;font-weight:700;">
                    <?= strtoupper($rc['vote_option']) ?>
                    <?= $rc['is_blank'] ? '<span class="muted-note">(blank)</span>' : '' ?>
                  </span>
                </td>
                <td style="font-size:.8rem;"><?= date('H:i:s', strtotime($rc['cast_at'])) ?></td>
              </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>
      <?php endif; ?>

    </main>

    <?php pageFooter(); exit;
}

// ============================================================
// RESULTS — full result display
// ============================================================
if ($action === 'results' && $motionId > 0) {

    $motion    = loadMotion($motionId);
    $meetingId = (int)$motion['meeting_id'];
    $rt        = RESOLUTION_TYPES[$motion['resolution_type']];

    // For closed motions use stored result; for open use live counts
    if ($motion['status'] === 'closed') {
        $res = db()->prepare("SELECT * FROM vote_result WHERE motion_id=?");
        $res->execute([$motionId]);
        $result = $res->fetch();
        $counts = [
            'online'     => $result['count_online'],
            'manual'     => $result['count_manual'],
            'proxy'      => $result['count_proxy'],
            'for'        => $result['count_for'],
            'against'    => $result['count_against'],
            'abstain'    => $result['count_abstain'],
            'noshow'     => $result['count_noshow'],
            'blank'      => $result['count_blank'],
            'physical'   => $result['physical_present'],
            'total'      => $result['total_voted'],
            'forAgainst' => $result['count_for'] + $result['count_against'],
            'resultPct'  => $result['result_pct'],
        ];
        $quorum = ['met' => $result['quorum_met']];
        $passed = $result['passed'];
    } else {
        $counts = voteCounts($motionId);
        $quorum = checkQuorum($counts, $motion);
        $passed = $quorum['met'] && $counts['resultPct'] >= $rt['threshold'];
        $result = null;
    }

    pageHeader('Results', 'admin');
    renderHeader('📊 Vote Results', 'logout.php');
    ?>

    <main class="pc-main">

      <!-- Header -->
      <div class="card card-wide" style="margin-bottom:16px;">
        <div class="card-toolbar">
          <div>
            <h2 class="card-title">📊 Motion <?= (int)$motion['motion_number'] ?>: <?= htmlspecialchars($motion['title']) ?></h2>
            <p style="margin-top:4px;">
              <span class="badge <?= $motion['status'] === 'open' ? 'badge-green' : 'badge-grey' ?>">
                <?= ucfirst($motion['status']) ?>
              </span>
              &nbsp;
              <span style="font-size:.85rem;color:#666;">
                <?= htmlspecialchars($rt['label']) ?> — <?= $rt['threshold'] ?>% required
              </span>
            </p>
          </div>
          <?php if ($motion['status'] === 'closed'): ?>
          <a href="admin_votes.php?action=csv&id=<?= $motionId ?>&meeting_id=<?= $meetingId ?>" class="btn btn-green">⬇ Download CSV</a>
          <?php endif; ?>
        </div>
      </div>

      <!-- Outcome banner (closed motions) -->
      <?php if ($motion['status'] === 'closed'): ?>
      <div style="padding:20px 24px;border-radius:10px;text-align:center;margin-bottom:16px;
                  background:<?= $passed ? '#e8f5e9' : '#ffebee' ?>;
                  border:2px solid <?= $passed ? '#4caf50' : '#f44336' ?>;">
        <div style="font-size:2.5rem;"><?= $passed ? '✅' : '❌' ?></div>
        <div style="font-size:1.4rem;font-weight:800;color:<?= $passed ? '#2e7d32' : '#c62828' ?>;margin-top:6px;">
          MOTION <?= $passed ? 'PASSED' : 'FAILED' ?>
        </div>
        <div style="font-size:.9rem;color:#555;margin-top:4px;">
          <?= $counts['resultPct'] ?>% For (<?= $rt['threshold'] ?>% required)
          <?php if (!$quorum['met']): ?>
            &nbsp;·&nbsp; <strong style="color:#e65100;">Quorum not met</strong>
          <?php endif; ?>
        </div>
      </div>
      <?php endif; ?>

      <!-- Vote breakdown -->
      <div class="card card-wide" style="margin-bottom:16px;">
        <h3 class="section-title">Vote Breakdown</h3>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:12px;margin-top:8px;">
          <?php
            $tiles = [
              ['For',      $counts['for'],      '#2e7d32'],
              ['Against',  $counts['against'],  '#c62828'],
              ['Abstain',  $counts['abstain'],  '#757575'],
              ['No Show',  $counts['noshow'],   '#9e9e9e'],
              ['Online',   $counts['online'],   '#1565c0'],
              ['Manual',   $counts['manual'],   '#6a1b9a'],
              ['Proxy',    $counts['proxy'],    '#e65100'],
              ['Physical', $counts['physical'], '#0277bd'],
              ['Total',    $counts['total'],    '#1a237e'],
            ];
            foreach ($tiles as [$label, $val, $color]):
          ?>
          <div style="background:#fff;border:2px solid <?= $color ?>;border-radius:8px;
                      padding:12px;text-align:center;">
            <div style="font-size:1.8rem;font-weight:800;color:<?= $color ?>;"><?= $val ?></div>
            <div style="font-size:.75rem;color:#666;"><?= $label ?></div>
          </div>
          <?php endforeach; ?>
        </div>

        <!-- Result percentage bar -->
        <?php if ($counts['forAgainst'] > 0): ?>
        <div style="margin-top:20px;">
          <div style="display:flex;justify-content:space-between;font-size:.85rem;margin-bottom:4px;">
            <span style="color:#2e7d32;font-weight:700;">For: <?= $counts['resultPct'] ?>%</span>
            <span style="color:#c62828;font-weight:700;">Against: <?= round(100 - $counts['resultPct'], 2) ?>%</span>
          </div>
          <div style="background:#f8d7da;border-radius:20px;height:24px;overflow:hidden;">
            <div style="background:#2e7d32;width:<?= min(100, $counts['resultPct']) ?>%;height:100%;
                        border-radius:20px;transition:width .5s;position:relative;">
              <?php if ($counts['resultPct'] >= $rt['threshold']): ?>
                <div style="position:absolute;right:6px;top:3px;font-size:.75rem;color:#fff;font-weight:700;">
                  ✔ <?= $counts['resultPct'] ?>%
                </div>
              <?php endif; ?>
            </div>
          </div>
          <!-- Threshold marker -->
          <div style="position:relative;height:16px;">
            <div style="position:absolute;left:<?= $rt['threshold'] ?>%;transform:translateX(-50%);
                        font-size:.7rem;color:#e65100;white-space:nowrap;">
              ▲ <?= $rt['threshold'] ?>% required
            </div>
          </div>
        </div>
        <?php endif; ?>
      </div>

      <!-- Quorum detail -->
      <div class="card card-wide" style="margin-bottom:16px;">
        <h3 class="section-title">Quorum</h3>
        <table class="data-table" style="max-width:480px;">
          <thead><tr><th>Requirement</th><th>Required</th><th>Actual</th><th>Status</th></tr></thead>
          <tbody>
            <tr>
              <td>Physical present (online + manual)</td>
              <td><?= $motion['quorum_physical'] ?></td>
              <td><?= $counts['physical'] ?></td>
              <td><?= $counts['physical'] >= $motion['quorum_physical'] ? '✅' : '❌' ?></td>
            </tr>
            <tr>
              <td>Total (physical + proxy)</td>
              <td><?= $motion['quorum_total'] ?></td>
              <td><?= $counts['total'] ?></td>
              <td><?= $counts['total'] >= $motion['quorum_total'] ? '✅' : '❌' ?></td>
            </tr>
            <tr>
              <td><strong>Quorum met</strong></td>
              <td colspan="2">Both conditions above must be satisfied</td>
              <td><?= $quorum['met'] ? '✅ Yes' : '❌ No' ?></td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card card-wide">
        <div class="btn-group">
          <?php if ($motion['status'] === 'closed'): ?>
            <a href="admin_votes.php?action=csv&id=<?= $motionId ?>&meeting_id=<?= $meetingId ?>" class="btn btn-green">⬇ Download CSV</a>
          <?php endif; ?>
          <?php if ($motion['status'] === 'open'): ?>
            <a href="admin_votes.php?action=capture&id=<?= $motionId ?>&meeting_id=<?= $meetingId ?>" class="btn btn-primary">✏️ Capture Vote</a>
            <a href="admin_votes.php?action=proxies&id=<?= $motionId ?>&meeting_id=<?= $meetingId ?>" class="btn btn-navy">📋 Proxies</a>
          <?php endif; ?>
          <a href="admin_votes.php?action=list&meeting_id=<?= $meetingId ?>" class="btn btn-navy">← Back to Motions</a>
        </div>
      </div>

    </main>

    <?php pageFooter(); exit;
}

// ============================================================
// CSV — download results
// ============================================================
if ($action === 'csv' && $motionId > 0) {

    $motion    = loadMotion($motionId);
    $meetingId = (int)$motion['meeting_id'];
    $rt        = RESOLUTION_TYPES[$motion['resolution_type']];

    $res = db()->prepare("SELECT * FROM vote_result WHERE motion_id=?");
    $res->execute([$motionId]);
    $result = $res->fetch();

    if (!$result) {
        setFlash('error', 'No result record found. The motion may not be closed yet.');
        header("Location: admin_votes.php?action=results&id={$motionId}&meeting_id={$meetingId}"); exit;
    }

    function csvVoteRow(array $f): string {
        return implode(',', array_map(fn($v) => '"' . str_replace('"','""',$v??'') . '"', $f)) . "\r\n";
    }

    $filename = 'vote_result_' . $motionId . '_' . date('Ymd') . '.csv';
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Pragma: no-cache');

    $out = fopen('php://output', 'w');
    fputs($out, "\xEF\xBB\xBF");

    fwrite($out, csvVoteRow(['GEMB HOA — Vote Result Certificate']));
    fwrite($out, csvVoteRow([]));
    fwrite($out, csvVoteRow(['Motion',          $motion['title']]));
    fwrite($out, csvVoteRow(['Resolution Type', $rt['label']]));
    fwrite($out, csvVoteRow(['Threshold',       $rt['threshold'] . '%']));
    fwrite($out, csvVoteRow(['Status',          'Closed']));
    fwrite($out, csvVoteRow(['Closed At',       date('d M Y H:i', strtotime($result['closed_at']))]));
    fwrite($out, csvVoteRow(['Generated',       date('d M Y H:i')]));
    fwrite($out, csvVoteRow([]));

    fwrite($out, csvVoteRow(['QUORUM', '', '']));
    fwrite($out, csvVoteRow(['Physical present (online + manual)', $result['physical_present'], 'Required: ' . $motion['quorum_physical']]));
    fwrite($out, csvVoteRow(['Total voted (physical + proxy)',     $result['total_voted'],      'Required: ' . $motion['quorum_total']]));
    fwrite($out, csvVoteRow(['Quorum met', $result['quorum_met'] ? 'YES' : 'NO', '']));
    fwrite($out, csvVoteRow([]));

    fwrite($out, csvVoteRow(['VOTE BREAKDOWN', '', '']));
    fwrite($out, csvVoteRow(['Online votes',  $result['count_online'],  '']));
    fwrite($out, csvVoteRow(['Manual votes',  $result['count_manual'],  '']));
    fwrite($out, csvVoteRow(['Proxy votes',   $result['count_proxy'],   '']));
    fwrite($out, csvVoteRow(['Total cast',    $result['total_voted'],   '']));
    fwrite($out, csvVoteRow([]));
    fwrite($out, csvVoteRow(['For',           $result['count_for'],     '']));
    fwrite($out, csvVoteRow(['Against',       $result['count_against'], '']));
    fwrite($out, csvVoteRow(['Abstain',       $result['count_abstain'], '(excluded from threshold)']));
    fwrite($out, csvVoteRow(['No Show',       $result['count_noshow'],  '(excluded from threshold)']));
    fwrite($out, csvVoteRow(['Blank ballots', $result['count_blank'],   '(recorded as abstain)']));
    fwrite($out, csvVoteRow([]));

    $forAgainst = $result['count_for'] + $result['count_against'];
    fwrite($out, csvVoteRow(['RESULT', '', '']));
    fwrite($out, csvVoteRow(['For + Against base',  $forAgainst,           '']));
    fwrite($out, csvVoteRow(['Result percentage',   $result['result_pct'] . '%', 'For / (For+Against)']));
    fwrite($out, csvVoteRow(['Required threshold',  $result['threshold_pct'] . '%', '']));
    fwrite($out, csvVoteRow(['MOTION',              $result['passed'] ? 'PASSED' : 'FAILED', '']));

    fclose($out);
    exit;
}

// ============================================================
// Fallback
// ============================================================
header('Location: admin_meetings.php?action=list');
exit;
