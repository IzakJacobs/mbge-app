<?php
// ============================================================
// admin_meetings.php — Meeting / Voting Register Module (Admin only)
// GEMB Access Control System
// Version 1.0  |  2026-06-14
//
// A "meeting" (e.g. AGM November 2026) is the top-level voting
// register. Each meeting contains one or more motions, numbered
// sequentially (Motion 1, 2, 3...) within that meeting.
//
// Actions:
//   list    — view all meetings (default)
//   create  — new meeting form
//   edit    — edit draft meeting
//   open    — draft -> open (voting register opens; motions can
//             then be opened individually from admin_votes.php)
//   close   — open -> closed (meeting wrap-up; individual motions
//             must already be closed)
//   delete  — delete draft meeting only (must have no motions)
//   motions — jump into admin_votes.php scoped to this meeting
//
// Security:
//   requireAdmin() at chokepoint
//   verifyCsrfToken() on every POST
//   PDO prepared statements throughout
//   htmlspecialchars() on all output
//   Status transitions validated server-side
// ============================================================

require_once 'layout.php';
require_once __DIR__ . '/xlsx_lib/gemb_xlsx_helper.php';
if (session_status() === PHP_SESSION_NONE) session_start();

requireAdmin();

$action    = $_GET['action'] ?? 'list';
$meetingId = (int)($_GET['id'] ?? 0);
$adminId   = (int)($_SESSION['admin_id'] ?? 0);

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

// ============================================================
// LIST
// ============================================================
if ($action === 'list') {

    $stmt = db()->query(
        "SELECT mt.*,
                (SELECT COUNT(*) FROM motions mo WHERE mo.meeting_id = mt.id) AS motion_count,
                (SELECT COUNT(*) FROM motions mo WHERE mo.meeting_id = mt.id AND mo.status = 'open')   AS motions_open,
                (SELECT COUNT(*) FROM motions mo WHERE mo.meeting_id = mt.id AND mo.status = 'closed') AS motions_closed,
                (SELECT COUNT(*) FROM motions mo WHERE mo.meeting_id = mt.id AND mo.status = 'draft')  AS motions_draft
         FROM meetings mt
         ORDER BY mt.created_at DESC"
    );
    $meetings = $stmt->fetchAll();

    pageHeader('Voting Register', 'admin');
    renderHeader('🗳️ Voting Register — Meetings', 'logout.php');
    ?>

    <main class="pc-main">
      <div class="card card-wide">
        <div class="card-toolbar">
          <h2 class="card-title">🗳️ Meetings</h2>
          <a href="admin_meetings.php?action=create" class="btn btn-primary">＋ New Meeting</a>
        </div>

        <?= getFlash() ?>

        <?php if (empty($meetings)): ?>
          <p class="muted-note">No meetings yet. Click <strong>New Meeting</strong> to create one
             (e.g. "AGM November 2026").</p>
        <?php else: ?>
        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Meeting</th>
                <th>Date</th>
                <th>Status</th>
                <th>Motions</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
            <?php foreach ($meetings as $mt): ?>
              <?php
                $statusClass = match($mt['status']) {
                    'open'   => 'badge-green',
                    'closed' => 'badge-grey',
                    default  => 'badge-amber',
                };
              ?>
              <tr>
                <td><?= $mt['id'] ?></td>
                <td><strong><?= htmlspecialchars($mt['title']) ?></strong></td>
                <td><?= $mt['meeting_date'] ? date('d M Y', strtotime($mt['meeting_date'])) : '<span class="muted-note">—</span>' ?></td>
                <td><span class="badge <?= $statusClass ?>"><?= ucfirst($mt['status']) ?></span></td>
                <td>
                  <span style="font-size:.85rem;">
                    <?= (int)$mt['motion_count'] ?> total
                    <?php if ($mt['motions_draft']):  ?><br><span class="muted-note"><?= (int)$mt['motions_draft'] ?> draft</span><?php endif; ?>
                    <?php if ($mt['motions_open']):   ?><br><span style="color:#2e7d32;"><?= (int)$mt['motions_open'] ?> open</span><?php endif; ?>
                    <?php if ($mt['motions_closed']): ?><br><span class="muted-note"><?= (int)$mt['motions_closed'] ?> closed</span><?php endif; ?>
                  </span>
                </td>
                <td>
                  <div class="btn-group-sm">

                    <a href="admin_votes.php?action=list&meeting_id=<?= $mt['id'] ?>" class="btn btn-sm btn-blue">📋 Motions</a>

                    <?php if ($mt['status'] === 'draft'): ?>
                      <a href="admin_meetings.php?action=edit&id=<?= $mt['id'] ?>" class="btn btn-sm btn-amber">⚙️ Edit</a>
                      <form method="POST" action="admin_meetings.php?action=open&id=<?= $mt['id'] ?>" style="display:inline;">
                        <?= csrfField() ?>
                        <button type="submit" class="btn btn-sm btn-green"
                                onclick="return confirm('Open this meeting? You will then be able to open individual motions for voting.')">
                          ▶ Open
                        </button>
                      </form>
                      <?php if ((int)$mt['motion_count'] === 0): ?>
                      <form method="POST" action="admin_meetings.php?action=delete&id=<?= $mt['id'] ?>" style="display:inline;">
                        <?= csrfField() ?>
                        <button type="submit" class="btn btn-sm btn-red"
                                onclick="return confirm('Delete this meeting permanently?')">
                          🗑 Delete
                        </button>
                      </form>
                      <?php endif; ?>
                    <?php endif; ?>

                    <?php if ($mt['status'] === 'open' || $mt['status'] === 'closed'): ?>
                      <a href="admin_meetings.php?action=voter_register&id=<?= $mt['id'] ?>" class="btn btn-sm btn-amber">📋 Voter Register</a>
                      <a href="admin_meetings.php?action=send_tokens&id=<?= $mt['id'] ?>" class="btn btn-sm btn-green">✉️ Send Tokens</a>
                    <?php endif; ?>

                    <?php if ($mt['status'] === 'open'): ?>
                      <?php if ((int)$mt['motions_open'] === 0 && (int)$mt['motions_draft'] === 0): ?>
                      <form method="POST" action="admin_meetings.php?action=close&id=<?= $mt['id'] ?>" style="display:inline;">
                        <?= csrfField() ?>
                        <button type="submit" class="btn btn-sm btn-red"
                                onclick="return confirm('Close this meeting? All motions are already closed.')">
                          ⏹ Close Meeting
                        </button>
                      </form>
                      <?php else: ?>
                        <span class="muted-note" style="font-size:.75rem;">Close all motions before closing the meeting</span>
                      <?php endif; ?>
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
          <a href="admin.php?action=menu" class="btn btn-navy">← Back to Admin Menu</a>
        </div>
      </div>
    </main>

    <?php pageFooter(); exit;
}

// ============================================================
// CREATE
// ============================================================
if ($action === 'create') {

    $errors = [];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $title = trim($_POST['title']        ?? '');
        $date  = trim($_POST['meeting_date'] ?? '');

        if ($title === '') $errors[] = 'Meeting title is required.';

        if (empty($errors)) {
            db()->prepare(
                "INSERT INTO meetings (title, meeting_date, status, created_by)
                 VALUES (?,?,'draft',?)"
            )->execute([$title, $date ?: null, $adminId]);

            setFlash('success', 'Meeting created as draft. Add motions, then open it for voting.');
            header('Location: admin_meetings.php?action=list'); exit;
        }
    }

    pageHeader('New Meeting', 'admin');
    renderHeader('🗳️ New Meeting', 'logout.php');
    ?>

    <main class="pc-main">
      <div class="card card-wide">
        <h2 class="card-title">🗳️ Create Meeting / Voting Register</h2>

        <?php if (!empty($errors)): ?>
          <div class="alert alert-danger">
            <?php foreach ($errors as $e): ?><p><?= htmlspecialchars($e) ?></p><?php endforeach; ?>
          </div>
        <?php endif; ?>

        <form method="POST">
          <?= csrfField() ?>

          <div class="form-group">
            <label>Meeting Title <span class="required">*</span></label>
            <input type="text" name="title" maxlength="255" required
                   placeholder="e.g. AGM November 2026"
                   value="<?= htmlspecialchars($_POST['title'] ?? '') ?>">
          </div>

          <div class="form-group">
            <label>Meeting Date <span class="muted-note">(optional)</span></label>
            <input type="date" name="meeting_date"
                   value="<?= htmlspecialchars($_POST['meeting_date'] ?? '') ?>">
          </div>

          <p class="muted-note">
            After creating the meeting, add agenda items requiring a vote as
            Motion 1, Motion 2, etc. from the Motions screen.
          </p>

          <div class="btn-group">
            <button type="submit" class="btn btn-primary">Create Meeting →</button>
            <a href="admin_meetings.php?action=list" class="btn btn-navy">Cancel</a>
          </div>
        </form>
      </div>
    </main>

    <?php pageFooter(); exit;
}

// ============================================================
// EDIT — draft only
// ============================================================
if ($action === 'edit' && $meetingId > 0) {

    $meeting = loadMeeting($meetingId);
    if ($meeting['status'] !== 'draft') {
        setFlash('error', 'Only draft meetings can be edited.');
        header('Location: admin_meetings.php?action=list'); exit;
    }

    $errors = [];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $title = trim($_POST['title']        ?? '');
        $date  = trim($_POST['meeting_date'] ?? '');

        if ($title === '') $errors[] = 'Meeting title is required.';

        if (empty($errors)) {
            db()->prepare(
                "UPDATE meetings SET title=?, meeting_date=? WHERE id=? AND status='draft'"
            )->execute([$title, $date ?: null, $meetingId]);

            setFlash('success', 'Meeting updated.');
            header('Location: admin_meetings.php?action=list'); exit;
        }

        $meeting['title']        = $title;
        $meeting['meeting_date'] = $date;
    }

    pageHeader('Edit Meeting', 'admin');
    renderHeader('🗳️ Edit Meeting', 'logout.php');
    ?>

    <main class="pc-main">
      <div class="card card-wide">
        <h2 class="card-title">⚙️ Edit Meeting</h2>

        <?php if (!empty($errors)): ?>
          <div class="alert alert-danger">
            <?php foreach ($errors as $e): ?><p><?= htmlspecialchars($e) ?></p><?php endforeach; ?>
          </div>
        <?php endif; ?>

        <form method="POST">
          <?= csrfField() ?>

          <div class="form-group">
            <label>Meeting Title <span class="required">*</span></label>
            <input type="text" name="title" maxlength="255" required
                   value="<?= htmlspecialchars($meeting['title']) ?>">
          </div>

          <div class="form-group">
            <label>Meeting Date <span class="muted-note">(optional)</span></label>
            <input type="date" name="meeting_date"
                   value="<?= htmlspecialchars($meeting['meeting_date'] ?? '') ?>">
          </div>

          <div class="btn-group">
            <button type="submit" class="btn btn-primary">Save Changes</button>
            <a href="admin_meetings.php?action=list" class="btn btn-navy">← Back</a>
          </div>
        </form>
      </div>
    </main>

    <?php pageFooter(); exit;
}

// ============================================================
// OPEN — draft → open
// ============================================================
if ($action === 'open' && $meetingId > 0) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $meeting = loadMeeting($meetingId);
        if ($meeting['status'] !== 'draft') {
            setFlash('error', 'Only draft meetings can be opened.');
        } else {
            db()->prepare("UPDATE meetings SET status='open', updated_at=NOW() WHERE id=? AND status='draft'")
               ->execute([$meetingId]);
            setFlash('success', 'Meeting opened. You can now open individual motions for voting from the Motions screen.');
        }
    }
    header('Location: admin_meetings.php?action=list'); exit;
}

// ============================================================
// CLOSE — open → closed
// ============================================================
if ($action === 'close' && $meetingId > 0) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $meeting = loadMeeting($meetingId);
        if ($meeting['status'] !== 'open') {
            setFlash('error', 'Only open meetings can be closed.');
        } else {
            // Guard: all motions must be closed (or there must be none)
            $stmt = db()->prepare(
                "SELECT COUNT(*) FROM motions WHERE meeting_id=? AND status IN ('draft','open')"
            );
            $stmt->execute([$meetingId]);
            if ((int)$stmt->fetchColumn() > 0) {
                setFlash('error', 'All motions must be closed before closing the meeting.');
            } else {
                db()->prepare("UPDATE meetings SET status='closed', updated_at=NOW() WHERE id=? AND status='open'")
                   ->execute([$meetingId]);
                setFlash('success', 'Meeting closed.');
            }
        }
    }
    header('Location: admin_meetings.php?action=list'); exit;
}

// ============================================================
// DELETE — draft only, must have no motions
// ============================================================
if ($action === 'delete' && $meetingId > 0) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $meeting = loadMeeting($meetingId);
        if ($meeting['status'] !== 'draft') {
            setFlash('error', 'Only draft meetings can be deleted.');
        } else {
            $stmt = db()->prepare("SELECT COUNT(*) FROM motions WHERE meeting_id=?");
            $stmt->execute([$meetingId]);
            if ((int)$stmt->fetchColumn() > 0) {
                setFlash('error', 'Cannot delete a meeting that has motions. Delete the motions first.');
            } else {
                db()->prepare("DELETE FROM meetings WHERE id=? AND status='draft'")->execute([$meetingId]);
                setFlash('success', 'Meeting deleted.');
            }
        }
    }
    header('Location: admin_meetings.php?action=list'); exit;
}

// ============================================================
// VOTER REGISTER — upload levy roll CSV (Erf, Owner Name, Email, Phone)
// Re-uploadable: replaces existing rows for this meeting.
// ============================================================
if ($action === 'voter_register' && $meetingId > 0) {

    $meeting = loadMeeting($meetingId);
    $errors  = [];
    $preview = null;

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();

        $uploadExt = strtolower(pathinfo($_FILES['levy_csv']['name'] ?? '', PATHINFO_EXTENSION));
        if (empty($_FILES['levy_csv']['tmp_name']) || $_FILES['levy_csv']['error'] !== UPLOAD_ERR_OK) {
            $errors[] = 'Please choose a CSV or Excel (.xlsx) file to upload.';
        } elseif (!in_array($uploadExt, ['csv', 'txt', 'xlsx'], true)) {
            $errors[] = 'Only CSV or Excel (.xlsx) files are allowed.';
        } else {
            $rows     = [];
            $rawRows  = gemb_read_raw_rows($_FILES['levy_csv']['tmp_name'], $uploadExt);
            if (empty($rawRows)) {
                $errors[] = 'Could not read the uploaded file.';
            } else {
                $lineNum = 0;
                foreach ($rawRows as $line) {
                    $lineNum++;
                    if (count($line) < 1) continue;

                    $line = array_map('trim', $line);

                    // Skip empty rows
                    if (count(array_filter($line, fn($v) => $v !== '')) === 0) continue;

                    // Skip header row (detect by non-numeric-ish first cell containing "erf")
                    if ($lineNum === 1 && stripos((string)($line[0] ?? ''), 'erf') !== false) {
                        continue;
                    }

                    if (count($line) < 3) continue; // need at least Erf + 2 more columns

                    $erf = strtoupper(preg_replace('/[^A-Z0-9]/i', '', $line[0] ?? ''));
                    if ($erf === '') continue;

                    // Find which column (after the erf) contains a valid email —
                    // levy roll exports vary: either
                    //   Erf, Owner Name, Email, Phone   (email in col 3)
                    // or
                    //   Erf, Surname, FirstName, Email  (email in col 4, no phone)
                    $emailCol = null;
                    for ($c = 1; $c < count($line); $c++) {
                        if (filter_var($line[$c], FILTER_VALIDATE_EMAIL)) {
                            $emailCol = $c;
                            break;
                        }
                    }
                    if ($emailCol === null) continue; // no valid email anywhere — skip row

                    $email = $line[$emailCol];

                    // Everything before the email column (excluding erf) is the name —
                    // join multiple columns (e.g. Surname + FirstName) with a space.
                    $nameParts = array_slice($line, 1, $emailCol - 1);
                    $nameParts = array_filter($nameParts, fn($v) => $v !== '');
                    $name = trim(implode(' ', $nameParts));

                    // Anything after the email column is treated as phone (first non-empty)
                    $phone = '';
                    for ($c = $emailCol + 1; $c < count($line); $c++) {
                        if ($line[$c] !== '') { $phone = $line[$c]; break; }
                    }

                    if ($name === '') continue;

                    $rows[] = [$erf, $name, $email, $phone];
                }
            }

            if (empty($rows) && empty($errors)) {
                $errors[] = 'No valid rows found. Expected columns: Erf, Owner Name, Email, Phone.';
            }

            if (empty($errors)) {
                $pdo = db();
                $pdo->beginTransaction();
                try {
                    // Replace existing register for this meeting
                    $pdo->prepare("DELETE FROM vote_eligible_owners WHERE meeting_id = ?")
                        ->execute([$meetingId]);

                    $ins = $pdo->prepare(
                        "INSERT INTO vote_eligible_owners
                         (meeting_id, erf_number, owner_name, owner_email, owner_phone)
                         VALUES (?,?,?,?,?)
                         ON DUPLICATE KEY UPDATE
                           owner_name = VALUES(owner_name),
                           owner_email = VALUES(owner_email),
                           owner_phone = VALUES(owner_phone)"
                    );
                    foreach ($rows as $r) {
                        $ins->execute([$meetingId, $r[0], $r[1], $r[2], $r[3]]);
                    }

                    // Clear any previously-generated tokens — register changed
                    $pdo->prepare("DELETE FROM vote_tokens WHERE meeting_id = ?")
                        ->execute([$meetingId]);

                    $pdo->commit();
                    setFlash('success', count($rows) . ' erf(s) loaded into the voter register. '
                        . 'Any previously generated tokens were cleared — click "Send Tokens" to generate new ones.');
                    header('Location: admin_meetings.php?action=voter_register&id=' . $meetingId); exit;
                } catch (\Throwable $e) {
                    $pdo->rollBack();
                    $errors[] = 'Database error: ' . $e->getMessage();
                }
            }
        }
    }

    // Current register
    $stmt = db()->prepare(
        "SELECT veo.*,
                vt.token, vt.sent_at, vt.used_at, vt.device_token
         FROM vote_eligible_owners veo
         LEFT JOIN vote_tokens vt
                ON vt.meeting_id = veo.meeting_id AND vt.erf_number = veo.erf_number
         WHERE veo.meeting_id = ?
         ORDER BY veo.erf_number"
    );
    $stmt->execute([$meetingId]);
    $register = $stmt->fetchAll();

    pageHeader('Voter Register', 'admin');
    renderHeader('📋 Voter Register — ' . htmlspecialchars($meeting['title']), 'logout.php');
    ?>

    <main class="pc-main">
      <div class="card card-wide">
        <h2 class="card-title">📋 Voter Register — <?= htmlspecialchars($meeting['title']) ?></h2>

        <?= getFlash() ?>

        <?php if (!empty($errors)): ?>
          <div class="alert alert-danger">
            <?php foreach ($errors as $e): ?><p><?= htmlspecialchars($e) ?></p><?php endforeach; ?>
          </div>
        <?php endif; ?>

        <div class="alert alert-info" style="font-size:.88rem;margin-bottom:16px;">
          Upload the levy roll as a CSV or Excel (.xlsx) file with columns: <strong>Erf, Owner Name, Email, Phone</strong>
          (a header row is optional and will be detected automatically).
          Re-uploading <strong>replaces</strong> the entire register for this meeting and
          clears any tokens already generated — use this to correct mistakes
          <em>before</em> clicking "Send Tokens".
        </div>

        <form method="POST" enctype="multipart/form-data" style="margin-bottom:24px;">
          <?= csrfField() ?>
          <div class="form-group">
            <label>Levy Roll (CSV or Excel)</label>
            <input type="file" name="levy_csv" accept=".csv,.txt,.xlsx" required>
          </div>
          <div class="btn-group">
            <button type="submit" class="btn btn-primary">Upload / Replace Register</button>
            <a href="admin_meetings.php?action=list" class="btn btn-navy">← Back to Meetings</a>
          </div>
        </form>

        <?php if (!empty($register)): ?>
          <h3 style="margin-bottom:8px;">
            Current Register — <?= count($register) ?> erf(s)
          </h3>
          <div class="table-responsive">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Erf</th>
                  <th>Owner Name</th>
                  <th>Email</th>
                  <th>Phone</th>
                  <th>Token Status</th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($register as $r): ?>
                <tr>
                  <td><strong><?= htmlspecialchars($r['erf_number']) ?></strong></td>
                  <td><?= htmlspecialchars($r['owner_name']) ?></td>
                  <td><?= htmlspecialchars($r['owner_email']) ?></td>
                  <td><?= htmlspecialchars($r['owner_phone'] ?? '') ?></td>
                  <td style="font-size:.82rem;">
                    <?php if (!$r['token']): ?>
                      <span class="muted-note">Not generated</span>
                    <?php elseif ($r['used_at']): ?>
                      <span class="badge badge-green">Used — device locked</span>
                    <?php elseif ($r['sent_at']): ?>
                      <span class="badge badge-amber">Sent, not yet used</span>
                    <?php else: ?>
                      <span class="muted-note">Generated, not sent</span>
                    <?php endif; ?>
                  </td>
                </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        <?php else: ?>
          <p class="muted-note">No voter register uploaded yet for this meeting.</p>
        <?php endif; ?>

      </div>
    </main>

    <?php pageFooter(); exit;
}

// ============================================================
// SEND TOKENS — generate (if needed) and email tokens to
// owner_email from the levy roll register
// ============================================================
if ($action === 'send_tokens' && $meetingId > 0) {

    $meeting = loadMeeting($meetingId);

    $stmt = db()->prepare("SELECT * FROM vote_eligible_owners WHERE meeting_id = ? ORDER BY erf_number");
    $stmt->execute([$meetingId]);
    $owners = $stmt->fetchAll();

    if (empty($owners)) {
        setFlash('error', 'No voter register found for this meeting. Upload the levy roll CSV first.');
        header('Location: admin_meetings.php?action=voter_register&id=' . $meetingId); exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $mode = $_POST['send_mode'] ?? 'unsent'; // 'unsent' or 'all'

        require_once __DIR__ . '/twilio_helper.php'; // provides mail helper used elsewhere

        $sent  = 0;
        $skip  = 0;
        $sendErrors = [];
        $voteLoginUrl = (defined('SITE_URL') ? SITE_URL : '') . '/vote_login.php';

        foreach ($owners as $o) {
            $erf = $o['erf_number'];

            // Find or create token
            $tstmt = db()->prepare("SELECT * FROM vote_tokens WHERE meeting_id=? AND erf_number=?");
            $tstmt->execute([$meetingId, $erf]);
            $vt = $tstmt->fetch();

            if ($vt && $vt['sent_at'] && $mode === 'unsent') {
                $skip++;
                continue;
            }

            if (!$vt) {
                // Generate a unique 6-digit token for this meeting
                do {
                    $token = (string)random_int(100000, 999999);
                    $chk = db()->prepare("SELECT id FROM vote_tokens WHERE meeting_id=? AND token=?");
                    $chk->execute([$meetingId, $token]);
                } while ($chk->fetch());

                db()->prepare(
                    "INSERT INTO vote_tokens (meeting_id, erf_number, token) VALUES (?,?,?)"
                )->execute([$meetingId, $erf, $token]);
            } else {
                $token = $vt['token'];
                // Don't regenerate or resend if already used (device-locked)
                if ($vt['used_at']) {
                    $skip++;
                    continue;
                }
            }

            // ── Email the registered owner (levy roll email — NOT resident portal email) ──
            $subject = 'Your Voting Token - ' . $meeting['title'];
            $body    = "Dear " . $o['owner_name'] . ",\n\n"
                     . "You are eligible to vote in: " . $meeting['title'] . "\n\n"
                     . "Erf Number: " . $erf . "\n"
                     . "Voting Token: " . $token . "\n\n"
                     . "To cast your vote, go to:\n" . $voteLoginUrl . "\n\n"
                     . "Enter your erf number and the 6-digit token above.\n"
                     . "This token can only be used once, from one device.\n\n"
                     . "Regards,\nGEMB HOA Board";

            $ok = sendEmail($o['owner_email'], $subject, $body);
            if ($ok) {
                db()->prepare("UPDATE vote_tokens SET sent_at=NOW() WHERE meeting_id=? AND erf_number=?")
                    ->execute([$meetingId, $erf]);
                $sent++;
            } else {
                $sendErrors[] = $erf . ': sendEmail() returned false (mail() failed — check server mail config/logs)';
                $skip++;
            }
        }

        $msg = "Tokens sent: {$sent}. Skipped (already sent/used): {$skip}.";
        if (!empty($sendErrors)) {
            $msg .= ' [DEBUG errors: ' . implode(' | ', array_slice($sendErrors, 0, 5)) . ']';
        }
        setFlash('success', $msg);
        header('Location: admin_meetings.php?action=voter_register&id=' . $meetingId); exit;
    }

    // Counts for the confirmation screen
    $tstmt = db()->prepare(
        "SELECT
           SUM(CASE WHEN token IS NULL THEN 1 ELSE 0 END) AS not_generated,
           SUM(CASE WHEN token IS NOT NULL AND sent_at IS NULL THEN 1 ELSE 0 END) AS not_sent,
           SUM(CASE WHEN sent_at IS NOT NULL AND used_at IS NULL THEN 1 ELSE 0 END) AS sent_unused,
           SUM(CASE WHEN used_at IS NOT NULL THEN 1 ELSE 0 END) AS used
         FROM vote_eligible_owners veo
         LEFT JOIN vote_tokens vt ON vt.meeting_id = veo.meeting_id AND vt.erf_number = veo.erf_number
         WHERE veo.meeting_id = ?"
    );
    $tstmt->execute([$meetingId]);
    $counts = $tstmt->fetch();

    pageHeader('Send Tokens', 'admin');
    renderHeader('✉️ Send Tokens — ' . htmlspecialchars($meeting['title']), 'logout.php');
    ?>

    <main class="pc-main">
      <div class="card card-wide">
        <h2 class="card-title">✉️ Send Voting Tokens — <?= htmlspecialchars($meeting['title']) ?></h2>

        <?= getFlash() ?>

        <div class="alert alert-info" style="font-size:.88rem;margin-bottom:16px;">
          Tokens are emailed to the <strong>registered owner email from the levy roll</strong>
          (not the resident portal email). Each erf gets one 6-digit token covering
          <strong>all motions</strong> in this meeting. The token is permanently
          locked to the first device used to enter it.
        </div>

        <table class="data-table" style="max-width:480px;margin-bottom:20px;">
          <tr><td>Not yet generated</td><td><strong><?= (int)($counts['not_generated'] ?? 0) ?></strong></td></tr>
          <tr><td>Generated, not sent</td><td><strong><?= (int)($counts['not_sent'] ?? 0) ?></strong></td></tr>
          <tr><td>Sent, not yet used</td><td><strong><?= (int)($counts['sent_unused'] ?? 0) ?></strong></td></tr>
          <tr><td>Used (device-locked)</td><td><strong><?= (int)($counts['used'] ?? 0) ?></strong></td></tr>
          <tr><td><strong>Total in register</strong></td><td><strong><?= count($owners) ?></strong></td></tr>
        </table>

        <form method="POST" onsubmit="return confirm('Send voting tokens by email now?')">
          <?= csrfField() ?>
          <div class="form-group">
            <label>
              <input type="radio" name="send_mode" value="unsent" checked>
              Send to erven that have <strong>not yet been sent</strong> a token (recommended)
            </label><br>
            <label>
              <input type="radio" name="send_mode" value="all">
              Resend to <strong>all</strong> erven that haven't used their token yet
              (already-used/device-locked tokens are never resent)
            </label>
          </div>
          <div class="btn-group">
            <button type="submit" class="btn btn-primary">Send Tokens Now</button>
            <a href="admin_meetings.php?action=voter_register&id=<?= $meetingId ?>" class="btn btn-navy">← Back to Register</a>
          </div>
        </form>
      </div>
    </main>

    <?php pageFooter(); exit;
}

// ============================================================
// Fallback
// ============================================================
header('Location: admin_meetings.php?action=list');
exit;