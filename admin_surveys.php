<?php
// ============================================================
// admin_surveys.php — Survey Module (Admin only)
// GEMB Access Control System
// Version 1.1  |  2026-06-13
//
// Actions:
//   list        — view all surveys (default)
//   create      — form to create a new survey + questions
//   edit        — edit survey title/description/dates
//   questions   — manage questions for a survey
//   activate    — change status draft→active
//   close       — change status active→closed
//   delete      — delete survey (draft/closed only)
//   results     — view response summary (read-only)
//   csv_summary — download summary CSV (counts + percentages)
//   csv_rawdata — download raw data CSV (one row per respondent)
//
// Security:
//   requireAdmin() enforces admin session at chokepoint
//   CSRF token on every POST form
//   PDO prepared statements throughout
//   htmlspecialchars() on all output
//   Status transitions validated server-side
// ============================================================

require_once 'layout.php';

if (session_status() === PHP_SESSION_NONE) session_start();

requireAdmin();

$action   = $_GET['action']    ?? 'list';
$surveyId = (int)($_GET['id']  ?? 0);
$adminId  = (int)($_SESSION['admin_id'] ?? 0);
$adminName = htmlspecialchars($_SESSION['admin_name'] ?? 'Admin');

// ============================================================
// LIST — show all surveys
// ============================================================
if ($action === 'list') {

    $stmt = db()->prepare(
        "SELECT s.*,
                (SELECT COUNT(*) FROM survey_questions q WHERE q.survey_id = s.id) AS q_count,
                (SELECT COUNT(*) FROM survey_responses r WHERE r.survey_id = s.id) AS r_count
         FROM surveys s
         ORDER BY s.created_at DESC"
    );
    $stmt->execute();
    $surveys = $stmt->fetchAll();

    pageHeader('Surveys', 'admin');
    renderHeader('📋 Surveys', 'logout.php');
    ?>

    <main class="pc-main">
      <div class="card card-wide">

        <div class="card-toolbar">
          <h2 class="card-title">📋 Survey Management</h2>
          <a href="admin_surveys.php?action=create" class="btn btn-primary">＋ New Survey</a>
        </div>

        <?= getFlash() ?>

        <?php if (empty($surveys)): ?>
          <p class="muted-note">No surveys yet. Click <strong>New Survey</strong> to create one.</p>
        <?php else: ?>

        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Title</th>
                <th>Status</th>
                <th>Questions</th>
                <th>Responses</th>
                <th>Opens</th>
                <th>Closes</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
            <?php foreach ($surveys as $s): ?>
              <?php
                $statusClass = match($s['status']) {
                    'active' => 'badge-green',
                    'closed' => 'badge-grey',
                    default  => 'badge-amber',
                };
              ?>
              <tr>
                <td><?= $s['id'] ?></td>
                <td><strong><?= htmlspecialchars($s['title']) ?></strong></td>
                <td><span class="badge <?= $statusClass ?>"><?= ucfirst($s['status']) ?></span></td>
                <td class="text-center"><?= (int)$s['q_count'] ?></td>
                <td class="text-center"><?= (int)$s['r_count'] ?></td>
                <td><?= $s['starts_at'] ? htmlspecialchars(date('d M Y', strtotime($s['starts_at']))) : '<span class="muted-note">Immediate</span>' ?></td>
                <td><?= $s['ends_at']   ? htmlspecialchars(date('d M Y', strtotime($s['ends_at'])))   : '<span class="muted-note">No end date</span>' ?></td>
                <td>
                  <div class="btn-group-sm">
                    <a href="admin_surveys.php?action=questions&id=<?= $s['id'] ?>" class="btn btn-sm btn-navy">✏️ Questions</a>
                    <a href="admin_surveys.php?action=results&id=<?= $s['id'] ?>"   class="btn btn-sm btn-blue">📊 Results</a>

                    <?php if ($s['status'] === 'draft'): ?>
                      <a href="admin_surveys.php?action=edit&id=<?= $s['id'] ?>" class="btn btn-sm btn-amber">⚙️ Edit</a>
                      <?php if ((int)$s['q_count'] > 0): ?>
                        <form method="POST" action="admin_surveys.php?action=activate&id=<?= $s['id'] ?>" style="display:inline;">
                          <?= csrfField() ?>
                          <button type="submit" class="btn btn-sm btn-green"
                                  onclick="return confirm('Activate this survey? It will become visible to all users.')">
                            ▶ Activate
                          </button>
                        </form>
                      <?php endif; ?>
                      <form method="POST" action="admin_surveys.php?action=delete&id=<?= $s['id'] ?>" style="display:inline;">
                        <?= csrfField() ?>
                        <button type="submit" class="btn btn-sm btn-red"
                                onclick="return confirm('Delete this survey permanently? This cannot be undone.')">
                          🗑 Delete
                        </button>
                      </form>
                    <?php endif; ?>

                    <?php if ($s['status'] === 'active'): ?>
                      <form method="POST" action="admin_surveys.php?action=close&id=<?= $s['id'] ?>" style="display:inline;">
                        <?= csrfField() ?>
                        <button type="submit" class="btn btn-sm btn-red"
                                onclick="return confirm('Close this survey? No further responses will be accepted.')">
                          ⏹ Close
                        </button>
                      </form>
                    <?php endif; ?>

                    <?php if ($s['status'] === 'closed'): ?>
                      <form method="POST" action="admin_surveys.php?action=delete&id=<?= $s['id'] ?>" style="display:inline;">
                        <?= csrfField() ?>
                        <button type="submit" class="btn btn-sm btn-red"
                                onclick="return confirm('Delete this closed survey and all its responses? This cannot be undone.')">
                          🗑 Delete
                        </button>
                      </form>
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
// ACTIVATE — draft → active
// ============================================================
if ($action === 'activate' && $surveyId > 0) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $stmt = db()->prepare(
            "SELECT s.status,
                    (SELECT COUNT(*) FROM survey_questions q WHERE q.survey_id = s.id) AS q_count
             FROM surveys s WHERE s.id = ?"
        );
        $stmt->execute([$surveyId]);
        $row = $stmt->fetch();
        if (!$row) {
            setFlash('error', 'Survey not found.');
        } elseif ($row['status'] !== 'draft') {
            setFlash('error', 'Only draft surveys can be activated.');
        } elseif ((int)$row['q_count'] < 1) {
            setFlash('error', 'Add at least one question before activating.');
        } else {
            db()->prepare("UPDATE surveys SET status = 'active', updated_at = NOW() WHERE id = ? AND status = 'draft'")->execute([$surveyId]);
            setFlash('success', 'Survey activated. It is now visible to all users.');
        }
    }
    header('Location: admin_surveys.php?action=list'); exit;
}

// ============================================================
// CLOSE — active → closed
// ============================================================
if ($action === 'close' && $surveyId > 0) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $upd = db()->prepare("UPDATE surveys SET status = 'closed', updated_at = NOW() WHERE id = ? AND status = 'active'");
        $upd->execute([$surveyId]);
        if ($upd->rowCount() > 0) {
            setFlash('success', 'Survey closed. No further responses will be accepted.');
        } else {
            setFlash('error', 'Survey could not be closed. It may already be closed.');
        }
    }
    header('Location: admin_surveys.php?action=list'); exit;
}

// ============================================================
// DELETE — draft or closed surveys only
// ============================================================
if ($action === 'delete' && $surveyId > 0) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $check = db()->prepare("SELECT status FROM surveys WHERE id = ?");
        $check->execute([$surveyId]);
        $row = $check->fetch();
        if (!$row) {
            setFlash('error', 'Survey not found.');
        } elseif ($row['status'] === 'active') {
            setFlash('error', 'Close the survey before deleting it.');
        } else {
            db()->prepare("DELETE sa FROM survey_answers sa JOIN survey_responses sr ON sa.response_id = sr.id WHERE sr.survey_id = ?")->execute([$surveyId]);
            db()->prepare("DELETE FROM survey_responses WHERE survey_id = ?")->execute([$surveyId]);
            db()->prepare("DELETE FROM survey_questions WHERE survey_id = ?")->execute([$surveyId]);
            db()->prepare("DELETE FROM surveys WHERE id = ? AND status != 'active'")->execute([$surveyId]);
            setFlash('success', 'Survey and all associated data deleted.');
        }
    }
    header('Location: admin_surveys.php?action=list'); exit;
}

// ============================================================
// CREATE — new survey form
// ============================================================
if ($action === 'create') {

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $title       = trim($_POST['title']       ?? '');
        $description = trim($_POST['description'] ?? '');
        $starts_at   = trim($_POST['starts_at']   ?? '');
        $ends_at     = trim($_POST['ends_at']     ?? '');
        $errors = [];
        if ($title === '') $errors[] = 'Survey title is required.';
        if (strlen($title) > 255) $errors[] = 'Title must be 255 characters or fewer.';
        if ($ends_at !== '' && $starts_at !== '' && $ends_at <= $starts_at) {
            $errors[] = 'End date must be after start date.';
        }
        if (empty($errors)) {
            $ins = db()->prepare("INSERT INTO surveys (title, description, status, created_by, starts_at, ends_at) VALUES (?, ?, 'draft', ?, ?, ?)");
            $ins->execute([$title, $description ?: null, $adminId, $starts_at ?: null, $ends_at ?: null]);
            $newId = db()->lastInsertId();
            setFlash('success', 'Survey created. Now add your questions.');
            header("Location: admin_surveys.php?action=questions&id={$newId}"); exit;
        }
    }

    pageHeader('Create Survey', 'admin');
    renderHeader('📋 Create Survey', 'logout.php');
    ?>

    <main class="pc-main">
      <div class="card card-wide">
        <h2 class="card-title">📋 New Survey</h2>

        <?php if (!empty($errors)): ?>
          <div class="alert alert-error">
            <?php foreach ($errors as $e): ?><p><?= htmlspecialchars($e) ?></p><?php endforeach; ?>
          </div>
        <?php endif; ?>

        <?= getFlash() ?>

        <form method="POST">
          <?= csrfField() ?>
          <div class="form-group">
            <label for="title">Survey Title <span class="required">*</span></label>
            <input type="text" id="title" name="title" maxlength="255" required
                   value="<?= htmlspecialchars($_POST['title'] ?? '') ?>">
          </div>
          <div class="form-group">
            <label for="description">Description / Instructions <span class="muted-note">(optional)</span></label>
            <textarea id="description" name="description" rows="3" maxlength="1000"
                      placeholder="Explain the purpose of this survey to respondents..."><?= htmlspecialchars($_POST['description'] ?? '') ?></textarea>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label for="starts_at">Opens <span class="muted-note">(leave blank = open immediately on activation)</span></label>
              <input type="datetime-local" id="starts_at" name="starts_at" value="<?= htmlspecialchars($_POST['starts_at'] ?? '') ?>">
            </div>
            <div class="form-group">
              <label for="ends_at">Closes <span class="muted-note">(leave blank = no auto-close)</span></label>
              <input type="datetime-local" id="ends_at" name="ends_at" value="<?= htmlspecialchars($_POST['ends_at'] ?? '') ?>">
            </div>
          </div>
          <div class="btn-group" style="margin-top:16px;">
            <button type="submit" class="btn btn-primary">Create Survey →</button>
            <a href="admin_surveys.php?action=list" class="btn btn-navy">Cancel</a>
          </div>
        </form>
      </div>
    </main>

    <?php pageFooter(); exit;
}

// ============================================================
// EDIT — update title/description/dates (draft only)
// ============================================================
if ($action === 'edit' && $surveyId > 0) {

    $stmt = db()->prepare("SELECT * FROM surveys WHERE id = ?");
    $stmt->execute([$surveyId]);
    $survey = $stmt->fetch();

    if (!$survey) { setFlash('error', 'Survey not found.'); header('Location: admin_surveys.php?action=list'); exit; }
    if ($survey['status'] !== 'draft') { setFlash('error', 'Only draft surveys can be edited.'); header('Location: admin_surveys.php?action=list'); exit; }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $title       = trim($_POST['title']       ?? '');
        $description = trim($_POST['description'] ?? '');
        $starts_at   = trim($_POST['starts_at']   ?? '');
        $ends_at     = trim($_POST['ends_at']     ?? '');
        $errors = [];
        if ($title === '') $errors[] = 'Survey title is required.';
        if (strlen($title) > 255) $errors[] = 'Title must be 255 characters or fewer.';
        if ($ends_at !== '' && $starts_at !== '' && $ends_at <= $starts_at) $errors[] = 'End date must be after start date.';
        if (empty($errors)) {
            db()->prepare("UPDATE surveys SET title=?, description=?, starts_at=?, ends_at=?, updated_at=NOW() WHERE id=? AND status='draft'")
               ->execute([$title, $description ?: null, $starts_at ?: null, $ends_at ?: null, $surveyId]);
            setFlash('success', 'Survey updated.');
            header("Location: admin_surveys.php?action=list"); exit;
        }
        $survey['title']       = $_POST['title']       ?? '';
        $survey['description'] = $_POST['description'] ?? '';
        $survey['starts_at']   = $_POST['starts_at']   ?? '';
        $survey['ends_at']     = $_POST['ends_at']     ?? '';
    }

    $startsVal = $survey['starts_at'] ? date('Y-m-d\TH:i', strtotime($survey['starts_at'])) : '';
    $endsVal   = $survey['ends_at']   ? date('Y-m-d\TH:i', strtotime($survey['ends_at']))   : '';

    pageHeader('Edit Survey', 'admin');
    renderHeader('📋 Edit Survey', 'logout.php');
    ?>

    <main class="pc-main">
      <div class="card card-wide">
        <h2 class="card-title">⚙️ Edit Survey — <?= htmlspecialchars($survey['title']) ?></h2>

        <?php if (!empty($errors)): ?>
          <div class="alert alert-error">
            <?php foreach ($errors as $e): ?><p><?= htmlspecialchars($e) ?></p><?php endforeach; ?>
          </div>
        <?php endif; ?>

        <form method="POST">
          <?= csrfField() ?>
          <div class="form-group">
            <label for="title">Survey Title <span class="required">*</span></label>
            <input type="text" id="title" name="title" maxlength="255" required value="<?= htmlspecialchars($survey['title']) ?>">
          </div>
          <div class="form-group">
            <label for="description">Description / Instructions</label>
            <textarea id="description" name="description" rows="3" maxlength="1000"><?= htmlspecialchars($survey['description'] ?? '') ?></textarea>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label for="starts_at">Opens</label>
              <input type="datetime-local" id="starts_at" name="starts_at" value="<?= htmlspecialchars($startsVal) ?>">
            </div>
            <div class="form-group">
              <label for="ends_at">Closes</label>
              <input type="datetime-local" id="ends_at" name="ends_at" value="<?= htmlspecialchars($endsVal) ?>">
            </div>
          </div>
          <div class="btn-group" style="margin-top:16px;">
            <button type="submit" class="btn btn-primary">Save Changes</button>
            <a href="admin_surveys.php?action=questions&id=<?= $surveyId ?>" class="btn btn-navy">Manage Questions</a>
            <a href="admin_surveys.php?action=list" class="btn btn-navy">← Back to Surveys</a>
          </div>
        </form>
      </div>
    </main>

    <?php pageFooter(); exit;
}

// ============================================================
// QUESTIONS — add / delete questions for a survey
// ============================================================
if ($action === 'questions' && $surveyId > 0) {

    $stmt = db()->prepare("SELECT * FROM surveys WHERE id = ?");
    $stmt->execute([$surveyId]);
    $survey = $stmt->fetch();
    if (!$survey) { setFlash('error', 'Survey not found.'); header('Location: admin_surveys.php?action=list'); exit; }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['sub_action'] ?? '') === 'add_question') {
        verifyCsrfToken();
        $qtext = trim($_POST['question_text'] ?? '');
        $qtype = trim($_POST['question_type'] ?? '');
        $reqd  = isset($_POST['is_required']) ? 1 : 0;
        $opts  = trim($_POST['options_raw']   ?? '');
        $validTypes = ['single_choice','multi_choice','text','rating','yes_no'];
        $qerrors = [];
        if ($qtext === '') $qerrors[] = 'Question text is required.';
        if (!in_array($qtype, $validTypes)) $qerrors[] = 'Invalid question type.';
        if (in_array($qtype, ['single_choice','multi_choice'])) {
            $optArr = array_filter(array_map('trim', explode("\n", $opts)));
            if (count($optArr) < 2) $qerrors[] = 'Provide at least 2 options (one per line).';
        }
        if (empty($qerrors)) {
            $maxOrd = db()->prepare("SELECT COALESCE(MAX(sort_order),0)+1 FROM survey_questions WHERE survey_id=?");
            $maxOrd->execute([$surveyId]);
            $nextOrd = (int)$maxOrd->fetchColumn();
            $optJson = null;
            if (in_array($qtype, ['single_choice','multi_choice'])) {
                $optJson = json_encode(array_values($optArr));
            }
            db()->prepare("INSERT INTO survey_questions (survey_id, sort_order, question_text, question_type, is_required, options_json) VALUES (?, ?, ?, ?, ?, ?)")
               ->execute([$surveyId, $nextOrd, $qtext, $qtype, $reqd, $optJson]);
            setFlash('success', 'Question added.');
        } else {
            $_SESSION['qerrors'] = $qerrors;
            $_SESSION['qpost']   = $_POST;
        }
        header("Location: admin_surveys.php?action=questions&id={$surveyId}"); exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['sub_action'] ?? '') === 'delete_question') {
        verifyCsrfToken();
        $qid = (int)($_POST['question_id'] ?? 0);
        if ($qid > 0) {
            if ($survey['status'] === 'draft') {
                db()->prepare("DELETE FROM survey_questions WHERE id=? AND survey_id=?")->execute([$qid, $surveyId]);
                setFlash('success', 'Question removed.');
            } else {
                setFlash('error', 'Questions cannot be deleted from an active or closed survey.');
            }
        }
        header("Location: admin_surveys.php?action=questions&id={$surveyId}"); exit;
    }

    $qstmt = db()->prepare("SELECT * FROM survey_questions WHERE survey_id=? ORDER BY sort_order ASC");
    $qstmt->execute([$surveyId]);
    $questions = $qstmt->fetchAll();

    $qerrors = $_SESSION['qerrors'] ?? [];
    $qpost   = $_SESSION['qpost']   ?? [];
    unset($_SESSION['qerrors'], $_SESSION['qpost']);

    $questionTypes = [
        'yes_no'        => '✔️ Yes / No',
        'single_choice' => '🔘 Single Choice',
        'multi_choice'  => '☑️ Multiple Choice',
        'rating'        => '⭐ Rating (1–5)',
        'text'          => '📝 Free Text',
    ];

    $editable = ($survey['status'] === 'draft');

    pageHeader('Survey Questions', 'admin');
    renderHeader('📋 Questions', 'logout.php');
    ?>

    <main class="pc-main">

      <div class="card card-wide" style="margin-bottom:16px;">
        <div class="card-toolbar">
          <div>
            <h2 class="card-title" style="margin-bottom:4px;"><?= htmlspecialchars($survey['title']) ?></h2>
            <span class="badge <?= $survey['status'] === 'active' ? 'badge-green' : ($survey['status'] === 'closed' ? 'badge-grey' : 'badge-amber') ?>">
              <?= ucfirst($survey['status']) ?>
            </span>
            <?php if ($survey['description']): ?>
              <p class="muted-note" style="margin-top:8px;"><?= htmlspecialchars($survey['description']) ?></p>
            <?php endif; ?>
          </div>
          <?php if ($editable): ?>
            <a href="admin_surveys.php?action=edit&id=<?= $surveyId ?>" class="btn btn-amber">⚙️ Edit Details</a>
          <?php endif; ?>
        </div>
      </div>

      <div class="card card-wide" style="margin-bottom:16px;">
        <h3 class="section-title">Questions (<?= count($questions) ?>)</h3>
        <?= getFlash() ?>
        <?php if (empty($questions)): ?>
          <p class="muted-note">No questions yet. Add the first question below.</p>
        <?php else: ?>
          <?php foreach ($questions as $i => $q): ?>
            <div class="question-row">
              <div class="question-meta">
                <span class="q-number"><?= $q['sort_order'] ?>.</span>
                <span class="badge badge-blue"><?= htmlspecialchars($questionTypes[$q['question_type']] ?? $q['question_type']) ?></span>
                <?php if (!$q['is_required']): ?><span class="badge badge-grey">Optional</span><?php endif; ?>
              </div>
              <p class="question-text"><?= htmlspecialchars($q['question_text']) ?></p>
              <?php if ($q['options_json']): ?>
                <?php $opts = json_decode($q['options_json'], true) ?? []; ?>
                <ul class="option-list">
                  <?php foreach ($opts as $opt): ?><li><?= htmlspecialchars($opt) ?></li><?php endforeach; ?>
                </ul>
              <?php endif; ?>
              <?php if ($editable): ?>
                <form method="POST" style="margin-top:8px;">
                  <?= csrfField() ?>
                  <input type="hidden" name="sub_action"  value="delete_question">
                  <input type="hidden" name="question_id" value="<?= $q['id'] ?>">
                  <button type="submit" class="btn btn-sm btn-red"
                          onclick="return confirm('Remove this question?')">🗑 Remove</button>
                </form>
              <?php endif; ?>
            </div>
            <?php if ($i < count($questions)-1): ?><hr class="q-divider"><?php endif; ?>
          <?php endforeach; ?>
        <?php endif; ?>
      </div>

      <?php if ($editable): ?>
      <div class="card card-wide">
        <h3 class="section-title">Add Question</h3>
        <?php if (!empty($qerrors)): ?>
          <div class="alert alert-error">
            <?php foreach ($qerrors as $e): ?><p><?= htmlspecialchars($e) ?></p><?php endforeach; ?>
          </div>
        <?php endif; ?>
        <form method="POST" id="addQForm">
          <?= csrfField() ?>
          <input type="hidden" name="sub_action" value="add_question">
          <div class="form-group">
            <label for="question_text">Question <span class="required">*</span></label>
            <textarea id="question_text" name="question_text" rows="2" required
                      maxlength="1000"><?= htmlspecialchars($qpost['question_text'] ?? '') ?></textarea>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label for="question_type">Type <span class="required">*</span></label>
              <select id="question_type" name="question_type" required onchange="toggleOptions(this.value)">
                <option value="">— Select type —</option>
                <?php foreach ($questionTypes as $val => $label): ?>
                  <option value="<?= $val ?>" <?= ($qpost['question_type'] ?? '') === $val ? 'selected' : '' ?>><?= $label ?></option>
                <?php endforeach; ?>
              </select>
            </div>
            <div class="form-group" style="display:flex;align-items:flex-end;padding-bottom:4px;">
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
                <input type="checkbox" name="is_required" value="1"
                       <?= isset($qpost['is_required']) ? 'checked' : 'checked' ?>>
                Required question
              </label>
            </div>
          </div>
          <div class="form-group" id="optionsGroup" style="display:none;">
            <label for="options_raw">Answer Options <span class="required">*</span>
              <span class="muted-note">(one option per line)</span>
            </label>
            <textarea id="options_raw" name="options_raw" rows="4"
                      placeholder="Option A&#10;Option B&#10;Option C"><?= htmlspecialchars($qpost['options_raw'] ?? '') ?></textarea>
          </div>
          <div class="btn-group" style="margin-top:12px;">
            <button type="submit" class="btn btn-primary">＋ Add Question</button>
          </div>
        </form>
      </div>
      <?php endif; ?>

      <div class="card card-wide" style="margin-top:16px;">
        <div class="btn-group">
          <?php if ($editable && count($questions) > 0): ?>
            <form method="POST" action="admin_surveys.php?action=activate&id=<?= $surveyId ?>" style="display:inline;">
              <?= csrfField() ?>
              <button type="submit" class="btn btn-green"
                      onclick="return confirm('Activate this survey now? It will be visible to all users.')">
                ▶ Activate Survey
              </button>
            </form>
          <?php endif; ?>
          <a href="admin_surveys.php?action=list" class="btn btn-navy">← Back to Surveys</a>
        </div>
      </div>

    </main>

    <script>
    function toggleOptions(type) {
        const g = document.getElementById('optionsGroup');
        g.style.display = (type === 'single_choice' || type === 'multi_choice') ? 'block' : 'none';
    }
    (function(){ const sel = document.getElementById('question_type'); if (sel) toggleOptions(sel.value); })();
    </script>

    <?php pageFooter(); exit;
}

// ============================================================
// CSV HELPER
// ============================================================
function csvRow(array $fields): string {
    return implode(',', array_map(function($f) {
        $f = str_replace('"', '""', $f ?? '');
        return '"' . $f . '"';
    }, $fields)) . "\r\n";
}

// ============================================================
// DOWNLOAD SUMMARY CSV
// ============================================================
if ($action === 'csv_summary' && $surveyId > 0) {
    $stmt = db()->prepare("SELECT * FROM surveys WHERE id = ?");
    $stmt->execute([$surveyId]);
    $survey = $stmt->fetch();
    if (!$survey) { header('Location: admin_surveys.php?action=list'); exit; }

    $qstmt = db()->prepare("SELECT * FROM survey_questions WHERE survey_id=? ORDER BY sort_order");
    $qstmt->execute([$surveyId]);
    $questions = $qstmt->fetchAll();

    $cntStmt = db()->prepare("SELECT COUNT(*) FROM survey_responses WHERE survey_id=?");
    $cntStmt->execute([$surveyId]);
    $totalResponses = (int)$cntStmt->fetchColumn();

    $filename = 'survey_' . $surveyId . '_summary_' . date('Ymd') . '.csv';
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Pragma: no-cache');

    $out = fopen('php://output', 'w');
    fputs($out, "\xEF\xBB\xBF");
    fwrite($out, csvRow(['Survey', $survey['title']]));
    fwrite($out, csvRow(['Status', ucfirst($survey['status'])]));
    fwrite($out, csvRow(['Total Responses', $totalResponses]));
    fwrite($out, csvRow(['Generated', date('d M Y H:i')]));
    fwrite($out, csvRow([]));

    foreach ($questions as $q) {
        fwrite($out, csvRow(['Question ' . $q['sort_order'], $q['question_text'], 'Type: ' . $q['question_type']]));
        if (in_array($q['question_type'], ['yes_no', 'single_choice'])) {
            $aStmt = db()->prepare("SELECT a.answer_option, COUNT(*) AS cnt FROM survey_answers a JOIN survey_responses r ON a.response_id = r.id WHERE r.survey_id=? AND a.question_id=? GROUP BY a.answer_option ORDER BY cnt DESC");
            $aStmt->execute([$surveyId, $q['id']]);
            $aRows  = $aStmt->fetchAll();
            $aTotal = array_sum(array_column($aRows, 'cnt'));
            fwrite($out, csvRow(['Option', 'Count', 'Percentage']));
            foreach ($aRows as $ar) {
                $pct = $aTotal > 0 ? round($ar['cnt'] / $aTotal * 100, 1) : 0;
                fwrite($out, csvRow([$ar['answer_option'] ?? '(blank)', $ar['cnt'], $pct . '%']));
            }
        } elseif ($q['question_type'] === 'multi_choice') {
            $aStmt = db()->prepare("SELECT a.answer_json FROM survey_answers a JOIN survey_responses r ON a.response_id = r.id WHERE r.survey_id=? AND a.question_id=?");
            $aStmt->execute([$surveyId, $q['id']]);
            $tally = [];
            foreach ($aStmt->fetchAll() as $ar) {
                foreach (json_decode($ar['answer_json'], true) ?? [] as $o) { $tally[$o] = ($tally[$o] ?? 0) + 1; }
            }
            arsort($tally);
            fwrite($out, csvRow(['Option', 'Selections']));
            foreach ($tally as $opt => $cnt) { fwrite($out, csvRow([$opt, $cnt])); }
        } elseif ($q['question_type'] === 'rating') {
            $aStmt = db()->prepare("SELECT AVG(a.answer_rating) AS avg_r, COUNT(*) AS cnt FROM survey_answers a JOIN survey_responses r ON a.response_id = r.id WHERE r.survey_id=? AND a.question_id=? AND a.answer_rating IS NOT NULL");
            $aStmt->execute([$surveyId, $q['id']]);
            $rRow = $aStmt->fetch();
            fwrite($out, csvRow(['Average Rating', number_format((float)$rRow['avg_r'], 2) . ' / 5', 'Responses: ' . $rRow['cnt']]));
        } elseif ($q['question_type'] === 'text') {
            $aStmt = db()->prepare("SELECT COUNT(*) FROM survey_answers a JOIN survey_responses r ON a.response_id = r.id WHERE r.survey_id=? AND a.question_id=? AND a.answer_text IS NOT NULL AND a.answer_text != ''");
            $aStmt->execute([$surveyId, $q['id']]);
            fwrite($out, csvRow(['Text responses received', $aStmt->fetchColumn(), '(see raw data CSV)']));
        }
        fwrite($out, csvRow([]));
    }
    fclose($out);
    exit;
}

// ============================================================
// DOWNLOAD RAW DATA CSV
// ============================================================
if ($action === 'csv_rawdata' && $surveyId > 0) {
    $stmt = db()->prepare("SELECT * FROM surveys WHERE id = ?");
    $stmt->execute([$surveyId]);
    $survey = $stmt->fetch();
    if (!$survey) { header('Location: admin_surveys.php?action=list'); exit; }

    $qstmt = db()->prepare("SELECT * FROM survey_questions WHERE survey_id=? ORDER BY sort_order");
    $qstmt->execute([$surveyId]);
    $questions = $qstmt->fetchAll();

    $rStmt = db()->prepare("SELECT * FROM survey_responses WHERE survey_id=? ORDER BY submitted_at ASC");
    $rStmt->execute([$surveyId]);
    $responses = $rStmt->fetchAll();

    $filename = 'survey_' . $surveyId . '_rawdata_' . date('Ymd') . '.csv';
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Pragma: no-cache');

    $out = fopen('php://output', 'w');
    fputs($out, "\xEF\xBB\xBF");

    $headerRow = ['Erf', 'Role', 'Submitted'];
    foreach ($questions as $q) { $headerRow[] = 'Q' . $q['sort_order'] . ': ' . $q['question_text']; }
    fwrite($out, csvRow($headerRow));

    foreach ($responses as $r) {
        $aStmt = db()->prepare("SELECT question_id, answer_text, answer_option, answer_json, answer_rating FROM survey_answers WHERE response_id=?");
        $aStmt->execute([$r['id']]);
        $answerMap = [];
        foreach ($aStmt->fetchAll() as $a) { $answerMap[$a['question_id']] = $a; }

        $row = [$r['erf_number'] ?? '', $r['user_role'] ?? '', date('d M Y H:i', strtotime($r['submitted_at']))];
        foreach ($questions as $q) {
            $a = $answerMap[$q['id']] ?? null;
            if (!$a) { $row[] = ''; continue; }
            switch ($q['question_type']) {
                case 'text':         $row[] = $a['answer_text']   ?? ''; break;
                case 'yes_no':
                case 'single_choice': $row[] = $a['answer_option'] ?? ''; break;
                case 'multi_choice':
                    $opts = json_decode($a['answer_json'] ?? '[]', true) ?? [];
                    $row[] = implode('; ', $opts); break;
                case 'rating':       $row[] = $a['answer_rating']  ?? ''; break;
                default:             $row[] = '';
            }
        }
        fwrite($out, csvRow($row));
    }
    fclose($out);
    exit;
}

// ============================================================
// RESULTS — read-only response summary + CSV download buttons
// ============================================================
if ($action === 'results' && $surveyId > 0) {

    $stmt = db()->prepare("SELECT * FROM surveys WHERE id = ?");
    $stmt->execute([$surveyId]);
    $survey = $stmt->fetch();
    if (!$survey) { setFlash('error', 'Survey not found.'); header('Location: admin_surveys.php?action=list'); exit; }

    $cntStmt = db()->prepare("SELECT COUNT(*) FROM survey_responses WHERE survey_id=?");
    $cntStmt->execute([$surveyId]);
    $totalResponses = (int)$cntStmt->fetchColumn();

    $qstmt = db()->prepare("SELECT * FROM survey_questions WHERE survey_id=? ORDER BY sort_order");
    $qstmt->execute([$surveyId]);
    $questions = $qstmt->fetchAll();

    $questionTypes = [
        'yes_no'        => '✔️ Yes / No',
        'single_choice' => '🔘 Single Choice',
        'multi_choice'  => '☑️ Multiple Choice',
        'rating'        => '⭐ Rating',
        'text'          => '📝 Free Text',
    ];

    pageHeader('Survey Results', 'admin');
    renderHeader('📊 Results', 'logout.php');
    ?>

    <main class="pc-main">

      <div class="card card-wide" style="margin-bottom:16px;">
        <div class="card-toolbar">
          <div>
            <h2 class="card-title">📊 Results — <?= htmlspecialchars($survey['title']) ?></h2>
            <p style="margin-top:4px;">
              <span class="badge <?= $survey['status'] === 'active' ? 'badge-green' : ($survey['status'] === 'closed' ? 'badge-grey' : 'badge-amber') ?>">
                <?= ucfirst($survey['status']) ?>
              </span>
              &nbsp; <strong><?= $totalResponses ?></strong> response<?= $totalResponses !== 1 ? 's' : '' ?> received.
            </p>
          </div>
          <?php if ($totalResponses > 0): ?>
          <div class="btn-group">
            <a href="admin_surveys.php?action=csv_summary&id=<?= $surveyId ?>" class="btn btn-green">⬇ Summary CSV</a>
            <a href="admin_surveys.php?action=csv_rawdata&id=<?= $surveyId ?>" class="btn btn-blue">⬇ Raw Data CSV</a>
          </div>
          <?php endif; ?>
        </div>
      </div>

      <?php if ($totalResponses === 0): ?>
        <div class="card card-wide"><p class="muted-note">No responses have been submitted yet.</p></div>
      <?php else: ?>
        <?php foreach ($questions as $q): ?>
          <div class="card card-wide" style="margin-bottom:16px;">
            <div class="question-meta">
              <span class="q-number"><?= $q['sort_order'] ?>.</span>
              <span class="badge badge-blue"><?= htmlspecialchars($questionTypes[$q['question_type']] ?? '') ?></span>
            </div>
            <p class="question-text"><?= htmlspecialchars($q['question_text']) ?></p>

            <?php if (in_array($q['question_type'], ['yes_no','single_choice'])): ?>
              <?php
                $aStmt = db()->prepare("SELECT a.answer_option, COUNT(*) AS cnt FROM survey_answers a JOIN survey_responses r ON a.response_id = r.id WHERE r.survey_id=? AND a.question_id=? GROUP BY a.answer_option ORDER BY cnt DESC");
                $aStmt->execute([$surveyId, $q['id']]);
                $aRows  = $aStmt->fetchAll();
                $aTotal = array_sum(array_column($aRows, 'cnt'));
              ?>
              <table class="data-table" style="max-width:480px;margin-top:10px;">
                <thead><tr><th>Option</th><th>Count</th><th>%</th></tr></thead>
                <tbody>
                <?php foreach ($aRows as $ar): ?>
                  <tr>
                    <td><?= htmlspecialchars($ar['answer_option'] ?? '(blank)') ?></td>
                    <td><?= $ar['cnt'] ?></td>
                    <td><?= $aTotal > 0 ? round($ar['cnt'] / $aTotal * 100, 1) : 0 ?>%</td>
                  </tr>
                <?php endforeach; ?>
                </tbody>
              </table>

            <?php elseif ($q['question_type'] === 'multi_choice'): ?>
              <?php
                $aStmt = db()->prepare("SELECT a.answer_json FROM survey_answers a JOIN survey_responses r ON a.response_id = r.id WHERE r.survey_id=? AND a.question_id=?");
                $aStmt->execute([$surveyId, $q['id']]);
                $tally = [];
                foreach ($aStmt->fetchAll() as $ar) {
                    foreach (json_decode($ar['answer_json'], true) ?? [] as $o) { $tally[$o] = ($tally[$o] ?? 0) + 1; }
                }
                arsort($tally);
              ?>
              <table class="data-table" style="max-width:480px;margin-top:10px;">
                <thead><tr><th>Option</th><th>Selections</th></tr></thead>
                <tbody>
                <?php foreach ($tally as $opt => $cnt): ?>
                  <tr><td><?= htmlspecialchars($opt) ?></td><td><?= $cnt ?></td></tr>
                <?php endforeach; ?>
                </tbody>
              </table>

            <?php elseif ($q['question_type'] === 'rating'): ?>
              <?php
                $aStmt = db()->prepare("SELECT AVG(a.answer_rating) AS avg_r, COUNT(*) AS cnt FROM survey_answers a JOIN survey_responses r ON a.response_id = r.id WHERE r.survey_id=? AND a.question_id=? AND a.answer_rating IS NOT NULL");
                $aStmt->execute([$surveyId, $q['id']]);
                $rRow = $aStmt->fetch();
              ?>
              <p style="margin-top:10px;">
                Average rating: <strong><?= number_format((float)$rRow['avg_r'], 1) ?> / 5</strong>
                &nbsp;(<?= $rRow['cnt'] ?> response<?= $rRow['cnt'] != 1 ? 's' : '' ?>)
              </p>

            <?php elseif ($q['question_type'] === 'text'): ?>
              <?php
                $aStmt = db()->prepare("SELECT a.answer_text FROM survey_answers a JOIN survey_responses r ON a.response_id = r.id WHERE r.survey_id=? AND a.question_id=? AND a.answer_text IS NOT NULL AND a.answer_text != '' ORDER BY r.submitted_at DESC LIMIT 50");
                $aStmt->execute([$surveyId, $q['id']]);
                $texts = $aStmt->fetchAll(PDO::FETCH_COLUMN);
              ?>
              <?php if (empty($texts)): ?>
                <p class="muted-note">No text responses yet.</p>
              <?php else: ?>
                <ul class="text-responses" style="margin-top:10px;">
                  <?php foreach ($texts as $t): ?><li><?= htmlspecialchars($t) ?></li><?php endforeach; ?>
                </ul>
              <?php endif; ?>
            <?php endif; ?>

          </div>
        <?php endforeach; ?>
      <?php endif; ?>

      <div class="card card-wide">
        <div class="btn-group">
          <?php if ($totalResponses > 0): ?>
            <a href="admin_surveys.php?action=csv_summary&id=<?= $surveyId ?>" class="btn btn-green">⬇ Summary CSV</a>
            <a href="admin_surveys.php?action=csv_rawdata&id=<?= $surveyId ?>" class="btn btn-blue">⬇ Raw Data CSV</a>
          <?php endif; ?>
          <a href="admin_surveys.php?action=list" class="btn btn-navy">← Back to Surveys</a>
        </div>
      </div>
    </main>

    <?php pageFooter(); exit;
}

// ============================================================
// Fallback
// ============================================================
header('Location: admin_surveys.php?action=list');
exit;