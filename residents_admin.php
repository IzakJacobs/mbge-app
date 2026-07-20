<?php
// ============================================================
// GEMB Access Control — residents_admin.php
// Manages residents with multi-occupant support per erf
//
// Occupant convention:
//   A = primary owner (reassigned on property transfer)
//   B, C, D... = additional occupants, sequential
//   Letters never reused at same erf
//
// residents columns:
//   id, resident_erfno, occupant_code, occupant_type,
//   is_primary, resident_name, address, phone, email,
//   pin_hash, device_token, status, created_at
// ============================================================
require_once __DIR__ . '/layout.php';
if (session_status() === PHP_SESSION_NONE) session_start();
requireAdmin();

$action = $_GET['action'] ?? 'list';

// ── Helper: next available occupant code for an erf ──────
function nextOccupantCode(string $erfno): string {
    $used = db()->prepare(
        "SELECT occupant_code FROM residents
         WHERE resident_erfno = ?
         ORDER BY occupant_code ASC"
    );
    $used->execute([$erfno]);
    $codes = array_column($used->fetchAll(), 'occupant_code');
    foreach (range('A', 'Z') as $letter) {
        if (!in_array($letter, $codes)) return $letter;
    }
    return '?';
}

// ── Helper: occupant type label ───────────────────────────
function occupantTypeLabel(string $type): string {
    return match($type) {
        'owner'           => '🏠 Owner',
        'spouse'          => '💑 Spouse',
        'dependent'       => '👶 Dependent',
        'domestic_worker' => '🧹 Domestic Worker',
        'tenant'          => '🔑 Tenant',
        default           => '👤 Other',
    };
}

// ── Helper: occupant badge colour ────────────────────────
function occupantBadgeClass(string $type): string {
    return match($type) {
        'owner'           => 'badge-success',
        'spouse'          => 'badge-info',
        'dependent'       => 'badge-warning',
        'domestic_worker' => 'badge-muted',
        'tenant'          => 'badge-warning',
        default           => 'badge-muted',
    };
}

// ════════════════════════════════════════════════════════
// DELETE OCCUPANT
// Safety rules:
//   1. Cannot delete primary (A) if other occupants exist
//      — must delete non-primary occupants first
//   2. Deleting the last occupant of an erf removes the erf
//   3. Associated vehicles, visitors, service_providers
//      are NOT deleted — access_log is a permanent audit trail
// ════════════════════════════════════════════════════════
if ($action === 'delete') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        header('Location: residents_admin.php?action=list'); exit;
    }
    verifyCsrfToken();

    $id = (int)($_POST['id'] ?? 0);
    if (!$id) {
        setFlash('error', 'Invalid request.');
        header('Location: residents_admin.php?action=list'); exit;
    }

    // Fetch the occupant
    $res = db()->prepare(
        "SELECT id, resident_erfno, occupant_code, is_primary,
                resident_name
         FROM residents WHERE id = ? LIMIT 1"
    );
    $res->execute([$id]);
    $res = $res->fetch();

    if (!$res) {
        setFlash('error', 'Resident not found.');
        header('Location: residents_admin.php?action=list'); exit;
    }

    $erfno = $res['resident_erfno'];

    // Count total occupants at this erf
    $count = db()->prepare(
        "SELECT COUNT(*) FROM residents WHERE resident_erfno = ?"
    );
    $count->execute([$erfno]);
    $total = (int)$count->fetchColumn();

    // Block: cannot delete primary if others still exist
    if ($res['is_primary'] && $total > 1) {
        setFlash('error',
            "Cannot delete primary resident {$erfno}A while other occupants exist. "
            . "Delete all other occupants first, then delete the primary."
        );
        header('Location: residents_admin.php?action=list'); exit;
    }

    // Delete the occupant record
    db()->prepare("DELETE FROM residents WHERE id = ?")
        ->execute([$id]);

    $name = $res['resident_name'];
    $code = $erfno . $res['occupant_code'];

    if ($total === 1) {
        // Last occupant — erf is now empty
        setFlash('success',
            "Occupant {$code} — {$name} deleted. Erf {$erfno} removed from system."
        );
    } else {
        setFlash('success', "Occupant {$code} — {$name} deleted.");
    }

    header('Location: residents_admin.php?action=list'); exit;
}

// ════════════════════════════════════════════════════════
// LIST — all erfs grouped with their occupants
// ════════════════════════════════════════════════════════
if ($action === 'list') {
    $search = trim($_GET['q'] ?? '');
    if (strlen($search) === 1) $search = ''; // require at least 2 chars
    if ($search) {
        $stmt = db()->prepare(
            "SELECT * FROM residents
             WHERE (resident_erfno LIKE ?
                OR  resident_name  LIKE ?
                OR  phone          LIKE ?)
             ORDER BY resident_erfno, occupant_code"
        );
        $like = "%{$search}%";
        $stmt->execute([$like, $like, $like]);
    } else {
        $stmt = db()->query(
            "SELECT * FROM residents
             ORDER BY resident_erfno, occupant_code"
        );
    }
    $all = $stmt->fetchAll();

    // Group by erf
    $erfs = [];
    foreach ($all as $r) {
        $erfs[$r['resident_erfno']][] = $r;
    }

    pageHeader('Residents', 'admin');
    renderHeader('🏠 Residents', 'admin.php?action=menu');
    ?>
    <div class="container">
      <?= getFlash() ?>

      <!-- Search + Add -->
      <div class="card" style="display:flex;gap:10px;
                               flex-wrap:wrap;align-items:center;">
        <form method="GET" style="flex:1;display:flex;gap:8px;">
          <input type="hidden" name="action" value="list">
          <input type="text" name="q" value="<?= htmlspecialchars($search) ?>"
                 placeholder="Search erf, name or phone… (min 2 chars)"
                 minlength="2"
                 style="flex:1;padding:8px 12px;border:1px solid #dee2e6;
                        border-radius:6px;">
          <button type="submit" class="btn btn-primary">Search</button>
          <?php if ($search): ?>
          <a href="residents_admin.php?action=list" class="btn btn-secondary">Clear</a>
          <?php endif; ?>
        </form>
        <a href="residents_admin.php?action=add"
           class="btn btn-success">+ Add Resident</a>
      </div>

      <!-- Summary -->
      <div style="font-size:.85rem;color:#666;margin-bottom:12px;">
        <?= count($erfs) ?> erfs &nbsp;|&nbsp;
        <?= count($all)  ?> occupants total
        <?php if ($search): ?>
          &nbsp;|&nbsp; Search: <strong><?= htmlspecialchars($search) ?></strong>
        <?php endif; ?>
      </div>

      <!-- Erf cards -->
      <?php foreach ($erfs as $erfno => $occupants):
        $primary = array_values(array_filter(
            $occupants, fn($o) => $o['is_primary']
        ))[0] ?? $occupants[0];
        $total = count($occupants);
      ?>
      <div class="card" style="margin-bottom:14px;">

        <!-- Erf header -->
        <div style="display:flex;justify-content:space-between;
                    align-items:flex-start;flex-wrap:wrap;gap:8px;
                    margin-bottom:12px;">
          <div>
            <span style="font-size:1.1rem;font-weight:700;
                         color:var(--accent);">
              Erf <?= htmlspecialchars($erfno) ?>
            </span>
            <span style="color:#666;font-size:.85rem;margin-left:8px;">
              <?= htmlspecialchars($primary['address'] ?? '') ?>
            </span>
          </div>
          <a href="residents_admin.php?action=add_occupant&erf=<?= urlencode($erfno) ?>"
             class="btn btn-primary btn-sm">
            + Add Occupant
          </a>
        </div>

        <!-- Occupants table -->
        <div class="table-wrap">
          <table>
            <tr>
              <th>Code</th>
              <th>Name</th>
              <th>Type</th>
              <th>Phone</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
            <?php foreach ($occupants as $occ):
              $isPrimary    = (bool)$occ['is_primary'];
              $blockDelete  = $isPrimary && $total > 1;
            ?>
            <tr style="<?= $occ['status'] !== 'active' ? 'opacity:0.6;' : '' ?>">
              <td>
                <span style="font-family:monospace;font-weight:800;
                             font-size:1.05rem;color:var(--accent);">
                  <?= htmlspecialchars($erfno . $occ['occupant_code']) ?>
                </span>
                <?php if ($isPrimary): ?>
                  <span class="badge badge-success"
                        style="margin-left:4px;">PRIMARY</span>
                <?php endif; ?>
              </td>
              <td><?= htmlspecialchars($occ['resident_name']) ?></td>
              <td>
                <span class="badge <?= occupantBadgeClass($occ['occupant_type']) ?>">
                  <?= occupantTypeLabel($occ['occupant_type']) ?>
                </span>
              </td>
              <td><?= htmlspecialchars($occ['phone'] ?? '') ?></td>
              <td>
                <span class="badge badge-<?= $occ['status'] === 'active'
                                              ? 'success' : 'muted' ?>">
                  <?= $occ['status'] ?>
                </span>
              </td>
              <td>
                <div style="display:flex;gap:4px;flex-wrap:wrap;">
                  <a href="residents_admin.php?action=edit&id=<?= $occ['id'] ?>"
                     class="btn btn-primary btn-sm">Edit</a>

                  <?php if (!$isPrimary): ?>
                  <!-- Activate / Deactivate for non-primary -->
                  <form method="POST"
                        action="residents_admin.php?action=toggle_status"
                        style="display:inline">
                          <?= csrfField() ?>
                    <input type="hidden" name="id" value="<?= $occ['id'] ?>">
                    <input type="hidden" name="status"
                           value="<?= $occ['status'] === 'active'
                                      ? 'inactive' : 'active' ?>">
                    <button class="btn btn-sm btn-<?= $occ['status'] === 'active'
                                                       ? 'secondary' : 'success' ?>">
                      <?= $occ['status'] === 'active' ? 'Deactivate' : 'Activate' ?>
                    </button>
                  </form>
                  <?php endif; ?>

                  <!-- Delete button -->
                  <?php if ($blockDelete): ?>
                    <!-- Primary with siblings — show disabled button with tooltip -->
                    <button class="btn btn-sm btn-danger"
                            style="opacity:.4;cursor:not-allowed;"
                            title="Delete other occupants first before deleting the primary"
                            disabled>
                      Delete
                    </button>
                  <?php else: ?>
                    <form method="POST"
                          action="residents_admin.php?action=delete"
                          style="display:inline"
                          onsubmit="return confirm('Permanently delete <?= htmlspecialchars(addslashes($erfno . $occ['occupant_code'])) ?> — <?= htmlspecialchars(addslashes($occ['resident_name'])) ?>?\n\nThis cannot be undone.')">
                            <?= csrfField() ?>
                      <input type="hidden" name="id" value="<?= $occ['id'] ?>">
                      <button class="btn btn-danger btn-sm">Delete</button>
                    </form>
                  <?php endif; ?>

                </div>
              </td>
            </tr>
            <?php endforeach; ?>
          </table>
        </div>
      </div>
      <?php endforeach; ?>

      <?php if (empty($erfs)): ?>
      <div class="card">
        <p style="color:#666;">No residents found.</p>
      </div>
      <?php endif; ?>

    </div>
    <?php pageFooter(); exit; ?>
<?php } // end action

// ════════════════════════════════════════════════════════
// ADD — new primary resident (new erf only)
// ════════════════════════════════════════════════════════
if ($action === 'add') {

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $erfno = strtoupper(trim($_POST['resident_erfno'] ?? ''));
        $pin   = trim($_POST['pin'] ?? '');

        if (!$erfno) {
            setFlash('error', 'Erf number is required.');
            header('Location: residents_admin.php?action=add'); exit;
        }
        if (!preg_match('/^\d{4}$/', $pin)) {
            setFlash('error', 'PIN must be exactly 4 digits.');
            header('Location: residents_admin.php?action=add'); exit;
        }
        $email = trim($_POST['email'] ?? '');
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            // Email is how residents receive their one-time code when
            // logging in from an unrecognised device (see resident.php) —
            // without one on file, that resident is locked out the first
            // time they need it and has to call an administrator.
            setFlash('error', 'A valid email address is required — it is used to send a one-time login code the first time this resident signs in from a new device.');
            header('Location: residents_admin.php?action=add'); exit;
        }

        $exists = db()->prepare(
            "SELECT id FROM residents
             WHERE resident_erfno = ? AND occupant_code = 'A' LIMIT 1"
        );
        $exists->execute([$erfno]);
        if ($exists->rowCount() > 0) {
            setFlash('info',
                "Erf {$erfno} already has a primary resident. " .
                "Adding as an additional occupant instead.");
            header("Location: residents_admin.php?action=add_occupant" .
                   "&erf=" . urlencode($erfno)); exit;
        }

        try {
            db()->prepare("
                INSERT INTO residents
                    (resident_erfno, occupant_code, occupant_type,
                     is_primary, resident_name, address, phone,
                     email, pin_hash, status)
                VALUES (?, 'A', 'owner', 1, ?, ?, ?, ?, ?, 'active')
            ")->execute([
                $erfno,
                trim($_POST['resident_name']),
                trim($_POST['address']),
                trim($_POST['phone'] ?? ''),
                $email,
                password_hash($pin, PASSWORD_BCRYPT),
            ]);
            setFlash('success',
                "Primary resident {$erfno}A — " .
                htmlspecialchars($_POST['resident_name']) .
                " added.");
            header("Location: residents_admin.php?action=add_occupant" .
                   "&erf=" . urlencode($erfno)); exit;
        } catch (Exception $e) {
            setFlash('error', 'Could not add resident: ' . $e->getMessage());
            header('Location: residents_admin.php?action=add'); exit;
        }
    }

    pageHeader('Add Resident', 'admin');
    renderHeader('➕ Add New Erf — Primary Resident',
                 'residents_admin.php?action=list');
    ?>
    <div class="container" style="max-width:560px;">
      <div class="card">
        <?= getFlash() ?>

        <div class="alert alert-info"
             style="margin-bottom:16px;font-size:.88rem;">
          This registers a <strong>new erf</strong> and its
          <strong>primary owner (code A)</strong>.<br><br>
          Spouses, dependents, domestic workers and tenants
          are added as additional occupants (B, C, D…) after
          the primary has been created.
        </div>

        <form method="POST" action="residents_admin.php?action=add"
              id="addForm">
                <?= csrfField() ?>
          <div class="form-group">
            <label>Erf Number *</label>
            <input type="text" name="resident_erfno" id="erfInput"
                   required
                   style="text-transform:uppercase;font-size:1.1rem;
                          letter-spacing:0.08em;"
                   oninput="this.value=this.value.toUpperCase();checkErf(this.value)"
                   placeholder="e.g. E15227">
            <div id="erf-status" style="font-size:.82rem;margin-top:4px;"></div>
          </div>

          <input type="hidden" name="occupant_type" value="owner">

          <div class="form-group">
            <label>Full Name — Owner / Primary Resident *</label>
            <input type="text" name="resident_name" required>
          </div>
          <div class="form-group">
            <label>Physical Address *</label>
            <input type="text" name="address" required
                   placeholder="e.g. 114 Myrica Drive">
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div class="form-group">
              <label>Phone (27XXXXXXXXX) *</label>
              <input type="tel" name="phone" required
                     placeholder="e.g. 27825222205"
                     pattern="27[0-9]{9}">
            </div>
            <div class="form-group">
              <label>Email *</label>
              <input type="email" name="email" required
                     placeholder="name@example.com">
            </div>
          </div>
          <small style="color:#888;display:block;margin:-8px 0 12px;">
            Email is required — it's how this resident receives their
            one-time login code the first time they sign in from a new
            device or browser.
          </small>
          <div class="form-group">
            <label>4-digit PIN *</label>
            <input type="password" name="pin" required
                   inputmode="numeric" maxlength="4" pattern="\d{4}"
                   placeholder="••••"
                   style="font-size:1.6rem;letter-spacing:0.4em;
                          text-align:center;">
            <small style="color:#888;">
              Owner logs in with
              <strong id="loginPreview">E?????A</strong> + this PIN.
            </small>
          </div>
          <button type="submit" class="btn btn-primary btn-block"
                  id="submitBtn">
            Register Primary Resident (Owner) — Email Required
          </button>
        </form>
        <div class="popia-notice">
          Resident data processed under POPIA §11.
        </div>
      </div>
    </div>

    <script>
    function checkErf(val) {
      const status  = document.getElementById('erf-status');
      const preview = document.getElementById('loginPreview');
      const btn     = document.getElementById('submitBtn');
      if (!val || val.length < 2) {
        status.textContent = '';
        preview.textContent = 'E?????A';
        return;
      }
      preview.textContent = val + 'A';
      fetch('residents_admin.php?action=check_erf&erf=' +
            encodeURIComponent(val))
        .then(r => r.json())
        .then(data => {
          if (data.exists) {
            status.innerHTML =
              '⚠️ Erf <strong>' + val + '</strong> already registered. ' +
              '<a href="residents_admin.php?action=add_occupant&erf=' +
              encodeURIComponent(val) + '">Add occupant instead →</a>';
            status.style.color = '#856404';
            btn.textContent    = 'Add Occupant Instead';
            btn.style.background = '#ffc107';
            btn.style.color      = '#000';
            document.getElementById('addForm').action =
              'residents_admin.php?action=add_occupant&erf=' +
              encodeURIComponent(val);
          } else {
            status.innerHTML   = '✅ Erf available.';
            status.style.color = '#155724';
            btn.textContent    = 'Register Primary Resident (Owner) — Email Required';
            btn.style.background = '';
            btn.style.color      = '';
            document.getElementById('addForm').action =
              'residents_admin.php?action=add';
          }
        })
        .catch(() => { status.textContent = ''; });
    }
    </script>
    <?php pageFooter(); exit; ?>
<?php } // end action

// ── AJAX: check if erf exists ─────────────────────────────
if ($action === 'check_erf') {
    header('Content-Type: application/json');
    $erf = strtoupper(trim($_GET['erf'] ?? ''));
    $chk = db()->prepare(
        "SELECT id FROM residents
         WHERE resident_erfno = ? AND occupant_code = 'A' LIMIT 1"
    );
    $chk->execute([$erf]);
    echo json_encode(['exists' => $chk->rowCount() > 0]);
    exit;
}

// ════════════════════════════════════════════════════════
// ADD OCCUPANT — additional person at existing erf
// ════════════════════════════════════════════════════════
if ($action === 'add_occupant') {
    $erfno = strtoupper(trim($_GET['erf'] ?? ''));

    $existing = db()->prepare(
        "SELECT occupant_code, resident_name, occupant_type, address
         FROM residents WHERE resident_erfno = ?
         ORDER BY occupant_code"
    );
    $existing->execute([$erfno]);
    $existing = $existing->fetchAll();

    if (empty($existing)) {
        setFlash('error', "Erf {$erfno} not found.");
        header('Location: residents_admin.php?action=list'); exit;
    }

    $nextCode = nextOccupantCode($erfno);
    $address  = $existing[0]['address'] ?? '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $pin = trim($_POST['pin'] ?? '');
        if (!preg_match('/^\d{4}$/', $pin)) {
            setFlash('error', 'PIN must be exactly 4 digits.');
            header("Location: residents_admin.php?action=add_occupant&erf={$erfno}");
            exit;
        }
        $email = trim($_POST['email'] ?? '');
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            // Same reasoning as the primary-owner form: each occupant
            // logs in on their own code (erf+letter) and needs an email
            // on file to receive the new-device one-time code.
            setFlash('error', 'A valid email address is required — it is used to send a one-time login code the first time this occupant signs in from a new device.');
            header("Location: residents_admin.php?action=add_occupant&erf={$erfno}");
            exit;
        }

        try {
            db()->prepare("
                INSERT INTO residents
                    (resident_erfno, occupant_code, occupant_type,
                     is_primary, resident_name, address, phone,
                     email, pin_hash, status)
                VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, 'active')
            ")->execute([
                $erfno,
                $nextCode,
                $_POST['occupant_type'] ?? 'other',
                trim($_POST['resident_name']),
                trim($_POST['address'] ?? $address),
                trim($_POST['phone']   ?? ''),
                $email,
                password_hash($pin, PASSWORD_BCRYPT),
            ]);
            setFlash('success',
                "Occupant {$erfno}{$nextCode} — " .
                htmlspecialchars($_POST['resident_name']) .
                " added successfully.");
            header('Location: residents_admin.php?action=list'); exit;
        } catch (Exception $e) {
            setFlash('error', 'Could not add occupant: ' . $e->getMessage());
            header("Location: residents_admin.php?action=add_occupant&erf={$erfno}");
            exit;
        }
    }

    pageHeader('Add Occupant', 'admin');
    renderHeader(
        "➕ Add Occupant — Erf {$erfno}",
        'residents_admin.php?action=list'
    );
    ?>
    <div class="container" style="max-width:560px;">
      <div class="card">
        <?= getFlash() ?>

        <div style="background:#f5f7fa;border-radius:8px;
                    padding:12px 16px;margin-bottom:18px;">
          <div style="font-weight:700;margin-bottom:8px;color:var(--accent);">
            Erf <?= htmlspecialchars($erfno) ?> — Current Occupants
          </div>
          <?php foreach ($existing as $occ): ?>
          <div style="font-size:.88rem;padding:3px 0;">
            <strong><?= $erfno . $occ['occupant_code'] ?></strong>
            — <?= htmlspecialchars($occ['resident_name']) ?>
            (<?= occupantTypeLabel($occ['occupant_type']) ?>)
          </div>
          <?php endforeach; ?>
        </div>

        <div class="alert alert-info" style="font-size:.88rem;margin-bottom:16px;">
          New occupant will be assigned code
          <strong><?= $erfno . $nextCode ?></strong>.
          This code is permanent and will not be reused.
        </div>

        <form method="POST"
              action="residents_admin.php?action=add_occupant&erf=<?= urlencode($erfno) ?>">
                <?= csrfField() ?>
          <div class="form-group">
            <label>Occupant Type</label>
            <select name="occupant_type">
              <option value="spouse">💑 Spouse</option>
              <option value="dependent">👶 Dependent</option>
              <option value="domestic_worker">🧹 Domestic Worker</option>
              <option value="tenant">🔑 Tenant</option>
              <option value="other">👤 Other</option>
            </select>
          </div>
          <div class="form-group">
            <label>Full Name *</label>
            <input type="text" name="resident_name" required>
          </div>
          <div class="form-group">
            <label>Address</label>
            <input type="text" name="address"
                   value="<?= htmlspecialchars($address) ?>">
            <small style="color:#888;">
              Pre-filled from the primary resident's address — all
              occupants at Erf <?= htmlspecialchars($erfno) ?> share the
              same address. Edit only if this occupant's address
              genuinely differs.
            </small>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div class="form-group">
              <label>Phone (27XXXXXXXXX)</label>
              <input type="tel" name="phone"
                     placeholder="e.g. 27821234567"
                     pattern="27[0-9]{9}">
            </div>
            <div class="form-group">
              <label>Email *</label>
              <input type="email" name="email" required
                     placeholder="name@example.com">
            </div>
          </div>
          <small style="color:#888;display:block;margin:-8px 0 12px;">
            Email is required — it's how this occupant receives their
            one-time login code the first time they sign in from a new
            device or browser.
          </small>
          <div class="form-group">
            <label>4-digit PIN *</label>
            <input type="password" name="pin" required
                   inputmode="numeric" maxlength="4" pattern="\d{4}"
                   placeholder="••••"
                   style="font-size:1.6rem;letter-spacing:0.4em;
                          text-align:center;">
            <small style="color:#888;">
              This occupant logs in with
              <strong><?= $erfno . $nextCode ?></strong> + PIN.
            </small>
          </div>
          <button type="submit" class="btn btn-primary btn-block">
            Add Occupant <?= $erfno . $nextCode ?> — Email Required
          </button>
        </form>
        <div class="popia-notice">
          Resident data processed under POPIA §11.
        </div>
      </div>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end action

// ════════════════════════════════════════════════════════
// EDIT — update occupant details
// ════════════════════════════════════════════════════════
if ($action === 'edit') {
    $id = (int)($_GET['id'] ?? 0);
    $res = db()->prepare("SELECT * FROM residents WHERE id=? LIMIT 1");
    $res->execute([$id]);
    $res = $res->fetch();

    if (!$res) {
        setFlash('error', 'Resident not found.');
        header('Location: residents_admin.php?action=list'); exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $pin    = trim($_POST['pin'] ?? '');
        $params = [
            trim($_POST['resident_name']),
            trim($_POST['address']       ?? ''),
            trim($_POST['phone']         ?? ''),
            trim($_POST['email']         ?? ''),
            $_POST['occupant_type']      ?? $res['occupant_type'],
            $_POST['status']             ?? $res['status'],
            $id,
        ];

        if ($pin) {
            if (!preg_match('/^\d{4}$/', $pin)) {
                setFlash('error', 'PIN must be exactly 4 digits.');
                header("Location: residents_admin.php?action=edit&id={$id}");
                exit;
            }
            db()->prepare("
                UPDATE residents
                SET resident_name = ?, address = ?, phone = ?,
                    email = ?, occupant_type = ?, status = ?,
                    pin_hash = ?, device_token = NULL
                WHERE id = ?
            ")->execute(array_merge(
                array_slice($params, 0, 6),
                [password_hash($pin, PASSWORD_BCRYPT)],
                [$id]
            ));
            setFlash('success', 'Resident updated. PIN changed — device token reset.');
        } else {
            db()->prepare("
                UPDATE residents
                SET resident_name = ?, address = ?, phone = ?,
                    email = ?, occupant_type = ?, status = ?
                WHERE id = ?
            ")->execute($params);
            setFlash('success', 'Resident updated.');
        }
        header('Location: residents_admin.php?action=list'); exit;
    }

    $loginCode = $res['resident_erfno'] . $res['occupant_code'];
    pageHeader('Edit Resident', 'admin');
    renderHeader(
        "✏️ Edit — {$loginCode}",
        'residents_admin.php?action=list'
    );
    ?>
    <div class="container" style="max-width:560px;">
      <div class="card">
        <?= getFlash() ?>

        <div style="background:#f5f7fa;border-radius:8px;
                    padding:10px 14px;margin-bottom:16px;
                    font-size:.88rem;">
          <strong>Login code:</strong>
          <span style="font-family:monospace;font-size:1.1rem;
                       font-weight:800;color:var(--accent);">
            <?= htmlspecialchars($loginCode) ?>
          </span>
          <?php if ($res['is_primary']): ?>
            <span class="badge badge-success" style="margin-left:6px;">
              PRIMARY
            </span>
          <?php endif; ?>
        </div>

        <form method="POST"
              action="residents_admin.php?action=edit&id=<?= $id ?>">
                <?= csrfField() ?>
          <div class="form-group">
            <label>Occupant Type</label>
            <select name="occupant_type" <?= $res['is_primary']
                                              ? 'disabled' : '' ?>>
              <option value="owner"
                <?= $res['occupant_type']==='owner'?'selected':'' ?>>
                🏠 Owner</option>
              <option value="spouse"
                <?= $res['occupant_type']==='spouse'?'selected':'' ?>>
                💑 Spouse</option>
              <option value="dependent"
                <?= $res['occupant_type']==='dependent'?'selected':'' ?>>
                👶 Dependent</option>
              <option value="domestic_worker"
                <?= $res['occupant_type']==='domestic_worker'?'selected':'' ?>>
                🧹 Domestic Worker</option>
              <option value="tenant"
                <?= $res['occupant_type']==='tenant'?'selected':'' ?>>
                🔑 Tenant</option>
              <option value="other"
                <?= $res['occupant_type']==='other'?'selected':'' ?>>
                👤 Other</option>
            </select>
            <?php if ($res['is_primary']): ?>
              <input type="hidden" name="occupant_type"
                     value="<?= $res['occupant_type'] ?>">
            <?php endif; ?>
          </div>
          <div class="form-group">
            <label>Full Name *</label>
            <input type="text" name="resident_name" required
                   value="<?= htmlspecialchars($res['resident_name']) ?>">
          </div>
          <div class="form-group">
            <label>Address</label>
            <input type="text" name="address"
                   value="<?= htmlspecialchars($res['address'] ?? '') ?>">
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div class="form-group">
              <label>Phone (27XXXXXXXXX)</label>
              <input type="tel" name="phone"
                     value="<?= htmlspecialchars($res['phone'] ?? '') ?>"
                     pattern="27[0-9]{9}">
            </div>
            <div class="form-group">
              <label>Email</label>
              <input type="email" name="email"
                     value="<?= htmlspecialchars($res['email'] ?? '') ?>">
            </div>
          </div>
          <div class="form-group">
            <label>Status</label>
            <select name="status" <?= $res['is_primary']
                                       ? 'disabled' : '' ?>>
              <option value="active"
                <?= $res['status']==='active'?'selected':'' ?>>Active</option>
              <option value="inactive"
                <?= $res['status']==='inactive'?'selected':'' ?>>Inactive</option>
            </select>
            <?php if ($res['is_primary']): ?>
              <input type="hidden" name="status" value="<?= $res['status'] ?>">
            <?php endif; ?>
          </div>
          <div class="form-group">
            <label>New PIN (leave blank to keep current)</label>
            <input type="password" name="pin"
                   inputmode="numeric" maxlength="4" pattern="\d{4}"
                   placeholder="••••"
                   style="font-size:1.6rem;letter-spacing:0.4em;
                          text-align:center;">
            <small style="color:#888;">
              Changing PIN will reset device token — resident
              must log in again on their device.
            </small>
          </div>
          <button type="submit" class="btn btn-primary btn-block">
            Save Changes
          </button>
        </form>
      </div>
    </div>
    <?php pageFooter(); exit; ?>
<?php } // end action

// ════════════════════════════════════════════════════════
// TOGGLE STATUS — activate/deactivate non-primary occupant
// ════════════════════════════════════════════════════════
if ($action === 'toggle_status') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $id     = (int)$_POST['id'];
        $status = $_POST['status'] === 'active' ? 'active' : 'inactive';
        db()->prepare(
            "UPDATE residents SET status=?
             WHERE id=? AND is_primary=0"
        )->execute([$status, $id]);
        setFlash('success', 'Occupant status updated.');
    }
    header('Location: residents_admin.php?action=list'); exit;
}

// Fallback
header('Location: residents_admin.php?action=list'); exit;
