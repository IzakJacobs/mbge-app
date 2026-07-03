<?php
// ============================================================
// GEMB Access Control — visitor.php
// Handles both visitor invites AND service provider invites
//
// visitors columns: id, resident_name, resident_address,
//   visitor_name, plate, idnum, visit_date, visit_date_to,
//   code, qrcode, arrival, visit_time, expired, created_at,
//   status, visitor_phone
//
// Service provider categories available to resident:
//   domestic, resident_worker, contractor_lead, delivery
//   (contractor_worker is site manager only)
//   delivery requires security office approval + single-use slip
// ============================================================
require_once __DIR__ . '/layout.php';
require_once __DIR__ . '/smtp_mail.php';
if (session_status() === PHP_SESSION_NONE) session_start();
requireResident();

$action = $_GET['action'] ?? 'select';
$rid    = $_SESSION['resident_id'];
$rerf   = $_SESSION['resident_erf']  ?? '';
$rname  = $_SESSION['resident_name'] ?? '';

// Get resident data
$resRow     = db()->prepare("SELECT address, phone FROM residents WHERE id=? LIMIT 1");
$resRow->execute([$rid]);
$resRow     = $resRow->fetch();
$resAddress = $resRow['address'] ?? '';

// ════════════════════════════════════════════════════════
// HELPERS  (defined first so all action blocks can call them)
// ════════════════════════════════════════════════════════

// ── Helper: unique 3XXXXX visitor code ───────────────────
function makeVisitorCode(): string {
    $pdo = db();
    do {
        $code = '3' . str_pad(random_int(0, 99999), 5, '0', STR_PAD_LEFT);
        $chk  = $pdo->prepare("SELECT id FROM visitors WHERE code=? LIMIT 1");
        $chk->execute([$code]);
    } while ($chk->rowCount() > 0);
    return $code;
}

// ── Helper: unique 7XXXXX SP code ────────────────────────
function makeSpCode(): string {
    $pdo = db();
    do {
        $code = '7' . str_pad(random_int(0, 99999), 5, '0', STR_PAD_LEFT);
        $chk  = $pdo->prepare(
            "SELECT id FROM service_providers WHERE unique_code=? LIMIT 1"
        );
        $chk->execute([$code]);
    } while ($chk->rowCount() > 0);
    return $code;
}

// ── Helper: WhatsApp wa.me link ──────────────────────────
function buildWhatsAppLink(string $phone, string $message): string {
    $phone = preg_replace('/\D/', '', $phone);
    if (substr($phone, 0, 1) === '0') $phone = '27' . substr($phone, 1);
    if (substr($phone, 0, 2) !== '27') $phone = '27' . $phone;
    return 'https://wa.me/' . $phone . '?text=' . rawurlencode($message);
}

// ── Helper: SMS link ─────────────────────────────────────
function buildSmsLink(string $phone, string $message): string {
    $phone = preg_replace('/\D/', '', $phone);
    if (substr($phone, 0, 1) === '0') $phone = '+27' . substr($phone, 1);
    elseif (substr($phone, 0, 2) === '27') $phone = '+' . $phone;
    return 'sms:' . $phone . '?body=' . rawurlencode($message);
}

// ── Helper: generate QR for visitor ──────────────────────
function generateQrForVisitor(int $visitorId, string $code): void
{
    $qrLib = __DIR__ . '/phpqrcode/qrlib.php';
    if (!file_exists($qrLib)) return;
    require_once $qrLib;
    $tempDir = __DIR__ . '/temp';
    if (!is_dir($tempDir)) @mkdir($tempDir, 0755, true);
    $verifyUrl = SITE_URL . '/visitor_qr_verify.php?code=' . urlencode($code);
    $filePath  = $tempDir . '/' . $code . '.png';
    QRcode::png($verifyUrl, $filePath, QR_ECLEVEL_M, 6, 2);
    if (file_exists($filePath)) {
        db()->prepare("UPDATE visitors SET qrcode=? WHERE id=?")
            ->execute(['/temp/' . $code . '.png', $visitorId]);
    }
}

// ── SP category labels ────────────────────────────────────
$spCategories = [
    'domestic'        => ['icon' => '🏠', 'label' => 'Domestic Worker',
                          'permit' => 'card',    'desc' => 'Regular domestic worker'],
    'resident_worker' => ['icon' => '🔧', 'label' => 'Resident Worker',
                          'permit' => 'card',    'desc' => 'Painter, gardener etc.'],
    'contractor_lead' => ['icon' => '👷', 'label' => 'Contractor Lead',
                          'permit' => 'card',    'desc' => 'Team leader for building work'],
    'delivery'        => ['icon' => '📦', 'label' => 'Delivery',
                          'permit' => 'slip', 'desc' => 'Once-off — security office approval required'],
];

// ── Helper: build the correct invite link + message per category.
//    Contractor Leads complete their OWN full registration (company
//    details, documents, etc.) via the applications engine — the
//    unique_code doubles as the ?invite= code application_form.php
//    already understands. Every other category still visits the
//    Security Office in person with their ID, unchanged.
function spInviteContent(string $cat, string $code, string $spName, string $rname, string $resAddress, array $spCategories): array {
    $catLabel = $spCategories[$cat]['label'] ?? $cat;

    if ($cat === 'contractor_lead') {
        $url = SITE_URL . '/application_form.php?type=contractor&invite=' . $code;
        $wa  = "🏡 GEMB Contractor Registration\n\n"
             . "Hi {$spName},\n\n"
             . "You have been invited by {$rname}\n{$resAddress}\n\n"
             . "Please complete your own registration — company details, ID "
             . "and any required documents — using the link below:\n\n"
             . "{$url}\n\n"
             . "Reference code: {$code}\n\n"
             . "GEMB HOA Reg. 1999/001249/08 | POPIA Act 4 of 2013";
    } else {
        $url = SITE_URL . '/sp_pass.php?code=' . $code;
        $wa  = "🏡 GEMB Service Provider Invite\n\n"
             . "Hi {$spName},\n\n"
             . "You have been invited by {$rname}\n{$resAddress}\n\n"
             . "Category: {$catLabel}\n\n"
             . "Please visit the GEMB Security Office with your ID document to "
             . "complete registration and collect your access permit.\n\n"
             . "Tap the link below and show it to the Security Officer:\n{$url}\n\n"
             . "Reference code: {$code}\n\n"
             . "GEMB HOA Reg. 1999/001249/08 | POPIA Act 4 of 2013";
    }
    return ['url' => $url, 'wa_message' => $wa, 'cat_label' => $catLabel];
}

// ── Helper: e-mail the same invite text sent via WhatsApp — an
//    addition alongside WhatsApp/SMS, never a replacement. Never
//    throws; a failed e-mail must not block the WhatsApp/SMS send.
function spSendInviteEmail(string $email, string $waMessage, string $catLabel, string $code): void {
    try {
        $html = '<p>' . nl2br(htmlspecialchars($waMessage, ENT_QUOTES, 'UTF-8')) . '</p>';
        smtpSend($email, 'GEMB Invitation — ' . $catLabel . ' — ' . $code, $html);
    } catch (\Throwable $e) {
        error_log('spSendInviteEmail failed for ' . $email . ': ' . $e->getMessage());
    }
}

// ════════════════════════════════════════════════════════
// SELECT — list visitors + service providers
// ════════════════════════════════════════════════════════
if ($action === 'select') {
    $visitors = db()->prepare(
        "SELECT * FROM visitors WHERE resident_name=?
         ORDER BY visit_date DESC LIMIT 30"
    );
    $visitors->execute([$rname]);
    $visitors = $visitors->fetchAll();

    $sps = db()->prepare(
        "SELECT * FROM service_providers
         WHERE resident_erfno=? OR resident_name=?
         ORDER BY created_at DESC LIMIT 30"
    );
    $sps->execute([$rerf, $rname]);
    $sps = $sps->fetchAll();

    pageHeader('My Visitors', 'resident');
    renderHeader(
        '👤 ' . ($_SESSION['resident_login'] ?? $rerf . 'A'),
        'resident.php?action=menu'
    );
    ?>
    <div class="container">
      <?= getFlash() ?>

      <!-- ── Open Gate ── -->
      <a href="gate_proximity_unlock.php"
         style="display:flex;align-items:center;gap:16px;
                text-decoration:none;color:white;
                background:linear-gradient(135deg,#1a7a32 0%,#28a745 100%);
                border-radius:14px;padding:18px 20px;margin-bottom:18px;
                box-shadow:0 4px 14px rgba(40,167,69,0.30);
                -webkit-tap-highlight-color:transparent;">
        <div style="font-size:2.4rem;line-height:1;flex-shrink:0;">🔓</div>
        <div style="flex:1;">
          <div style="font-size:1.1rem;font-weight:800;letter-spacing:.3px;">
            Open Gate
          </div>
          <div style="font-size:.8rem;opacity:.88;margin-top:3px;">
            Schoeman Street &amp; Church Street entrances
            &middot; must be within 100 m
          </div>
        </div>
        <div style="font-size:1.5rem;opacity:.75;flex-shrink:0;">›</div>
      </a>

      <!-- ── Action buttons ── -->
      <div style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;">
        <a href="visitor.php?action=add"
           class="btn btn-primary" style="flex:1;text-align:center;">
          + Invite Visitor
        </a>
        <a href="visitor.php?action=sp_invite"
           class="btn btn-success" style="flex:1;text-align:center;">
          🔧 Invite Service Provider
        </a>
      </div>

      <!-- ── Visitors ── -->
      <div style="font-weight:700;color:var(--accent);
                  margin-bottom:8px;font-size:.95rem;">
        👤 Visitors
      </div>
      <?php if (empty($visitors)): ?>
        <div class="card" style="margin-bottom:18px;">
          <p style="color:#666;font-size:.9rem;">No visitors registered yet.</p>
        </div>
      <?php else: foreach ($visitors as $v):
        $today    = date('Y-m-d');
        $visitTo  = $v['visit_date_to'] ?: $v['visit_date'];
        $isActive = !$v['expired'] && $v['status'] === 'active'
                    && $today <= $visitTo;
        $passUrl  = SITE_URL . '/visitor_qr.php?code=' . $v['code'];
        $fmtFrom  = date('d M Y', strtotime($v['visit_date']));
        $fmtTo    = date('d M Y', strtotime($visitTo));
        $waMsg    = "🏡 GEMB Visitor Pass\n\n"
                  . "Hi {$v['visitor_name']},\n\n"
                  . "Your access pass for Mossel Bay Golf Estate:\n\n"
                  . "📅 Valid: {$fmtFrom} – {$fmtTo}\n"
                  . "🔑 Gate code: {$v['code']}\n\n"
                  . "👇 Tap to open your pass:\n{$passUrl}\n\n"
                  . "Show the QR to the guard or give them your 6-digit code.";
        $waLink   = $v['visitor_phone']
                    ? buildWhatsAppLink($v['visitor_phone'], $waMsg) : '';
      ?>
      <div class="card" style="border-left:4px solid <?= $isActive?'#28a745':'#aaa' ?>">
        <div style="display:flex;justify-content:space-between;
                    align-items:flex-start;flex-wrap:wrap;gap:8px;">
          <div>
            <strong><?= htmlspecialchars($v['visitor_name']) ?></strong>
            <span class="badge badge-<?= $isActive?'success':'muted' ?>"
                  style="margin-left:6px;"><?= $v['status'] ?></span>
            <div style="font-size:.82rem;color:#666;margin-top:4px;">
              📅 <?= $fmtFrom ?>
              <?php if ($v['visit_date_to'] && $v['visit_date_to'] !== $v['visit_date']): ?>
                → <?= $fmtTo ?>
              <?php endif; ?>
              <?php if ($v['plate']): ?>
                &nbsp;|&nbsp; 🚗 <?= htmlspecialchars($v['plate']) ?>
              <?php endif; ?>
            </div>
            <div style="font-size:.8rem;color:#0f2744;margin-top:3px;
                        font-family:monospace;font-weight:700;">
              Code: <?= htmlspecialchars($v['code']) ?>
            </div>
          </div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;">
            <?php if ($isActive): ?>
              <a href="visitor_qr.php?code=<?= urlencode($v['code']) ?>"
                 target="_blank" class="btn btn-primary btn-sm">📱 Pass</a>
              <?php if ($waLink): ?>
              <a href="<?= htmlspecialchars($waLink) ?>"
                 class="btn btn-success btn-sm">📤 WhatsApp</a>
              <?php endif; ?>
              <form method="POST" action="visitor.php?action=delete"
                    onsubmit="return confirm('Cancel this visitor pass?')">
                <?= csrfField() ?>
                <input type="hidden" name="vid" value="<?= $v['id'] ?>">
                <button class="btn btn-danger btn-sm">Cancel</button>
              </form>
            <?php endif; ?>
          </div>
        </div>
        <?php if ($v['arrival']): ?>
          <div style="font-size:.75rem;color:#28a745;margin-top:6px;">
            ✅ Arrived <?= date('d M H:i', strtotime($v['arrival'])) ?>
          </div>
        <?php endif; ?>
      </div>
      <?php endforeach; endif; ?>

      <!-- ── Service Providers ── -->
      <div style="font-weight:700;color:var(--accent);
                  margin:18px 0 8px;font-size:.95rem;">
        🔧 Service Providers
      </div>
      <?php if (empty($sps)): ?>
        <div class="card">
          <p style="color:#666;font-size:.9rem;">No service providers invited yet.</p>
        </div>
      <?php else: foreach ($sps as $sp):
        $cat      = $spCategories[$sp['category']] ?? $spCategories['resident_worker'];
        $spStatus = $sp['status'] ?? ($sp['approved']==='true' ? 'approved' : 'pending');
        $isActive = $spStatus === 'approved' && !$sp['expired']
                    && $sp['end_date'] >= date('Y-m-d');
        $borderCol = $spStatus === 'approved' ? '#28a745'
                   : ($spStatus === 'invited'  ? '#17a2b8'
                   : ($spStatus === 'revoked'  ? '#dc3545'
                   : '#ffc107'));
        $badgeClass = $spStatus === 'approved' ? 'success'
                    : ($spStatus === 'invited' ? 'info'
                    : ($spStatus === 'revoked' ? 'danger'
                    : 'warning'));
      ?>
      <div class="card" style="border-left:4px solid <?= $borderCol ?>">
        <div style="display:flex;justify-content:space-between;
                    align-items:flex-start;flex-wrap:wrap;gap:8px;">
          <div>
            <span style="font-size:.8rem;">
              <?= $cat['icon'] ?> <?= $cat['label'] ?>
            </span>
            <div><strong><?= htmlspecialchars($sp['service_name']) ?></strong>
              <span class="badge badge-<?= $badgeClass ?>"
                    style="margin-left:6px;"><?= $spStatus ?></span>
            </div>
            <div style="font-size:.82rem;color:#666;margin-top:3px;">
              📅 <?= date('d M Y', strtotime($sp['start_date'])) ?>
              → <?= date('d M Y', strtotime($sp['end_date'])) ?>
            </div>
            <?php if ($sp['notes']): ?>
            <div style="font-size:.8rem;color:#888;margin-top:2px;">
              <?= htmlspecialchars($sp['notes']) ?>
            </div>
            <?php endif; ?>
            <div style="font-size:.8rem;color:#0f2744;margin-top:3px;
                        font-family:monospace;font-weight:700;">
              Code: <?= htmlspecialchars($sp['unique_code']) ?>
            </div>
          </div>
          <?php if ($spStatus === 'invited' && !empty($sp['sp_phone'])): ?>
          <?php
            // Resend — same category-aware content as the original invite
            $spContent = spInviteContent($sp['category'], $sp['unique_code'], $sp['service_name'], $rname, $resAddress, $spCategories);
            $spWaLink  = buildWhatsAppLink($sp['sp_phone'], $spContent['wa_message']);
          ?>
          <a href="<?= htmlspecialchars($spWaLink) ?>"
             class="btn btn-success btn-sm">📤 Resend</a>
          <?php if (!empty($sp['sp_email'])): ?>
          <a href="visitor.php?action=sp_resend_email&code=<?= urlencode($sp['unique_code']) ?>"
             class="btn btn-secondary btn-sm">📧 Resend</a>
          <?php endif; ?>
          <?php endif; ?>
        </div>
      </div>
      <?php endforeach; endif; ?>
    </div>
    <?php
    pageFooter();
    exit;
} // end select

// ════════════════════════════════════════════════════════
// SP INVITE — resident invites service provider
// ════════════════════════════════════════════════════════
if ($action === 'sp_invite') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $cat      = $_POST['category'] ?? 'domestic';
        $code     = makeSpCode();
        $dateFrom = $_POST['start_date'];
        $dateTo   = !empty($_POST['end_date'])
                    ? $_POST['end_date']
                    : date('Y-m-d', strtotime('+30 days'));

        db()->prepare("
            INSERT INTO service_providers
              (resident_erfno, resident_name, service_name, company_name,
               sp_phone, sp_email, category, permit_type,
               start_date, end_date, notes, unique_code,
               status, approved, expired,
               invited_by_resident_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'invited','false',0,?)
        ")->execute([
            $rerf,
            $rname,
            trim($_POST['sp_name']),
            trim($_POST['company_name'] ?? ''),
            trim($_POST['sp_phone']),
            filter_var(trim($_POST['sp_email'] ?? ''), FILTER_VALIDATE_EMAIL) ?: null,
            $cat,
            in_array($cat, ['domestic','resident_worker','contractor_lead'])
                ? 'card' : 'slip',
            $dateFrom,
            $dateTo,
            trim($_POST['notes']        ?? ''),
            $code,
            $rid,
        ]);

        // Build invite content — category-aware (contractor_lead gets the
        // full self-registration form link; everyone else gets sp_pass.php
        // as before) — then send WhatsApp/SMS as usual, plus e-mail if an
        // address was supplied.
        $spName    = trim($_POST['sp_name']);
        $spPhone   = trim($_POST['sp_phone']);
        $spEmail   = filter_var(trim($_POST['sp_email'] ?? ''), FILTER_VALIDATE_EMAIL) ?: '';
        $content   = spInviteContent($cat, $code, $spName, $rname, $resAddress, $spCategories);
        $catLabel  = $content['cat_label'];
        $passUrl   = $content['url'];
        $waMessage = $content['wa_message'];

        $waLink  = buildWhatsAppLink($spPhone, $waMessage);
        $smsLink = buildSmsLink($spPhone,
            "GEMB SP Invite: {$catLabel}. "
            . ($cat === 'contractor_lead' ? 'Complete your registration' : 'Visit Security Office with ID')
            . ". Ref: {$passUrl}");

        if ($spEmail !== '') {
            spSendInviteEmail($spEmail, $waMessage, $catLabel, $code);
        }

        // Redirect to pass display with send buttons
        header('Location: visitor.php?action=sp_send'
               . '&code=' . urlencode($code)
               . '&wa='   . urlencode($waLink)
               . '&sms='  . urlencode($smsLink)
               . ($spEmail !== '' ? '&emailed=1' : ''));
        exit;
    }

    pageHeader('Invite Service Provider', 'resident');
    renderHeader('🔧 Invite Service Provider', 'visitor.php?action=select');
    ?>
    <div class="container" style="max-width:560px;">
      <div class="card">
        <?= getFlash() ?>
        <form method="POST" action="visitor.php?action=sp_invite">
          <?= csrfField() ?>

          <!-- Category -->
          <div class="form-group">
            <label>Type of Service Provider *</label>
            <div style="display:flex;flex-direction:column;gap:8px;margin-top:4px;">
              <?php foreach ($spCategories as $key => $cat): ?>
              <label style="display:flex;align-items:center;gap:12px;
                            padding:10px 14px;border:2px solid #dee2e6;
                            border-radius:8px;cursor:pointer;"
                     class="cat-opt" id="copt-<?= $key ?>">
                <input type="radio" name="category" value="<?= $key ?>"
                       onchange="updateSpCat('<?= $key ?>')"
                       <?= $key === 'domestic' ? 'checked' : '' ?>
                       style="flex-shrink:0;width:18px;height:18px;">
                <div style="font-size:1.3rem;flex-shrink:0;">
                  <?= $cat['icon'] ?>
                </div>
                <div style="flex:1;">
                  <div style="font-weight:700;font-size:.95rem;">
                    <?= $cat['label'] ?>
                  </div>
                  <div style="font-size:.78rem;color:#666;margin-top:1px;">
                    <?= $cat['desc'] ?>
                  </div>
                </div>
              </label>
              <?php endforeach; ?>
            </div>
          </div>

          <!-- Delivery notice -->
          <div id="deliveryNote"
               style="display:none;background:#fff3cd;border:1px solid #ffc107;
                      border-radius:8px;padding:10px 14px;
                      font-size:.85rem;margin-bottom:14px;">
            📦 Delivery follows the <strong>Visitor pass flow</strong> —
            once-off entry, expires after first scan.
            You will be redirected to the visitor invite form.
          </div>

          <!-- SP details -->
          <div class="form-group">
            <label>Full Name *</label>
            <input type="text" name="sp_name" required
                   placeholder="Service provider's full name">
          </div>
          <div class="form-group">
            <label>WhatsApp / Cell Number *</label>
            <input type="tel" name="sp_phone" required
                   placeholder="e.g. 082 123 4567" inputmode="tel">
            <small style="color:#888;">
              Invite will be sent to this number.
            </small>
          </div>
          <div class="form-group">
            <label>Company Name (if applicable)</label>
            <input type="text" name="company_name"
                   placeholder="e.g. ABC Plumbing">
          </div>
          <div class="form-group">
            <label>Email Address</label>
            <input type="email" name="sp_email"
                   placeholder="e.g. name@example.com">
            <small style="color:#888;">
              Used to send them their registration link.
            </small>
          </div>
          <div class="form-group">
            <label>Description of Work</label>
            <input type="text" name="notes"
                   placeholder="e.g. Painting lounge, Garden maintenance">
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div class="form-group">
              <label>Start Date *</label>
              <input type="date" name="start_date" required
                     value="<?= date('Y-m-d') ?>">
            </div>
            <div class="form-group">
              <label>End Date *</label>
              <input type="date" name="end_date" required
                     value="<?= date('Y-m-d', strtotime('+30 days')) ?>">
            </div>
          </div>

          <button type="submit" class="btn btn-primary btn-block"
                  id="spSubmitBtn">
            Create Invite &amp; Send via WhatsApp
          </button>
        </form>
        <div class="popia-notice">
          Personal data collected under POPIA §11. Retained 90 days after expiry.
        </div>
      </div>
    </div>
    <script>
    function updateSpCat(key) {
        const delivNote = document.getElementById('deliveryNote');
        const btn       = document.getElementById('spSubmitBtn');
        document.querySelectorAll('.cat-opt').forEach(el => {
            el.style.borderColor = '#dee2e6';
            el.style.background  = '#fff';
        });
        const sel = document.getElementById('copt-' + key);
        if (sel) {
            sel.style.borderColor = 'var(--accent)';
            sel.style.background  = '#f0fff4';
        }
        if (key === 'delivery') {
            delivNote.style.display = 'block';
        } else {
            delivNote.style.display = 'none';
        }
        btn.textContent = 'Create Invite & Send via WhatsApp';
    }
    updateSpCat('domestic');
    </script>
    <?php
    pageFooter();
    exit;
} // end sp_invite

// ════════════════════════════════════════════════════════
// SP SEND — show WhatsApp/SMS send buttons
// ════════════════════════════════════════════════════════
if ($action === 'sp_send') {
    $code    = $_GET['code']    ?? '';
    $waLink  = $_GET['wa']      ?? '';
    $smsLink = $_GET['sms']     ?? '';
    $emailed = !empty($_GET['emailed']);

    // Fetch SP record
    $sp = db()->prepare(
        "SELECT * FROM service_providers WHERE unique_code=? LIMIT 1"
    );
    $sp->execute([$code]);
    $sp = $sp->fetch();

    if (!$sp) {
        header('Location: visitor.php?action=select'); exit;
    }

    $cat = $spCategories[$sp['category']] ?? $spCategories['domestic'];
    $isContractorLead = $sp['category'] === 'contractor_lead';

    pageHeader('Send SP Invite', 'resident');
    renderHeader('📤 Send Invite', 'visitor.php?action=select');
    ?>
    <div class="container" style="max-width:480px;">
      <div class="card">
        <!-- Success header -->
        <div style="text-align:center;padding:16px 0 20px;">
          <div style="font-size:2.5rem;margin-bottom:8px;">✅</div>
          <div style="font-size:1.1rem;font-weight:700;color:var(--accent);">
            Invite Created
          </div>
          <div style="font-size:.85rem;color:#666;margin-top:4px;">
            Send the invite to <?= htmlspecialchars($sp['service_name']) ?>
          </div>
        </div>

        <!-- SP summary card -->
        <div style="background:#f5f7fa;border-radius:8px;
                    padding:12px 14px;margin-bottom:18px;">
          <div style="font-size:.8rem;color:#666;">
            <?= $cat['icon'] ?> <?= $cat['label'] ?>
          </div>
          <div style="font-weight:700;margin-top:2px;">
            <?= htmlspecialchars($sp['service_name']) ?>
          </div>
          <?php if ($sp['company_name']): ?>
          <div style="font-size:.85rem;color:#666;">
            <?= htmlspecialchars($sp['company_name']) ?>
          </div>
          <?php endif; ?>
          <div style="font-size:.82rem;color:#666;margin-top:4px;">
            📅 <?= date('d M Y', strtotime($sp['start_date'])) ?>
            – <?= date('d M Y', strtotime($sp['end_date'])) ?>
          </div>
          <?php if ($sp['notes']): ?>
          <div style="font-size:.8rem;color:#888;margin-top:2px;">
            <?= htmlspecialchars($sp['notes']) ?>
          </div>
          <?php endif; ?>
        </div>

        <!-- Instructions -->
        <div style="background:#e8f8ee;border:1px solid #2ecc71;
                    border-radius:8px;padding:12px 14px;
                    font-size:.85rem;margin-bottom:18px;line-height:1.6;">
          <strong>Next steps:</strong><br>
          1. Tap <strong>Send via WhatsApp</strong> below<br>
          2. Service provider receives the invite on their phone<br>
          <?php if ($isContractorLead): ?>
          3. They complete their own registration — company details, ID and
             documents — using the link in the message
          <?php else: ?>
          3. They must visit the <strong>Security Office</strong>
             with their ID<br>
          4. Security will verify and issue their access permit
          <?php endif; ?>
          <?php if ($emailed): ?>
          <br><br>📧 A copy was also e-mailed to <?= htmlspecialchars($sp['sp_email'] ?? '') ?>.
          <?php endif; ?>
        </div>

        <!-- Send buttons -->
        <a href="<?= htmlspecialchars($waLink) ?>"
           style="display:block;padding:16px;background:#25D366;color:#fff;
                  border-radius:12px;text-align:center;font-size:1.05rem;
                  font-weight:800;text-decoration:none;margin-bottom:10px;">
          📲 Send Invite via WhatsApp
        </a>
        <a href="<?= htmlspecialchars($smsLink) ?>"
           style="display:block;padding:14px;background:#f5f7fa;color:#0f2744;
                  border:2px solid #dde3ea;border-radius:12px;text-align:center;
                  font-size:.95rem;font-weight:700;text-decoration:none;
                  margin-bottom:18px;">
          💬 Send via SMS instead
        </a>

        <a href="visitor.php?action=select"
           class="btn btn-secondary btn-block">
          ← Back to My Visitors
        </a>
      </div>
    </div>
    <?php
    pageFooter();
    exit;
} // end sp_send

// ════════════════════════════════════════════════════════
// SP RESEND EMAIL — resend an existing invite by e-mail only
// ════════════════════════════════════════════════════════
if ($action === 'sp_resend_email') {
    $code = $_GET['code'] ?? '';

    $sp = db()->prepare(
        "SELECT * FROM service_providers
         WHERE unique_code=? AND resident_erfno=? AND status='invited' LIMIT 1"
    );
    $sp->execute([$code, $rerf]);
    $sp = $sp->fetch();

    if ($sp && !empty($sp['sp_email'])) {
        $content = spInviteContent($sp['category'], $sp['unique_code'], $sp['service_name'], $rname, $resAddress, $spCategories);
        spSendInviteEmail($sp['sp_email'], $content['wa_message'], $content['cat_label'], $sp['unique_code']);
        setFlash('success', 'Invite re-sent by e-mail to ' . $sp['sp_email'] . '.');
    } else {
        setFlash('error', 'Could not resend — invite not found or no e-mail on file.');
    }
    header('Location: visitor.php?action=select'); exit;
}

// ════════════════════════════════════════════════════════
// ADD VISITOR
// ════════════════════════════════════════════════════════
if ($action === 'add') {
    $isDelivery = !empty($_GET['is_delivery']);

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        $code    = makeVisitorCode();
        $visitTo = !empty($_POST['visit_date_to'])
                 ? $_POST['visit_date_to']
                 : $_POST['visit_date'];

        try {
            $pdo = db();
            $pdo->prepare("
                INSERT INTO visitors
                  (resident_erfno, resident_id,
                   resident_name, resident_address, visitor_name, plate, idnum,
                   visit_date, visit_date_to, visit_time, code, qrcode,
                   expired, status, visitor_phone)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0,'active',?)
            ")->execute([
                $rerf,
                $rid,
                $rname,
                $resAddress,
                trim($_POST['visitor_name']),
                strtoupper(trim($_POST['plate']     ?? '')),
                trim($_POST['idnum']                ?? ''),
                $_POST['visit_date'],
                $visitTo,
                trim($_POST['visit_time']           ?? ''),
                $code,
                '',
                trim($_POST['visitor_phone']        ?? ''),
            ]);
            $newId = (int)$pdo->lastInsertId();
        } catch (Exception $e) {
            setFlash('error', 'Could not save visitor: ' . $e->getMessage());
            header('Location: visitor.php?action=add'); exit;
        }

        generateQrForVisitor($newId, $code);

        // Build pass URL + WhatsApp message
        $passUrl  = SITE_URL . '/visitor_qr.php?code=' . $code;
        $fmtFrom  = date('d M Y', strtotime($_POST['visit_date']));
        $fmtTo    = date('d M Y', strtotime($visitTo));
        $vPhone   = trim($_POST['visitor_phone'] ?? '');
        $waMsg    = "🏡 GEMB " . ($isDelivery ? "Delivery" : "Visitor")
                  . " Pass\n\n"
                  . "Hi {$_POST['visitor_name']},\n\n"
                  . ($isDelivery
                    ? "You have a delivery appointment at Mossel Bay Golf Estate.\n\n"
                    : "Your access pass for Mossel Bay Golf Estate:\n\n")
                  . "📅 Valid: {$fmtFrom}"
                  . ($visitTo !== $_POST['visit_date'] ? " – {$fmtTo}" : '')
                  . "\n🏠 " . ($isDelivery ? "Deliver to" : "Visiting")
                  . ": {$rname}, {$resAddress}\n"
                  . "🔑 Gate code: {$code}\n\n"
                  . "👇 Tap to open your pass:\n{$passUrl}\n\n"
                  . "Show the QR to the guard or give them your 6-digit code.\n"
                  . "GEMB HOA | POPIA Act 4 of 2013";

        $waLink  = $vPhone ? buildWhatsAppLink($vPhone, $waMsg) : '';
        $smsMsg  = "GEMB Pass: {$rname}, {$resAddress}. "
                 . "Valid: {$fmtFrom}. Code: {$code}. Pass: {$passUrl}";
        $smsLink = $vPhone ? buildSmsLink($vPhone, $smsMsg) : '';

        header('Location: visitor_qr.php?code=' . urlencode($code)
               . '&new=1'
               . ($waLink  ? '&wa='  . urlencode($waLink)  : '')
               . ($smsLink ? '&sms=' . urlencode($smsLink) : ''));
        exit;
    }

    pageHeader($isDelivery ? 'Delivery Pass' : 'Invite Visitor', 'resident');
    renderHeader(
        $isDelivery ? '📦 Create Delivery Pass' : '➕ Invite Visitor',
        'visitor.php?action=select'
    );
    ?>
    <div class="container" style="max-width:520px;">
      <div class="card">
        <?= getFlash() ?>
        <form method="POST"
              action="visitor.php?action=add<?= $isDelivery ? '&is_delivery=1' : '' ?>">
          <?= csrfField() ?>
          <div class="form-group">
            <label><?= $isDelivery ? 'Delivery Person / Driver Name' : 'Visitor Full Name' ?> *</label>
            <input type="text" name="visitor_name" required>
          </div>
          <div class="form-group">
            <label>WhatsApp / Cell Number</label>
            <input type="tel" name="visitor_phone"
                   placeholder="e.g. 082 123 4567" inputmode="tel">
          </div>
          <?php if ($isDelivery): ?>
          <div class="form-group">
            <label>Vehicle / Delivery Plate</label>
            <input type="text" name="plate"
                   style="text-transform:uppercase;"
                   placeholder="e.g. CA 123 456">
          </div>
          <div class="form-group">
            <label>Company / Courier</label>
            <input type="text" name="idnum" placeholder="e.g. DHL, Takealot">
          </div>
          <?php else: ?>
          <div class="form-group">
            <label>ID Number (optional)</label>
            <input type="text" name="idnum">
          </div>
          <div class="form-group">
            <label>Vehicle Plate (optional)</label>
            <input type="text" name="plate"
                   style="text-transform:uppercase;"
                   placeholder="e.g. CBS 10009">
          </div>
          <?php endif; ?>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div class="form-group">
              <label><?= $isDelivery ? 'Delivery Date' : 'Visit Date' ?> *</label>
              <input type="date" name="visit_date" required
                     value="<?= date('Y-m-d') ?>">
            </div>
            <?php if (!$isDelivery): ?>
            <div class="form-group">
              <label>Until (multi-day)</label>
              <input type="date" name="visit_date_to"
                     value="<?= date('Y-m-d') ?>">
            </div>
            <?php else: ?>
            <input type="hidden" name="visit_date_to"
                   value="<?= date('Y-m-d') ?>">
            <?php endif; ?>
          </div>
          <?php if (!$isDelivery): ?>
          <div class="form-group">
            <label>Arrival Time (optional)</label>
            <input type="text" name="visit_time"
                   placeholder="e.g. 14:00 – 18:00">
          </div>
          <?php endif; ?>
          <button type="submit" class="btn btn-primary btn-block">
            <?= $isDelivery
                ? 'Create Delivery Pass'
                : 'Create Visitor Pass' ?>
          </button>
        </form>
        <div class="popia-notice">
          Visitor data collected under POPIA §11.
          Retained 90 days after visit date.
        </div>
      </div>
    </div>
    <?php
    pageFooter();
    exit;
} // end add

// ════════════════════════════════════════════════════════
// DELETE VISITOR
// ════════════════════════════════════════════════════════
if ($action === 'delete') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
        db()->prepare(
            "UPDATE visitors SET status='cancelled', expired=1
             WHERE id=? AND resident_name=?"
        )->execute([(int)$_POST['vid'], $rname]);
        setFlash('success', 'Visitor pass cancelled.');
    }
    header('Location: visitor.php?action=select'); exit;
}

// Fallback
header('Location: visitor.php?action=select'); exit;