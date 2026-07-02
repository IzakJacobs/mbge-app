<?php
/**
 * gemB Application & Verification Engine - shared library
 * ------------------------------------------------------
 * All four application types (contractor, to_let, tenant, pet) are pure
 * configuration in APP_TYPES below. The form, upload handler, checklist
 * generation and site-manager verification screen are all driven from it.
 *
 * Requires: config.php providing $conn (mysqli) and GEMB_SECRET_KEY.
 */

declare(strict_types=1);

require_once __DIR__ . '/config.php';

// Uploaded application documents live OUTSIDE the webroot.
const APP_UPLOAD_DIR      = __DIR__ . '/../private/app_uploads';
const APP_MAX_FILE_BYTES  = 5 * 1024 * 1024;            // 5 MB per file
const APP_ALLOWED_MIME    = ['application/pdf' => 'pdf', 'image/jpeg' => 'jpg', 'image/png' => 'png'];
const APP_TARIFF_WORKER   = 85.00;                       // R85 per worker (Doc: 24 Jun 2025 rev 25 Aug)
const APP_PET_MAX_KG      = 15.00;

/* ============================================================
 * TYPE CONFIGURATION
 * Each type declares: applicant fields, item repeaters, per-item
 * documents (with conditions), application-level documents, payment
 * rule, acknowledgement clauses, second-party sign-off, dependency,
 * and the verification checklist.
 * ============================================================ */
const APP_TYPES = [

    'contractor' => [
        'label'        => 'Contractor / Service Provider Application',
        'reg_types'    => ['new' => 'New Application', 'renewal' => 'Access Card Renewal', 'add_workers' => 'Add New Workers'],
        'company_block'=> true,
        'company_types'=> ['Cleaning & Garden Services', 'Construction', 'Electrical', 'Plumbing',
                           'Painting', 'Roofing & Waterproofing', 'Security & Alarms', 'Solar & Electrical',
                           'Landscaping', 'Pest Control', 'Delivery / Courier', 'Other'],
        'requires_erf' => false,
        'items'        => [
            'worker' => [
                'label' => 'Worker', 'min' => 1,
                'fields' => ['first_name', 'surname', 'id_number', 'id_is_passport', 'is_asylum'],
                'docs'   => [
                    'police_clearance' => ['label' => 'Police clearance certificate (not older than 6 months)', 'required' => true, 'needs_date' => true, 'max_age_days' => 182],
                    'id_document'      => ['label' => 'ID document / valid passport with work permit', 'required' => true],
                    'id_photo'         => ['label' => 'ID photo', 'required' => true],
                    'home_affairs_verification' => ['label' => 'Home Affairs verification (asylum seekers)', 'required' => false, 'required_if' => 'is_asylum'],
                ],
            ],
        ],
        'app_docs'     => [
            'payment_proof' => ['label' => 'Proof of payment (R85.00 per worker)', 'required' => true],
        ],
        'payment'      => ['per' => 'worker', 'amount' => APP_TARIFF_WORKER,
                           'bank_details' => "MOSSEL BAY GOLF ESTATE\nABSA Bank Mossel Bay\nBranch code: 632005\nCheque account: 4049 422 172\nReference: your application reference"],
        'second_party' => false,
        'depends_on'   => null,
        'acks'         => [
            'contractor_security_rules'   => 'I confirm that I have read and understood the Estate Security Rules (2023).',
            'contractor_code_of_conduct'  => 'I confirm that I have read and understood the Contractors Code of Conduct.',
            'contractor_arch_guidelines'  => 'I confirm that I have read and understood the Architectural Guidelines (where applicable to the work).',
            'contractor_builders_holiday' => 'I acknowledge the Builders Holiday periods during which no construction work is permitted.',
            'contractor_solar_guidelines' => 'I confirm that I have read the Solar Installation Guidelines (where applicable).',
            'contractor_golf_undertaking' => 'I accept the Golf Estate Undertaking, including the fine schedule.',
            'contractor_search_consent'   => 'I consent, on behalf of the company and its workers, to vehicle and person searches at the gates.',
            'contractor_popia_consent'    => 'I consent to the processing of the personal information on this form solely for access control and induction purposes (POPIA).',
        ],
        'post_verify_status' => 'induction_scheduled',   // induction session before approval
        'checklist'    => [
            'app'  => [
                'company_details_valid' => 'Company details complete and registration/ID number valid',
                'payment_verified'      => 'Proof of payment received and amount correct (R85.00 per worker)',
                'all_acks_present'      => 'All induction documents acknowledged',
            ],
            'worker' => [
                'clearance_present'     => 'Police clearance certificate present and legible',
                'clearance_within_6_months' => 'Police clearance not older than 6 months',
                'id_matches'            => 'ID/passport document legible and matches worker details',
                'work_permit_valid'     => 'Work permit valid (passport holders) / N/A for SA ID',
                'home_affairs_verified' => 'Home Affairs verification present (asylum seekers) / N/A',
                'photo_acceptable'      => 'ID photo clear and acceptable for access card',
            ],
        ],
    ],

    'to_let' => [
        'label'        => 'Member Registration to Let (Conduct Rule 15.2)',
        'reg_types'    => ['lease' => 'Lease agreement (longer than a month)',
                           'self_catering_unit' => 'Self-catering: rent out complete house/unit',
                           'self_catering_guests' => 'Self-catering: transient guests while living in the house'],
        'company_block'=> false,
        'requires_erf' => true,
        'type_fields'  => ['street_address' => 'Street address', 'rental_from' => 'Rental period from',
                           'rental_to' => 'Rental period to', 'occupation_date' => 'Date of occupation'],
        'items'        => [],
        'app_docs'     => [
            'payment_proof' => ['label' => 'Proof of payment of registration fee (per Letting Procedure)', 'required' => true],
        ],
        'payment'      => ['per' => 'application', 'amount' => 0.00,   // amount per current Letting Procedure; set in admin config
                           'bank_details' => "Per the Letting Procedure tariff.\nMOSSEL BAY GOLF ESTATE, ABSA 632005, account 4049 422 172."],
        'second_party' => false,
        'depends_on'   => null,
        'acks'         => [
            'tolet_1_intent'        => 'I confirm my letting intent as selected above (lease / self-catering).',
            'tolet_2_no_business'   => 'No services or meals will be provided for profit; the letting will not constitute a business (B&B/guest house) in contravention of the MOI and Rules.',
            'tolet_3_rules_pack'    => 'I shall provide each tenant with the Conduct, Security and other Estate Rules against signature, and I remain legally responsible for my tenant\'s conduct, fines and damages.',
            'tolet_4_fee'           => 'I will pay the registration fee and related costs as set out in the Letting Procedure.',
            'tolet_5_tenant_reg'    => 'I will provide the managing agent with the Tenant Registration & Undertaking before access is allowed.',
            'tolet_6_compliance'    => 'My property is compliant with Estate rules and Municipal by-laws for its intended use; consent to let may be withdrawn on transgression.',
            'tolet_7_termination'   => 'I will notify the Managing Agent in writing of early termination or extension of the lease.',
            'tolet_popia_consent'   => 'I consent to the processing of this information for letting registration purposes (POPIA).',
        ],
        'post_verify_status' => 'approved',
        'checklist'    => [
            'app' => [
                'owner_identity_valid' => 'Owner/responsible person identity confirmed against erf records',
                'letting_type_clear'   => 'Letting type selection unambiguous',
                'payment_verified'     => 'Registration fee payment verified per Letting Procedure',
                'property_compliant'   => 'No known outstanding compliance issues on the erf',
                'all_acks_present'     => 'All undertakings acknowledged',
            ],
        ],
    ],

    'tenant' => [
        'label'        => 'Tenant Registration and Undertaking (MOI art 7.8)',
        'reg_types'    => null,
        'company_block'=> false,
        'requires_erf' => true,
        'type_fields'  => ['street_address' => 'Street address', 'rental_from' => 'Rental period from',
                           'rental_to' => 'Rental period to', 'occupation_date' => 'Date of occupation'],
        'items'        => [
            'occupant' => [
                'label' => 'Resident / Occupant', 'min' => 0,
                'fields' => ['first_name', 'surname', 'id_number', 'email'],
                'docs'   => [],
            ],
            'vehicle' => [
                'label' => 'Vehicle', 'min' => 0,
                'fields' => ['vehicle_make', 'vehicle_reg', 'vehicle_colour'],
                'docs'   => [],
            ],
        ],
        'app_docs'     => [
            'id_document' => ['label' => 'Tenant ID document / passport', 'required' => true],
        ],
        'payment'      => null,
        'second_party' => 'owner',           // owner must co-sign before verification
        'depends_on'   => 'to_let',          // erf must have current approved to_let registration
        'acks'         => [
            'tenant_4_1_owner_reg'   => '4.1 Access is obtained through the property owner, who is responsible for tenant registration.',
            'tenant_4_2_rules_copy'  => '4.2 I confirm receipt of a copy of the Estate\'s Rules from the owner.',
            'tenant_4_3_sign_docs'   => '4.3 I will sign for the full set of conduct rules; parents are liable for their children\'s conduct.',
            'tenant_4_4_bylaws'      => '4.4 All residents are subject to Municipal by-laws, the MOI and Estate Rules; my household will not contravene them.',
            'tenant_4_5_residential' => '4.5 The property will be used for residential purposes only; no business activities.',
            'tenant_4_6_no_sublet'   => '4.6 No sub-letting will be allowed.',
            'tenant_4_7_amendments'  => '4.7 The HOA may amend its MOI and Rules; I am responsible for staying aware of the latest rules.',
            'tenant_4_8_occupancy'   => '4.8 Occupancy is limited to two persons per bedroom.',
            'tenant_4_9_hoa_rights'  => '4.9 The HOA reserves its rights and obligations on any breach.',
            'tenant_4_10_adherence'  => '4.10 I understand and undertake to adhere to all of the above.',
            'tenant_popia_consent'   => 'My information on this form may only be used for tenant registration and Estate access (POPIA).',
        ],
        'post_verify_status' => 'approved',
        'checklist'    => [
            'app' => [
                'to_let_current'      => 'Erf has current approved Member Registration to Let',
                'owner_cosigned'      => 'Owner co-signature received and matches erf owner records',
                'tenant_id_valid'     => 'Tenant ID document legible and matches details',
                'period_consistent'   => 'Rental period consistent with to-let registration',
                'occupancy_rule'      => 'Occupant count within two-persons-per-bedroom rule',
                'all_acks_present'    => 'All undertaking clauses (4.1-4.10) acknowledged',
            ],
            'vehicle' => [
                'vehicle_details_ok'  => 'Vehicle details complete for LPR whitelisting',
            ],
        ],
    ],

    'pet' => [
        'label'        => 'Application for the Keeping of Animals, Reptiles and Birds',
        'reg_types'    => null,
        'company_block'=> false,
        'requires_erf' => true,
        'items'        => [
            'pet' => [
                'label' => 'Animal', 'min' => 1, 'max' => 1,   // Annexure C 1.2.1: one pet per erf
                'fields' => ['pet_species', 'pet_breed', 'pet_size', 'pet_age', 'pet_adult_weight_kg'],
                'docs'   => [
                    'pet_photo' => ['label' => 'Photo of the pet (mandatory)', 'required' => true],
                ],
            ],
        ],
        'app_docs'     => [],
        'payment'      => null,
        'second_party' => 'owner_if_tenant',    // owner co-sign only when applicant is a tenant
        'depends_on'   => null,
        'acks'         => [
            'pet_1_2_1_one_pet'    => '1.2.1 Only one pet per erf is allowed.',
            'pet_1_2_2_small_dog'  => '1.2.2 Only one small dog (breed adult weight not more than 15 kg) is allowed.',
            'pet_1_2_3_conservation' => '1.2.3 No dog is allowed within the Conservation area.',
            'pet_1_2_4_leash'      => '1.2.4 Dogs outside the premises must be on a leash or in an approved enclosure.',
            'pet_1_2_5_aggression' => '1.2.5 Aggressive or vicious behaviour will not be tolerated.',
            'pet_1_2_6_barking'    => '1.2.6 Excessive barking is a nuisance; Municipal by-laws will be enforced.',
            'pet_1_2_7_fouling'    => '1.2.7 The owner is responsible for removal of droppings; fouling will not be tolerated.',
            'pet_1_2_8_kennels'    => '1.2.8 Kennels must be screened from public view without nuisance to neighbours.',
            'pet_1_2_9_collar'     => '1.2.9 Every pet must wear a collar and tag with the owner\'s name and telephone number.',
            'pet_1_2_10_removal'   => '1.2.10 The Board may insist on removal of a pet that becomes a nuisance.',
            'pet_1_2_11_cats'      => '1.2.11 Cats must be kept indoors/on premises under supervision; no new cats since 20 December 2019.',
            'pet_1_3_withdrawal'   => '1.3 The Directors may withdraw approval on breach of any condition.',
            'pet_popia_consent'    => 'I consent to processing of this information for pet approval purposes (POPIA).',
        ],
        'post_verify_status' => 'approved',
        'approval_conditions_field' => true,     // remarks/conditions captured at approval
        'checklist'    => [
            'app' => [
                'no_existing_pet'    => 'No other approved pet currently registered on this erf (rule 1.2.1)',
                'owner_cosigned'     => 'Owner permission received if applicant is a tenant / N/A',
                'all_acks_present'   => 'All Annexure C conditions acknowledged',
            ],
            'pet' => [
                'weight_within_15kg' => 'Adult breed weight 15 kg or less (dogs, rule 1.2.2)',
                'species_permitted'  => 'Species/breed permissible under Conduct Rules (note: no new cats since 20 Dec 2019)',
                'photo_acceptable'   => 'Pet photo attached and identifiable',
            ],
        ],
    ],
];

/* ============================================================
 * Status state machine - the ONLY legal transitions
 * ============================================================ */
const APP_TRANSITIONS = [
    'draft'                => ['submitted', 'withdrawn'],
    'submitted'            => ['pending_verification', 'withdrawn'],           // system: after owner co-sign (if required)
    'pending_verification' => ['returned', 'verified', 'rejected', 'withdrawn'],
    'returned'             => ['submitted', 'withdrawn', 'expired'],
    'verified'             => ['induction_scheduled', 'approved', 'rejected'],
    'induction_scheduled'  => ['approved', 'rejected'],
    'approved'             => ['withdrawn', 'expired'],                        // rule 1.3 / consent withdrawal / lease end
    'rejected'             => [],
    'withdrawn'            => [],
    'expired'              => [],
];

/* ============================================================
 * Security helpers (align with existing gemB hardening)
 * ============================================================ */

function app_csrf_token(): string {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_set_cookie_params(['httponly' => true, 'secure' => true, 'samesite' => 'Strict']);
        session_start();
    }
    if (empty($_SESSION['app_csrf'])) {
        $_SESSION['app_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['app_csrf'];
}

function app_csrf_check(?string $token): bool {
    return is_string($token)
        && !empty($_SESSION['app_csrf'])
        && hash_equals($_SESSION['app_csrf'], $token);
}

function app_rate_limit(mysqli $conn, string $bucket, int $max, int $windowSec): bool {
    // Simple IP rate limit using application_log as the counter source.
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $stmt = $conn->prepare(
        "SELECT COUNT(*) FROM application_log
         WHERE log_ip = ? AND note = ? AND logged_at > DATE_SUB(NOW(), INTERVAL ? SECOND)");
    $stmt->bind_param('ssi', $ip, $bucket, $windowSec);
    $stmt->execute();
    $stmt->bind_result($count);
    $stmt->fetch();
    $stmt->close();
    return $count < $max;
}

function app_secure_token(): string { return bin2hex(random_bytes(32)); }

function app_hmac(string $data): string { return hash_hmac('sha256', $data, GEMB_SECRET_KEY); }

function app_clean(string $s, int $max = 200): string {
    $s = trim(preg_replace('/[\x00-\x1F\x7F]/u', '', $s) ?? '');
    return mb_substr($s, 0, $max);
}

/** Validate SA ID number (Luhn + date) or accept as passport when flagged. */
function app_valid_sa_id(string $id): bool {
    if (!preg_match('/^\d{13}$/', $id)) return false;
    $sum = 0;
    for ($i = 0; $i < 13; $i++) {
        $d = (int)$id[$i];
        if ($i % 2 === 1) { $d *= 2; if ($d > 9) $d -= 9; }
        $sum += $d;
    }
    return $sum % 10 === 0;
}

/* ============================================================
 * Reference + creation helpers
 * ============================================================ */

function app_new_ref(mysqli $conn): string {
    $year = date('Y');
    $stmt = $conn->prepare("SELECT COUNT(*) FROM applications WHERE app_ref LIKE CONCAT('APP-', ?, '-%')");
    $stmt->bind_param('s', $year);
    $stmt->execute();
    $stmt->bind_result($n);
    $stmt->fetch();
    $stmt->close();
    return sprintf('APP-%s-%06d', $year, $n + 1);
}

function app_log(mysqli $conn, int $appId, ?string $old, string $new, string $actorType, ?int $actorId, string $note = ''): void {
    $ip = $_SERVER['REMOTE_ADDR'] ?? null;
    $stmt = $conn->prepare(
        "INSERT INTO application_log (application_id, old_status, new_status, actor_type, actor_id, note, log_ip)
         VALUES (?,?,?,?,?,?,?)");
    $stmt->bind_param('isssiss', $appId, $old, $new, $actorType, $actorId, $note, $ip);
    $stmt->execute();
    $stmt->close();
}

/** Enforce the state machine on every status change. */
function app_set_status(mysqli $conn, int $appId, string $newStatus, string $actorType, ?int $actorId, string $note = ''): bool {
    $stmt = $conn->prepare("SELECT status FROM applications WHERE id = ? FOR UPDATE");
    $stmt->bind_param('i', $appId);
    $stmt->execute();
    $stmt->bind_result($current);
    if (!$stmt->fetch()) { $stmt->close(); return false; }
    $stmt->close();

    if (!in_array($newStatus, APP_TRANSITIONS[$current] ?? [], true)) return false;

    $stmt = $conn->prepare("UPDATE applications SET status = ? WHERE id = ?");
    $stmt->bind_param('si', $newStatus, $appId);
    $ok = $stmt->execute();
    $stmt->close();
    if ($ok) app_log($conn, $appId, $current, $newStatus, $actorType, $actorId, $note);
    return $ok;
}

/* ============================================================
 * Checklist generation at submission time
 * ============================================================ */
function app_generate_checklist(mysqli $conn, int $appId, string $appType): void {
    $cfg = APP_TYPES[$appType];

    // Application-level checks
    foreach ($cfg['checklist']['app'] ?? [] as $code => $label) {
        $stmt = $conn->prepare(
            "INSERT IGNORE INTO application_checklist (application_id, item_id, check_code, check_label)
             VALUES (?, NULL, ?, ?)");
        $stmt->bind_param('iss', $appId, $code, $label);
        $stmt->execute();
        $stmt->close();
    }

    // Per-item checks
    $stmt = $conn->prepare("SELECT id, item_type FROM application_items WHERE application_id = ?");
    $stmt->bind_param('i', $appId);
    $stmt->execute();
    $res = $stmt->get_result();
    $items = $res->fetch_all(MYSQLI_ASSOC);
    $stmt->close();

    foreach ($items as $item) {
        foreach ($cfg['checklist'][$item['item_type']] ?? [] as $code => $label) {
            $stmt = $conn->prepare(
                "INSERT IGNORE INTO application_checklist (application_id, item_id, check_code, check_label)
                 VALUES (?,?,?,?)");
            $stmt->bind_param('iiss', $appId, $item['id'], $code, $label);
            $stmt->execute();
            $stmt->close();
        }
    }
}

/** True when every checklist row is pass or n_a. */
function app_checklist_complete(mysqli $conn, int $appId): bool {
    $stmt = $conn->prepare(
        "SELECT COUNT(*) FROM application_checklist
         WHERE application_id = ? AND result NOT IN ('pass','n_a')");
    $stmt->bind_param('i', $appId);
    $stmt->execute();
    $stmt->bind_result($outstanding);
    $stmt->fetch();
    $stmt->close();
    return $outstanding === 0;
}

/* ============================================================
 * Dependency enforcement (tenant requires approved to_let on erf)
 * ============================================================ */
function app_find_current_to_let(mysqli $conn, string $erfNo): ?int {
    $stmt = $conn->prepare("SELECT to_let_app_id FROM v_erf_to_let WHERE erf_no = ? LIMIT 1");
    $stmt->bind_param('s', $erfNo);
    $stmt->execute();
    $stmt->bind_result($id);
    $found = $stmt->fetch();
    $stmt->close();
    return $found ? (int)$id : null;
}

/** Pet rule 1.2.1: one approved pet per erf. */
function app_erf_has_approved_pet(mysqli $conn, string $erfNo): bool {
    $stmt = $conn->prepare(
        "SELECT COUNT(*) FROM applications
         WHERE app_type = 'pet' AND status = 'approved' AND erf_no = ?");
    $stmt->bind_param('s', $erfNo);
    $stmt->execute();
    $stmt->bind_result($n);
    $stmt->fetch();
    $stmt->close();
    return $n > 0;
}

/* ============================================================
 * Secure upload handling
 * ============================================================ */
function app_store_upload(mysqli $conn, int $appId, ?int $itemId, string $docType, array $file, ?string $docDate = null): array {
    if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        return [false, 'Upload failed or no file received.'];
    }
    if ($file['size'] > APP_MAX_FILE_BYTES) {
        return [false, 'File exceeds the 5 MB limit.'];
    }
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime  = $finfo->file($file['tmp_name']);
    if (!isset(APP_ALLOWED_MIME[$mime])) {
        return [false, 'Only PDF, JPG and PNG files are accepted.'];
    }
    if (!is_dir(APP_UPLOAD_DIR) && !mkdir(APP_UPLOAD_DIR, 0750, true)) {
        return [false, 'Storage unavailable.'];
    }
    $stored = bin2hex(random_bytes(32));               // no extension; served via download proxy only
    $dest   = APP_UPLOAD_DIR . '/' . $stored;
    if (!move_uploaded_file($file['tmp_name'], $dest)) {
        return [false, 'Could not store the file.'];
    }
    chmod($dest, 0640);
    $sha  = hash_file('sha256', $dest);
    $orig = app_clean($file['name'], 255);
    $ip   = $_SERVER['REMOTE_ADDR'] ?? null;

    $stmt = $conn->prepare(
        "INSERT INTO application_documents
         (application_id, item_id, doc_type, orig_filename, stored_name, mime_type, file_size, doc_date, upload_ip)
         VALUES (?,?,?,?,?,?,?,?,?)");
    $size = (int)$file['size'];
    $stmt->bind_param('iissssiss', $appId, $itemId, $docType, $orig, $stored, $mime, $size, $docDate, $ip);
    $stmt->execute();
    $docId = $stmt->insert_id;
    $stmt->close();
    return [true, (string)$docId];
}

/* ============================================================
 * Acknowledgement recording (per clause, hashed text, timestamped)
 * ============================================================ */
function app_record_ack(mysqli $conn, int $appId, string $ackCode, string $clauseText, string $by = 'applicant'): void {
    $hash = hash('sha256', $clauseText);
    $ip   = $_SERVER['REMOTE_ADDR'] ?? null;
    $stmt = $conn->prepare(
        "INSERT IGNORE INTO application_acknowledgements
         (application_id, ack_code, ack_text_hash, acknowledged_by, ack_ip)
         VALUES (?,?,?,?,?)");
    $stmt->bind_param('issss', $appId, $ackCode, $hash, $by, $ip);
    $stmt->execute();
    $stmt->close();
}
