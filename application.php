<?php
// ============================================================
// GEMB Access Control — application_lib.php
// Application & Verification Engine (contractor / to_let / tenant / pet)
// Conventions: PDO via db(), layout.php helpers, POPIA audit trail.
// ============================================================
require_once __DIR__ . '/layout.php';

// Uploaded application documents live OUTSIDE the webroot.
if (!defined('APP_UPLOAD_DIR'))       define('APP_UPLOAD_DIR', __DIR__ . '/../private/app_uploads');
if (!defined('APP_MAX_FILE_BYTES'))   define('APP_MAX_FILE_BYTES', 5 * 1024 * 1024);   // 5 MB
if (!defined('APP_TARIFF_WORKER'))    define('APP_TARIFF_WORKER', 85.00);              // R85 pp (procedure doc)
if (!defined('APP_PET_MAX_KG'))       define('APP_PET_MAX_KG', 15.00);
if (!defined('APP_CARD_VALID_MONTHS'))define('APP_CARD_VALID_MONTHS', 12);             // contractor card validity

const APP_ALLOWED_MIME = ['application/pdf' => 'pdf', 'image/jpeg' => 'jpg', 'image/png' => 'png'];

// ════════════════════════════════════════════════════════
// TYPE CONFIGURATION — all four GEMB forms as pure config
// ════════════════════════════════════════════════════════
const APP_TYPES = [

    'contractor' => [
        'label'        => 'Contractor / Service Provider Application',
        'icon'         => '👷',
        'reg_types'    => ['new' => 'New Application', 'renewal' => 'Access Card Renewal', 'add_workers' => 'Add New Workers'],
        'company_block'=> true,
        'company_types'=> ['Cleaning & Garden Services', 'Construction', 'Electrical', 'Plumbing',
                           'Painting', 'Roofing & Waterproofing', 'Security & Alarms', 'Solar & Electrical',
                           'Landscaping', 'Pest Control', 'Delivery / Supplier', 'Other'],
        'requires_erf' => false,
        'items'        => [
            'worker' => [
                'label' => 'Worker', 'min' => 1, 'max' => 99,
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
        'post_verify_status' => 'induction_scheduled',
        'checklist'    => [
            'app'  => [
                'company_details_valid' => 'Company details complete and registration/ID number valid',
                'payment_verified'      => 'Proof of payment received and amount correct (R85.00 per worker)',
                'all_acks_present'      => 'All induction documents acknowledged',
            ],
            'worker' => [
                'clearance_present'         => 'Police clearance certificate present and legible',
                'clearance_within_6_months' => 'Police clearance not older than 6 months',
                'id_matches'                => 'ID/passport document legible and matches worker details',
                'work_permit_valid'         => 'Work permit valid (passport holders) / N/A for SA ID',
                'home_affairs_verified'     => 'Home Affairs verification present (asylum seekers) / N/A',
                'photo_acceptable'          => 'ID photo clear and acceptable for access card',
            ],
        ],
    ],

    'estate_agent' => [
        'label'        => 'Estate Agent Registration (GEMB Requirements & Rules 2023)',
        'icon'         => '🏢',
        'reg_types'    => ['new' => 'New Registration', 'renewal' => 'Annual Renewal'],
        'company_block'=> true,
        'company_types'=> null,          // agency name/principal captured; no trade category applies
        'requires_erf' => false,
        'type_fields'  => ['agency_phone' => 'Agency telephone number (as marked on vehicles)'],
        'type_fields_title' => 'Agency Details',
        'items'        => [
            'vehicle' => [
                'label' => 'Agency Vehicle (must be branded on both sides)', 'min' => 0, 'max' => 3,
                'fields' => ['vehicle_make', 'vehicle_reg', 'vehicle_colour'],
                'docs'   => [],
            ],
        ],
        'app_docs'     => [
            'ffc_agent'         => ['label' => 'Fidelity Fund Certificate — Agent', 'required' => true],
            'ffc_principal'     => ['label' => 'Fidelity Fund Certificate — Principal / Firm', 'required' => true],
            'employment_letter' => ['label' => 'Letter of Employment from the Principal', 'required' => true],
            'payment_proof'     => ['label' => 'Proof of payment (R150.00 access card + R100.00 administration fee)', 'required' => true],
        ],
        'payment'      => ['per' => 'application', 'amount' => 250.00,
                           'bank_details' => "R150.00 gate access card fee (HOA):\nMOSSEL BAY GOLF ESTATE, ABSA Bank Mossel Bay\nBranch code: 632005, Cheque account: 4049 422 172\nReference: your application reference\n\nR100.00 administration fee — payable to the Managing Agent (Status-Mark), banking details per their invoice."],
        'second_party' => false,
        'depends_on'   => null,
        'acks'         => [
            'agent_cs_gate'        => 'I acknowledge that access is obtained only through the contractor gate at Church Street.',
            'agent_card_display'   => 'I will display my gate access card and provide the security officer with the owner\'s name and the address of the property being visited.',
            'agent_card_personal'  => 'The gate access card is issued to me personally and is not transferable.',
            'agent_vehicle_branded'=> 'Vehicles I use to enter the estate will be clearly marked on both sides with the agency\'s name and telephone number.',
            'agent_purpose_only'   => 'I will visit the estate only to negotiate with prospective sellers or to bring prospective buyers to view properties for sale; no estate tours.',
            'agent_accompany'      => 'I will meet prospective buyers at the entrance gate and accompany them; buyers may not enter in their own vehicles or visit unaccompanied, and will leave the estate with me.',
            'agent_responsible'    => 'I am responsible for the behaviour and conduct of prospective buyers from entry until they leave the estate.',
            'agent_no_concessions' => 'I have no right to make concessions on estate rules, will not create any expectation of deviation, and will convey the rules to buyers as I received them.',
            'agent_rules_signed'   => 'I will ensure each new owner/tenant receives and signs the estate rules, handed to the Managing Agency before access is granted to them.',
            'agent_no_mechanisms'  => 'Sellers\' access mechanisms are not transferable, and I will not use any owner\'s or seller\'s access mechanism to enter or exit the estate.',
            'agent_pets_workers'   => 'I will ensure buyers/tenants understand the rules on pets (written authorisation in advance) and worker access (arranged in advance with estate management).',
            'agent_no_marketing'   => 'I will not market on the estate or go door-to-door distributing calendars, business cards or pamphlets — this also applies to agents residing on the estate.',
            'agent_signage'        => 'No for-sale/to-let boards in windows, on sidewalks, in yards or on walkways; show-day signs only within the marketed property\'s boundaries, removed after the showing, failing which they are confiscated.',
            'agent_cancellation'   => 'I understand that disregarding any of these requirements/rules may result in immediate cancellation of my access to the estate.',
            'agent_popia_consent'  => 'I consent to the processing of the personal information on this form solely for estate agent registration and access control purposes (POPIA).',
        ],
        'post_verify_status' => 'induction_scheduled',   // induction at the Managing Agent's office
        'checklist'    => [
            'app' => [
                'registered_with_ma'   => 'Agent registered with the Managing Agency',
                'ffc_agent_valid'      => 'Fidelity Fund Certificate (agent) present and currently valid',
                'ffc_principal_valid'  => 'Fidelity Fund Certificate (principal/firm) present and currently valid',
                'employment_letter_ok' => 'Letter of employment from the principal present and on agency letterhead',
                'payment_hoa_verified' => 'R150.00 gate access card fee received by the HOA',
                'payment_ma_verified'  => 'R100.00 administration fee received by the Managing Agent',
                'vehicle_branding'     => 'Vehicle branding (agency name + phone, both sides) confirmed / to be confirmed at induction',
                'all_acks_present'     => 'All requirements and rules acknowledged',
            ],
        ],
    ],

    'to_let' => [
        'label'        => 'Member Registration to Let (Conduct Rule 15.2)',
        'icon'         => '🏠',
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
        'payment'      => ['per' => 'application', 'amount' => 0.00,
                           'bank_details' => "Registration fee per the Letting Procedure tariff.\nMOSSEL BAY GOLF ESTATE, ABSA 632005, account 4049 422 172."],
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
        'icon'         => '🔑',
        'reg_types'    => null,
        'company_block'=> false,
        'requires_erf' => true,
        'type_fields'  => ['street_address' => 'Street address', 'rental_from' => 'Rental period from',
                           'rental_to' => 'Rental period to', 'occupation_date' => 'Date of occupation'],
        'items'        => [
            'occupant' => [
                'label' => 'Resident / Occupant', 'min' => 0, 'max' => 20,
                'fields' => ['first_name', 'surname', 'id_number', 'email'],
                'docs'   => [],
            ],
            'vehicle' => [
                'label' => 'Vehicle', 'min' => 0, 'max' => 10,
                'fields' => ['vehicle_make', 'vehicle_reg', 'vehicle_colour'],
                'docs'   => [],
            ],
        ],
        'app_docs'     => [
            'id_document' => ['label' => 'Tenant ID document / passport', 'required' => true],
        ],
        'payment'      => null,
        'second_party' => 'owner',
        'depends_on'   => 'to_let',
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
                'all_acks_present'    => 'All undertaking clauses (4.1–4.10) acknowledged',
            ],
            'vehicle' => [
                'vehicle_details_ok'  => 'Vehicle details complete for LPR whitelisting',
            ],
        ],
    ],

    'pet' => [
        'label'        => 'Application for the Keeping of Animals, Reptiles and Birds',
        'icon'         => '🐕',
        'reg_types'    => null,
        'company_block'=> false,
        'requires_erf' => true,
        'items'        => [
            'pet' => [
                'label' => 'Animal', 'min' => 1, 'max' => 1,   // Annexure C 1.2.1
                'fields' => ['pet_name', 'pet_species', 'pet_breed', 'pet_size', 'pet_age', 'pet_adult_weight_kg'],
                'docs'   => [
                    'pet_photo' => ['label' => 'Photo of the pet (mandatory)', 'required' => true],
                ],
            ],
        ],
        'app_docs'     => [],
        'payment'      => null,
        'second_party' => 'owner_if_tenant',
        'depends_on'   => null,
        'acks'         => [
            'pet_1_2_1_one_pet'      => '1.2.1 Only one pet per erf is allowed.',
            'pet_1_2_2_small_dog'    => '1.2.2 Only one small dog (breed adult weight not more than 15 kg) is allowed.',
            'pet_1_2_3_conservation' => '1.2.3 No dog is allowed within the Conservation area.',
            'pet_1_2_4_leash'        => '1.2.4 Dogs outside the premises must be on a leash or in an approved enclosure.',
            'pet_1_2_5_aggression'   => '1.2.5 Aggressive or vicious behaviour will not be tolerated.',
            'pet_1_2_6_barking'      => '1.2.6 Excessive barking is a nuisance; Municipal by-laws will be enforced.',
            'pet_1_2_7_fouling'      => '1.2.7 The owner is responsible for removal of droppings; fouling will not be tolerated.',
            'pet_1_2_8_kennels'      => '1.2.8 Kennels must be screened from public view without nuisance to neighbours.',
            'pet_1_2_9_collar'       => '1.2.9 Every pet must wear a collar and tag with the owner\'s name and telephone number.',
            'pet_1_2_10_removal'     => '1.2.10 The Board may insist on removal of a pet that becomes a nuisance.',
            'pet_1_2_11_cats'        => '1.2.11 Cats must be kept indoors/on premises under supervision; no new cats since 20 December 2019.',
            'pet_1_3_withdrawal'     => '1.3 The Directors may withdraw approval on breach of any condition.',
            'pet_popia_consent'      => 'I consent to processing of this information for pet approval purposes (POPIA).',
        ],
        'post_verify_status' => 'approved',
        'approval_conditions_field' => true,
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

// Status state machine — the ONLY legal transitions
const APP_TRANSITIONS = [
    'draft'                => ['submitted', 'withdrawn'],
    'submitted'            => ['pending_verification', 'withdrawn'],
    'pending_verification' => ['returned', 'verified', 'rejected', 'withdrawn'],
    'returned'             => ['submitted', 'withdrawn', 'expired'],
    'verified'             => ['induction_scheduled', 'approved', 'rejected'],
    'induction_scheduled'  => ['approved', 'rejected'],
    'approved'             => ['withdrawn', 'expired'],
    'rejected'             => [],
    'withdrawn'            => [],
    'expired'              => [],
];

// ════════════════════════════════════════════════════════
// HELPERS (PDO throughout)
// ════════════════════════════════════════════════════════

function appClean(string $s, int $max = 200): string {
    $s = trim(preg_replace('/[\x00-\x1F\x7F]/u', '', $s) ?? '');
    return mb_substr($s, 0, $max);
}

function appSecureToken(): string { return bin2hex(random_bytes(32)); }

/** SA ID Luhn validation; passports are exempted via the checkbox. */
function appValidSaId(string $id): bool {
    if (!preg_match('/^\d{13}$/', $id)) return false;
    $sum = 0;
    for ($i = 0; $i < 13; $i++) {
        $d = (int)$id[$i];
        if ($i % 2 === 1) { $d *= 2; if ($d > 9) $d -= 9; }
        $sum += $d;
    }
    return $sum % 10 === 0;
}

/** Simple IP rate limit backed by application_log. */
function appRateLimit(string $bucket, int $max, int $windowSec): bool {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $stmt = db()->prepare(
        "SELECT COUNT(*) FROM application_log
         WHERE log_ip = ? AND note = ? AND logged_at > DATE_SUB(NOW(), INTERVAL {$windowSec} SECOND)"
    );
    $stmt->execute([$ip, $bucket]);
    return (int)$stmt->fetchColumn() < $max;
}

function appNewRef(): string {
    $year = date('Y');
    $stmt = db()->prepare("SELECT COUNT(*) FROM applications WHERE app_ref LIKE ?");
    $stmt->execute(['APP-' . $year . '-%']);
    return sprintf('APP-%s-%06d', $year, (int)$stmt->fetchColumn() + 1);
}

function appLog(int $appId, ?string $old, string $new, string $actorType, ?int $actorId, string $note = ''): void {
    db()->prepare(
        "INSERT INTO application_log (application_id, old_status, new_status, actor_type, actor_id, note, log_ip)
         VALUES (?,?,?,?,?,?,?)"
    )->execute([$appId, $old, $new, $actorType, $actorId, $note, $_SERVER['REMOTE_ADDR'] ?? null]);
}

/** Enforce the state machine on every status change. */
function appSetStatus(int $appId, string $newStatus, string $actorType, ?int $actorId, string $note = ''): bool {
    $stmt = db()->prepare("SELECT status FROM applications WHERE id = ? FOR UPDATE");
    $stmt->execute([$appId]);
    $current = $stmt->fetchColumn();
    if ($current === false) return false;
    if (!in_array($newStatus, APP_TRANSITIONS[$current] ?? [], true)) return false;

    db()->prepare("UPDATE applications SET status = ? WHERE id = ?")->execute([$newStatus, $appId]);
    appLog($appId, $current, $newStatus, $actorType, $actorId, $note);
    return true;
}

function appGenerateChecklist(int $appId, string $appType): void {
    $cfg = APP_TYPES[$appType];
    $ins = db()->prepare(
        "INSERT IGNORE INTO application_checklist (application_id, item_id, check_code, check_label)
         VALUES (?,?,?,?)"
    );
    foreach ($cfg['checklist']['app'] ?? [] as $code => $label) {
        $ins->execute([$appId, null, $code, $label]);
    }
    $stmt = db()->prepare("SELECT id, item_type FROM application_items WHERE application_id = ?");
    $stmt->execute([$appId]);
    foreach ($stmt->fetchAll() as $item) {
        foreach ($cfg['checklist'][$item['item_type']] ?? [] as $code => $label) {
            $ins->execute([$appId, $item['id'], $code, $label]);
        }
    }
}

function appChecklistComplete(int $appId): bool {
    $stmt = db()->prepare(
        "SELECT COUNT(*) FROM application_checklist
         WHERE application_id = ? AND result NOT IN ('pass','n_a')"
    );
    $stmt->execute([$appId]);
    return (int)$stmt->fetchColumn() === 0;
}

/** Tenant dependency: current approved to_let on the erf. */
function appFindCurrentToLet(string $erfNo): ?int {
    $stmt = db()->prepare("SELECT to_let_app_id FROM v_erf_to_let WHERE erf_no = ? LIMIT 1");
    $stmt->execute([$erfNo]);
    $id = $stmt->fetchColumn();
    return $id === false ? null : (int)$id;
}

/** Pet rule 1.2.1: one approved pet per erf. */
function appErfHasApprovedPet(string $erfNo): bool {
    $stmt = db()->prepare(
        "SELECT COUNT(*) FROM applications WHERE app_type='pet' AND status='approved' AND erf_no = ?"
    );
    $stmt->execute([$erfNo]);
    return (int)$stmt->fetchColumn() > 0;
}

// ── Secure upload handling ────────────────────────────────
function appStoreUpload(int $appId, ?int $itemId, string $docType, array $file, ?string $docDate = null): array {
    if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) return [false, 'Upload failed or no file received.'];
    if ($file['size'] > APP_MAX_FILE_BYTES) return [false, 'File exceeds the 5 MB limit.'];

    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime  = $finfo->file($file['tmp_name']);
    if (!isset(APP_ALLOWED_MIME[$mime])) return [false, 'Only PDF, JPG and PNG files are accepted.'];

    if (!is_dir(APP_UPLOAD_DIR) && !@mkdir(APP_UPLOAD_DIR, 0750, true)) return [false, 'Storage unavailable.'];

    $stored = bin2hex(random_bytes(32));
    $dest   = APP_UPLOAD_DIR . '/' . $stored;
    if (!move_uploaded_file($file['tmp_name'], $dest)) return [false, 'Could not store the file.'];
    @chmod($dest, 0640);

    db()->prepare(
        "INSERT INTO application_documents
         (application_id, item_id, doc_type, orig_filename, stored_name, mime_type, file_size, sha256, doc_date, upload_ip)
         VALUES (?,?,?,?,?,?,?,?,?,?)"
    )->execute([
        $appId, $itemId, $docType,
        appClean($file['name'], 255), $stored, $mime, (int)$file['size'],
        hash_file('sha256', $dest), $docDate, $_SERVER['REMOTE_ADDR'] ?? null,
    ]);
    return [true, db()->lastInsertId()];
}

// ── Acknowledgement recording (per clause, hashed, timestamped) ──
function appRecordAck(int $appId, string $ackCode, string $clauseText, string $by = 'applicant'): void {
    db()->prepare(
        "INSERT IGNORE INTO application_acknowledgements
         (application_id, ack_code, ack_text_hash, acknowledged_by, ack_ip)
         VALUES (?,?,?,?,?)"
    )->execute([$appId, $ackCode, hash('sha256', $clauseText), $by, $_SERVER['REMOTE_ADDR'] ?? null]);
}

// ════════════════════════════════════════════════════════
// UNIQUE CODE + QR — identical conventions to security.php
// ════════════════════════════════════════════════════════

/** '7' + 5 digits, unique in service_providers — same as estate_sp_add. */
function appNewSpUniqueCode(): string {
    do {
        $unique = '7' . str_pad((string)random_int(0, 99999), 5, '0', STR_PAD_LEFT);
        $chk = db()->prepare("SELECT id FROM service_providers WHERE unique_code=? LIMIT 1");
        $chk->execute([$unique]);
    } while ($chk->rowCount() > 0);
    return $unique;
}

/** Mirror of generateSpQr() in security.php (same phpqrcode lib, temp dir, URL). */
function appGenerateSpQr(int $spId): void {
    $qrLib = __DIR__ . '/phpqrcode/qrlib.php';
    if (!file_exists($qrLib)) return;
    require_once $qrLib;
    $row = db()->prepare("SELECT unique_code FROM service_providers WHERE id=? LIMIT 1");
    $row->execute([$spId]);
    $row = $row->fetch();
    if (!$row) return;
    $code      = $row['unique_code'];
    $verifyUrl = SITE_URL . '/service_qr_verify.php?code=' . urlencode($code);
    $tempDir   = __DIR__ . '/temp';
    if (!is_dir($tempDir)) @mkdir($tempDir, 0755, true);
    $filePath  = $tempDir . '/' . $code . '.png';
    QRcode::png($verifyUrl, $filePath, QR_ECLEVEL_M, 6, 2);
    if (file_exists($filePath)) {
        db()->prepare("UPDATE service_providers SET qrcode=? WHERE id=?")->execute(['/temp/' . $code . '.png', $spId]);
    }
}

// ════════════════════════════════════════════════════════
// APPROVAL BRIDGE — push an approved contractor application
// into the LIVE service_providers table.
// Called from the applications admin at final approval
// (after induction). Creates one contractor_lead (the contact
// person) + one contractor_worker per passed worker, exactly
// mirroring the estate_sp_add column set and value formats.
// ════════════════════════════════════════════════════════
function appBridgeContractorToSp(int $appId, string $approverName): array {
    $pdo = db();

    $stmt = $pdo->prepare("SELECT * FROM applications WHERE id=? LIMIT 1");
    $stmt->execute([$appId]);
    $app = $stmt->fetch();
    if (!$app || $app['app_type'] !== 'contractor') return [0, 0];

    // Idempotence: never bridge the same application twice.
    $chk = $pdo->prepare("SELECT COUNT(*) FROM service_providers WHERE notes LIKE ?");
    $chk->execute(['%[gemB ' . $app['app_ref'] . ']%']);
    if ((int)$chk->fetchColumn() > 0) return [0, 0];

    $startDate = date('Y-m-d');
    $endDate   = date('Y-m-d', strtotime('+' . APP_CARD_VALID_MONTHS . ' months'));
    $noteTag   = '[gemB ' . $app['app_ref'] . ']';

    // ── Resident invite linkage: if the application was completed from a
    //    resident's Contractor Lead invite (type_data.invite_code), inherit
    //    that resident's erf/name (as sp_add does from a lead) and supersede
    //    the placeholder invite record so it cannot be approved separately.
    $resErfno  = '';
    $resName   = 'GEMB Estate';
    $invitedBy = null;
    $td = $app['type_data'] ? json_decode($app['type_data'], true) : [];
    if (!empty($td['invite_code']) && preg_match('/^\d{6}$/', (string)$td['invite_code'])) {
        $inv = $pdo->prepare(
            "SELECT id, resident_erfno, resident_name, invited_by_resident_id FROM service_providers
             WHERE unique_code = ? AND category = 'contractor_lead' LIMIT 1"
        );
        $inv->execute([$td['invite_code']]);
        if ($invRow = $inv->fetch()) {
            $resErfno  = $invRow['resident_erfno'] ?? '';
            $resName   = $invRow['resident_name'] ?: 'GEMB Estate';
            $invitedBy = $invRow['invited_by_resident_id'] !== null ? (int)$invRow['invited_by_resident_id'] : null;
            $pdo->prepare(
                "UPDATE service_providers
                 SET expired = 1,
                     notes = CONCAT(notes, ' [Superseded by application ', ?, ']')
                 WHERE id = ?"
            )->execute([$app['app_ref'], $invRow['id']]);
        }
    }

    // 1) Contractor Lead = the application contact person (card permit, Mon–Fri)
    $leadCode = appNewSpUniqueCode();
    $pdo->prepare("
        INSERT INTO service_providers
          (resident_erfno, resident_name, service_name, company_name,
           id_number, sp_phone, category, permit_type, lead_id,
           once_off, access_days, access_start, access_end,
           start_date, end_date, notes,
           unique_code, status, approved, expired,
           invited_by_resident_id, id_verified, approved_by, approved_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'approved','true',0,?,1,?,NOW())
    ")->execute([
        $resErfno, $resName,
        $app['applicant_name'], $app['company_name'] ?? '',
        $app['applicant_id_no'] ?? '', $app['applicant_phone'] ?? '',
        'contractor_lead', 'card', null,
        0, 'Mon,Tue,Wed,Thu,Fri', '07:00:00', '17:00:00',
        $startDate, $endDate,
        'Contact person — ' . ($app['company_name'] ?? '') . ' ' . $noteTag,
        $leadCode, $invitedBy, $approverName,
    ]);
    $leadId = (int)$pdo->lastInsertId();
    appGenerateSpQr($leadId);

    // 2) One contractor_worker per verified worker (slip permit, linked to lead)
    $ws = $pdo->prepare(
        "SELECT * FROM application_items
         WHERE application_id=? AND item_type='worker' AND item_status <> 'failed'"
    );
    $ws->execute([$appId]);
    $workers = $ws->fetchAll();

    $insW = $pdo->prepare("
        INSERT INTO service_providers
          (resident_erfno, resident_name, service_name, company_name,
           id_number, sp_phone, category, permit_type, lead_id,
           once_off, access_days, access_start, access_end,
           start_date, end_date, notes,
           unique_code, status, approved, expired,
           invited_by_resident_id, id_verified, approved_by, approved_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'approved','true',0,?,1,?,NOW())
    ");
    $n = 0;
    foreach ($workers as $w) {
        $code = appNewSpUniqueCode();
        $insW->execute([
            $resErfno, $resName,
            trim(($w['first_name'] ?? '') . ' ' . ($w['surname'] ?? '')),
            $app['company_name'] ?? '',
            $w['id_number'] ?? '', $app['applicant_phone'] ?? '',   // workers carry the contact person's number
            'contractor_worker', 'slip', $leadId,
            0, 'Mon,Tue,Wed,Thu,Fri', '07:00:00', '17:00:00',
            $startDate, $endDate,
            'Access card worker ' . $noteTag,
            $code, $invitedBy, $approverName,
        ]);
        appGenerateSpQr((int)$pdo->lastInsertId());
        $n++;
    }
    return [$leadId, $n];
}

// ════════════════════════════════════════════════════════
// LIVE-TABLE BRIDGES (tenant / pet) — mirror the contractor
// bridge pattern: fire once at approval, idempotent via an
// app_ref marker, exact live column sets from SHOW CREATE TABLE.
// ════════════════════════════════════════════════════════

/** Next free occupant code on an erf: A is the primary and never reused;
 *  letters are never reused even after deactivation (per estate convention),
 *  so we take the first letter after the highest ever used. */
function appNextOccupantCode(string $erfNo): ?string {
    $stmt = db()->prepare(
        "SELECT MAX(occupant_code) FROM residents WHERE resident_erfno = ?"
    );
    $stmt->execute([$erfNo]);
    $max = $stmt->fetchColumn();
    if ($max === false || $max === null || $max === '') return 'B'; // erf unknown to residents: start additional occupants at B
    $next = chr(ord(strtoupper((string)$max)) + 1);
    return ($next >= 'B' && $next <= 'Z') ? $next : null;           // exhausted A–Z (should never happen)
}

/**
 * TENANT BRIDGE — on approval of a tenant application:
 *  1) INSERT into live `tenants` (status approved, lease dates from type_data)
 *  2) CREATE a `residents` row for the tenant (next occupant code, type 'tenant')
 *  3) INSERT each 'vehicle' item into `resident_vehicles` under that resident id
 * Returns [tenantId, residentId, vehicleCount]; [0,0,0] if already bridged.
 */
function appBridgeTenantToLive(int $appId, string $approverName): array {
    $pdo = db();

    $stmt = $pdo->prepare("SELECT * FROM applications WHERE id=? LIMIT 1");
    $stmt->execute([$appId]);
    $app = $stmt->fetch();
    if (!$app || $app['app_type'] !== 'tenant') return [0, 0, 0];

    $marker = 'gemB ' . $app['app_ref'] . ' — Site Manager verification';

    // Idempotence: never bridge the same application twice.
    $chk = $pdo->prepare("SELECT COUNT(*) FROM tenants WHERE delegated_authority LIKE ?");
    $chk->execute(['%' . $app['app_ref'] . '%']);
    if ((int)$chk->fetchColumn() > 0) return [0, 0, 0];

    $td         = $app['type_data'] ? json_decode($app['type_data'], true) : [];
    $leaseStart = $td['rental_from'] ?? date('Y-m-d');
    $leaseEnd   = $td['rental_to'] ?? date('Y-m-d', strtotime('+12 months'));

    // Tenant's ID document (application-level doc) → proxy path for the record
    $doc = $pdo->prepare(
        "SELECT id FROM application_documents
         WHERE application_id=? AND item_id IS NULL AND doc_type='id_document' LIMIT 1"
    );
    $doc->execute([$appId]);
    $docId   = $doc->fetchColumn();
    $docPath = $docId ? ('application_doc.php?id=' . (int)$docId) : null;

    // Earliest tenant acknowledgement = rules signed (clause 4.2/4.3 audit trail)
    $ack = $pdo->prepare(
        "SELECT MIN(acknowledged_at), MIN(ack_ip) FROM application_acknowledgements
         WHERE application_id=? AND acknowledged_by='applicant'"
    );
    $ack->execute([$appId]);
    [$rulesSignedAt, $rulesSignedIp] = $ack->fetch(PDO::FETCH_NUM) ?: [null, null];

    // 1) Live tenants record
    $pdo->prepare("
        INSERT INTO tenants
          (resident_erfno, resident_name, tenant_name, id_number, id_document,
           sp_phone, email, lease_start, lease_end,
           rules_signed_at, rules_signed_ip,
           status, approved_by, approved_at, delegated_authority, permit_generated)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,'approved',?,NOW(),?,0)
    ")->execute([
        $app['erf_no'], $app['owner_name'] ?? '',
        $app['applicant_name'], $app['applicant_id_no'] ?? null, $docPath,
        $app['applicant_phone'] ?? null, $app['applicant_email'] ?? null,
        $leaseStart, $leaseEnd,
        $rulesSignedAt, $rulesSignedIp,
        $approverName, $marker,
    ]);
    $tenantId = (int)$pdo->lastInsertId();

    // 2) residents row for the tenant (so vehicles + PWA access work)
    $residentId = 0;
    $code = appNextOccupantCode($app['erf_no']);
    if ($code !== null) {
        // Random PIN hash placeholder — tenant sets a real PIN via the
        // existing forgot/reset flow; nobody can log in with this value.
        $pdo->prepare("
            INSERT INTO residents
              (resident_name, address, resident_erfno, phone, email, status,
               pin_hash, occupant_code, occupant_type, is_primary)
            VALUES (?,?,?,?,?,'active',?,?,?,0)
        ")->execute([
            $app['applicant_name'], $td['street_address'] ?? null, $app['erf_no'],
            $app['applicant_phone'] ?? null, $app['applicant_email'] ?? null,
            password_hash(bin2hex(random_bytes(16)), PASSWORD_BCRYPT),
            $code, 'tenant',
        ]);
        $residentId = (int)$pdo->lastInsertId();
    }

    // 3) Vehicles → resident_vehicles (LPR whitelist source)
    $vehicleCount = 0;
    if ($residentId > 0) {
        $vs = $pdo->prepare(
            "SELECT vehicle_make, vehicle_reg, vehicle_colour FROM application_items
             WHERE application_id=? AND item_type='vehicle' AND item_status <> 'failed'"
        );
        $vs->execute([$appId]);
        $insV = $pdo->prepare(
            "INSERT INTO resident_vehicles (resident_id, plate, description, active)
             VALUES (?,?,?,1)"
        );
        foreach ($vs->fetchAll() as $v) {
            $plate = strtoupper(preg_replace('/\s+/', '', $v['vehicle_reg'] ?? ''));
            if ($plate === '') continue;
            $insV->execute([
                $residentId, $plate,
                trim(($v['vehicle_make'] ?? '') . ' ' . ($v['vehicle_colour'] ?? '')) . ' [' . $app['app_ref'] . ']',
            ]);
            $vehicleCount++;
        }
    }
    return [$tenantId, $residentId, $vehicleCount];
}

/**
 * PET BRIDGE — on approval of a pet application:
 * INSERT into live `pets` (permanent, approved, photo via doc proxy,
 * approval conditions carried in denial_reason? no — conditions live on
 * the application; the live record carries the marker + core details).
 * Returns petId, or 0 if already bridged.
 */
function appBridgePetToLive(int $appId, string $approverName): int {
    $pdo = db();

    $stmt = $pdo->prepare("SELECT * FROM applications WHERE id=? LIMIT 1");
    $stmt->execute([$appId]);
    $app = $stmt->fetch();
    if (!$app || $app['app_type'] !== 'pet') return 0;

    $marker = 'gemB ' . $app['app_ref'] . ' — Site Manager verification';

    $chk = $pdo->prepare("SELECT COUNT(*) FROM pets WHERE delegated_authority LIKE ?");
    $chk->execute(['%' . $app['app_ref'] . '%']);
    if ((int)$chk->fetchColumn() > 0) return 0;

    $it = $pdo->prepare(
        "SELECT * FROM application_items
         WHERE application_id=? AND item_type='pet' AND item_status <> 'failed' LIMIT 1"
    );
    $it->execute([$appId]);
    $pet = $it->fetch();
    if (!$pet) return 0;

    // Pet photo (item-level doc) → proxy path
    $doc = $pdo->prepare(
        "SELECT id FROM application_documents
         WHERE application_id=? AND item_id=? AND doc_type='pet_photo' LIMIT 1"
    );
    $doc->execute([$appId, $pet['id']]);
    $docId   = $doc->fetchColumn();
    $docPath = $docId ? ('application_doc.php?id=' . (int)$docId) : null;

    $pdo->prepare("
        INSERT INTO pets
          (resident_erfno, resident_name, pet_type, pet_name, breed, weight_kg,
           photo, status, approved_by, approved_at, delegated_authority)
        VALUES (?,?,'permanent',?,?,?,?,'approved',?,NOW(),?)
    ")->execute([
        $app['erf_no'], $app['applicant_name'],
        $pet['pet_name'] ?: ($pet['pet_species'] ?? 'Pet'),
        trim(($pet['pet_species'] ?? '') . ' — ' . ($pet['pet_breed'] ?? ''), ' —'),
        ($pet['pet_adult_weight_kg'] !== null ? (float)$pet['pet_adult_weight_kg'] : null),
        $docPath, $approverName, $marker,
    ]);
    return (int)$pdo->lastInsertId();
}

/**
 * WITHDRAWAL / DEACTIVATION — when the site manager withdraws an
 * approval (pet rule 1.3, letting clause 6, lease termination), the
 * bridged live records are closed off too:
 *  tenant: tenants → denied(+reason), tenant's residents row → inactive,
 *          their resident_vehicles → active=0
 *  pet:    pets → denied(+reason)
 */
function appDeactivateBridged(int $appId, string $reason): void {
    $pdo = db();
    $stmt = $pdo->prepare("SELECT app_type, app_ref, erf_no, applicant_name FROM applications WHERE id=? LIMIT 1");
    $stmt->execute([$appId]);
    $app = $stmt->fetch();
    if (!$app) return;
    $like = '%' . $app['app_ref'] . '%';
    $reason = mb_substr($reason, 0, 500);

    if ($app['app_type'] === 'tenant') {
        $pdo->prepare(
            "UPDATE tenants SET status='denied', denial_reason=? WHERE delegated_authority LIKE ?"
        )->execute([$reason, $like]);

        // Deactivate the tenant's resident row + vehicles (matched on erf,
        // name and type — occupant codes are never reused, only deactivated)
        $r = $pdo->prepare(
            "SELECT id FROM residents
             WHERE resident_erfno=? AND resident_name=? AND occupant_type='tenant' AND status='active'"
        );
        $r->execute([$app['erf_no'], $app['applicant_name']]);
        foreach ($r->fetchAll() as $row) {
            $pdo->prepare("UPDATE residents SET status='inactive' WHERE id=?")->execute([$row['id']]);
            $pdo->prepare("UPDATE resident_vehicles SET active=0 WHERE resident_id=?")->execute([$row['id']]);
        }
    }

    if ($app['app_type'] === 'pet') {
        $pdo->prepare(
            "UPDATE pets SET status='denied', denial_reason=? WHERE delegated_authority LIKE ?"
        )->execute([$reason, $like]);
    }

    if (in_array($app['app_type'], ['contractor', 'estate_agent'], true)) {
        // Immediate cancellation per the Estate Agent Rules / contractor revocation
        $pdo->prepare(
            "UPDATE service_providers SET approved='false', expired=1 WHERE notes LIKE ?"
        )->execute([$like]);
    }
}

/**
 * ESTATE AGENT BRIDGE — on approval (after induction at the Managing
 * Agent's office), create ONE live service_providers record for the
 * agent: category 'estate_agent', card permit, Church Street gate,
 * 12-month validity (annual renewal per the 2023 Requirements & Rules).
 * Agency vehicle registrations are written into notes so the guard
 * sees them on QR verification. Idempotent via the app_ref marker.
 */
function appBridgeEstateAgentToSp(int $appId, string $approverName): int {
    $pdo = db();

    $stmt = $pdo->prepare("SELECT * FROM applications WHERE id=? LIMIT 1");
    $stmt->execute([$appId]);
    $app = $stmt->fetch();
    if (!$app || $app['app_type'] !== 'estate_agent') return 0;

    $noteTag = '[gemB ' . $app['app_ref'] . ']';
    $chk = $pdo->prepare("SELECT COUNT(*) FROM service_providers WHERE notes LIKE ?");
    $chk->execute(['%' . $noteTag . '%']);
    if ((int)$chk->fetchColumn() > 0) return 0;

    // Agency vehicles → guard-visible note
    $vs = $pdo->prepare(
        "SELECT vehicle_make, vehicle_reg, vehicle_colour FROM application_items
         WHERE application_id=? AND item_type='vehicle' AND item_status <> 'failed'"
    );
    $vs->execute([$appId]);
    $plates = [];
    foreach ($vs->fetchAll() as $v) {
        $p = strtoupper(trim($v['vehicle_reg'] ?? ''));
        if ($p !== '') $plates[] = $p . ' (' . trim(($v['vehicle_make'] ?? '') . ' ' . ($v['vehicle_colour'] ?? '')) . ')';
    }
    $td = $app['type_data'] ? json_decode($app['type_data'], true) : [];
    $notes = 'Estate agent — ' . ($app['company_name'] ?? '')
           . (!empty($td['agency_phone']) ? ', tel ' . $td['agency_phone'] : '')
           . '. CS gate only; card must be displayed; owner name + property address to be provided.'
           . ($plates ? ' Vehicles: ' . implode('; ', $plates) . '.' : '')
           . ' Annual renewal. ' . $noteTag;

    $startDate = date('Y-m-d');
    $endDate   = date('Y-m-d', strtotime('+12 months'));
    $code      = appNewSpUniqueCode();

    $pdo->prepare("
        INSERT INTO service_providers
          (resident_erfno, resident_name, service_name, company_name,
           id_number, sp_phone, category, permit_type, lead_id,
           once_off, access_days, access_start, access_end,
           start_date, end_date, notes,
           unique_code, status, approved, expired,
           invited_by_resident_id, id_verified, approved_by, approved_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'approved','true',0,NULL,1,?,NOW())
    ")->execute([
        '', 'GEMB Estate',
        $app['applicant_name'], $app['company_name'] ?? '',
        $app['applicant_id_no'] ?? '', $app['applicant_phone'] ?? '',
        'estate_agent', 'card', null,
        0, 'Mon,Tue,Wed,Thu,Fri,Sat,Sun', '07:00:00', '17:00:00',
        $startDate, $endDate, $notes,
        $code, $approverName,
    ]);
    $spId = (int)$pdo->lastInsertId();
    appGenerateSpQr($spId);
    return $spId;
}
