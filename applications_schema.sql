-- ============================================================
-- gemB Application & Verification Engine
-- Generic schema serving: contractor, to_let, tenant, pet
-- MySQL 5.7+/8.0 compatible (utf8mb4, InnoDB)
-- ============================================================

-- ------------------------------------------------------------
-- 1. Master application record (one row per submitted application)
-- ------------------------------------------------------------
CREATE TABLE applications (
    id                INT UNSIGNED NOT NULL AUTO_INCREMENT,
    app_ref           VARCHAR(20)  NOT NULL,                -- e.g. APP-2026-000123 (human reference)
    app_type          ENUM('contractor','to_let','tenant','pet') NOT NULL,
    reg_type          VARCHAR(30)  DEFAULT NULL,            -- contractor: new|renewal|add_workers; to_let: lease|self_catering_unit|self_catering_guests
    erf_no            VARCHAR(10)  DEFAULT NULL,            -- estate erf (tenant/to_let/pet); NULL for contractor
    linked_app_id     INT UNSIGNED DEFAULT NULL,            -- tenant app -> approved to_let app id
    status            ENUM('draft','submitted','pending_verification','returned',
                           'verified','induction_scheduled','approved',
                           'rejected','withdrawn','expired') NOT NULL DEFAULT 'draft',
    -- Applicant / primary party
    applicant_name    VARCHAR(120) NOT NULL,
    applicant_id_no   VARCHAR(30)  DEFAULT NULL,
    applicant_email   VARCHAR(150) NOT NULL,
    applicant_phone   VARCHAR(30)  NOT NULL,
    applicant_is_tenant TINYINT(1) NOT NULL DEFAULT 0,      -- pet form: owner vs tenant applicant
    -- Company block (contractor only)
    company_name      VARCHAR(150) DEFAULT NULL,
    company_type      VARCHAR(60)  DEFAULT NULL,            -- trade category
    company_reg_no    VARCHAR(40)  DEFAULT NULL,
    company_owner     VARCHAR(120) DEFAULT NULL,
    -- Second party (owner co-sign for tenant/pet-by-tenant)
    owner_name        VARCHAR(120) DEFAULT NULL,
    owner_id_no       VARCHAR(30)  DEFAULT NULL,
    owner_email       VARCHAR(150) DEFAULT NULL,
    owner_phone       VARCHAR(30)  DEFAULT NULL,
    owner_signed_at   DATETIME     DEFAULT NULL,            -- two-party sign-off timestamp
    owner_sign_token  CHAR(64)     DEFAULT NULL,            -- HMAC token emailed to owner for co-sign
    -- Type-specific structured data (validated server-side per type config)
    type_data         JSON         DEFAULT NULL,            -- rental period, pet species/breed/weight, etc.
    -- Approval outcome
    approval_conditions TEXT       DEFAULT NULL,            -- pet remarks/conditions; general use
    approved_by       INT UNSIGNED DEFAULT NULL,            -- security_users.id (site manager)
    approved_at       DATETIME     DEFAULT NULL,
    valid_until       DATE         DEFAULT NULL,            -- to_let/tenant: rental end; contractor card expiry
    -- Return-for-correction support
    return_reason     TEXT         DEFAULT NULL,
    resume_token      CHAR(64)     DEFAULT NULL,            -- emailed link token to resume returned/draft app
    -- Audit
    submitted_at      DATETIME     DEFAULT NULL,
    created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    submit_ip         VARCHAR(45)  DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_app_ref (app_ref),
    KEY idx_status_type (status, app_type),
    KEY idx_erf (erf_no),
    KEY idx_linked (linked_app_id),
    CONSTRAINT fk_app_linked FOREIGN KEY (linked_app_id) REFERENCES applications(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 2. Child items: workers, occupants, vehicles, pets
-- ------------------------------------------------------------
CREATE TABLE application_items (
    id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
    application_id INT UNSIGNED NOT NULL,
    item_type     ENUM('worker','occupant','vehicle','pet') NOT NULL,
    -- Common person fields (worker/occupant)
    first_name    VARCHAR(80)  DEFAULT NULL,
    surname       VARCHAR(80)  DEFAULT NULL,
    id_number     VARCHAR(30)  DEFAULT NULL,       -- SA ID or passport
    id_is_passport TINYINT(1)  NOT NULL DEFAULT 0,
    is_asylum     TINYINT(1)   NOT NULL DEFAULT 0, -- triggers conditional Home Affairs doc
    email         VARCHAR(150) DEFAULT NULL,
    -- Vehicle fields
    vehicle_make  VARCHAR(60)  DEFAULT NULL,
    vehicle_reg   VARCHAR(20)  DEFAULT NULL,
    vehicle_colour VARCHAR(30) DEFAULT NULL,
    -- Pet fields
    pet_species   VARCHAR(60)  DEFAULT NULL,
    pet_breed     VARCHAR(80)  DEFAULT NULL,
    pet_size      VARCHAR(40)  DEFAULT NULL,
    pet_age       VARCHAR(20)  DEFAULT NULL,
    pet_adult_weight_kg DECIMAL(5,2) DEFAULT NULL, -- rule: <= 15.00 for dogs
    -- Outcome per item (a single worker can be rejected without sinking the application)
    item_status   ENUM('pending','passed','failed') NOT NULL DEFAULT 'pending',
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_item_app (application_id, item_type),
    CONSTRAINT fk_item_app FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 3. Documents (uploads) - linked to application, optionally to an item
-- ------------------------------------------------------------
CREATE TABLE application_documents (
    id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
    application_id INT UNSIGNED NOT NULL,
    item_id       INT UNSIGNED DEFAULT NULL,       -- NULL = application-level doc (e.g. payment proof)
    doc_type      VARCHAR(40)  NOT NULL,           -- 'id_document','police_clearance','id_photo',
                                                   -- 'home_affairs_verification','payment_proof',
                                                   -- 'pet_photo','lease_agreement'
    orig_filename VARCHAR(255) NOT NULL,
    stored_name   CHAR(64)     NOT NULL,           -- random hex name on disk (outside webroot)
    mime_type     VARCHAR(80)  NOT NULL,
    file_size     INT UNSIGNED NOT NULL,
    sha256        CHAR(64)     NOT NULL,           -- integrity/duplicate detection
    doc_date      DATE         DEFAULT NULL,       -- e.g. police clearance issue date (6-month rule)
    uploaded_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    upload_ip     VARCHAR(45)  DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_stored (stored_name),
    KEY idx_doc_app (application_id),
    KEY idx_doc_item (item_id),
    CONSTRAINT fk_doc_app  FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE,
    CONSTRAINT fk_doc_item FOREIGN KEY (item_id) REFERENCES application_items(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 4. Acknowledgements: induction docs / undertaking clauses, per clause,
--    with timestamp - POPIA-grade consent audit trail
-- ------------------------------------------------------------
CREATE TABLE application_acknowledgements (
    id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
    application_id INT UNSIGNED NOT NULL,
    ack_code      VARCHAR(60)  NOT NULL,           -- e.g. 'contractor_code_of_conduct','tenant_4_5_no_business'
    ack_text_hash CHAR(64)     NOT NULL,           -- sha256 of clause text shown (proves what was agreed)
    acknowledged_by ENUM('applicant','owner') NOT NULL DEFAULT 'applicant',
    acknowledged_at DATETIME   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ack_ip        VARCHAR(45)  DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_ack (application_id, ack_code, acknowledged_by),
    CONSTRAINT fk_ack_app FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 5. Payments (contractor R85/worker, to_let registration fee)
-- ------------------------------------------------------------
CREATE TABLE application_payments (
    id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
    application_id INT UNSIGNED NOT NULL,
    amount_due    DECIMAL(10,2) NOT NULL,
    amount_basis  VARCHAR(60)  DEFAULT NULL,       -- 'R85.00 x 4 workers'
    proof_doc_id  INT UNSIGNED DEFAULT NULL,       -- application_documents.id (payment_proof)
    verified      TINYINT(1)   NOT NULL DEFAULT 0,
    verified_by   INT UNSIGNED DEFAULT NULL,       -- security_users.id
    verified_at   DATETIME     DEFAULT NULL,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_pay_app (application_id),
    CONSTRAINT fk_pay_app FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE,
    CONSTRAINT fk_pay_doc FOREIGN KEY (proof_doc_id) REFERENCES application_documents(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 6. Site manager verification checklist (generated from type config
--    at submission; one row per check, per item where applicable)
-- ------------------------------------------------------------
CREATE TABLE application_checklist (
    id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
    application_id INT UNSIGNED NOT NULL,
    item_id       INT UNSIGNED DEFAULT NULL,       -- NULL = application-level check
    check_code    VARCHAR(60)  NOT NULL,           -- 'clearance_within_6_months','payment_verified',...
    check_label   VARCHAR(200) NOT NULL,
    result        ENUM('pending','pass','fail','n_a') NOT NULL DEFAULT 'pending',
    comment       VARCHAR(500) DEFAULT NULL,
    checked_by    INT UNSIGNED DEFAULT NULL,       -- security_users.id
    checked_at    DATETIME     DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_check (application_id, item_id, check_code),
    KEY idx_chk_app (application_id, result),
    CONSTRAINT fk_chk_app  FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE,
    CONSTRAINT fk_chk_item FOREIGN KEY (item_id) REFERENCES application_items(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 7. Status history / audit log
-- ------------------------------------------------------------
CREATE TABLE application_log (
    id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
    application_id INT UNSIGNED NOT NULL,
    old_status    VARCHAR(30)  DEFAULT NULL,
    new_status    VARCHAR(30)  NOT NULL,
    actor_type    ENUM('applicant','owner','site_manager','system') NOT NULL,
    actor_id      INT UNSIGNED DEFAULT NULL,
    note          VARCHAR(500) DEFAULT NULL,
    logged_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    log_ip        VARCHAR(45)  DEFAULT NULL,
    PRIMARY KEY (id),
    KEY idx_log_app (application_id),
    CONSTRAINT fk_log_app FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 8. "Registered to let" enforcement view: current approved to_let per erf
--    (tenant applications validate against this)
-- ------------------------------------------------------------
CREATE OR REPLACE VIEW v_erf_to_let AS
SELECT erf_no, id AS to_let_app_id, valid_until
FROM applications
WHERE app_type = 'to_let'
  AND status = 'approved'
  AND (valid_until IS NULL OR valid_until >= CURDATE());
