-- gemB Application Engine — migration 2026-07-02 (c)
-- Pet / tenant / to-let / estate agent approvals move to the ADMIN
-- portal (Board delegation, MOI Art. 20.5.3); contractors remain with
-- the site manager. This lets the audit log record 'admin' as actor.
-- Run ONCE via phpMyAdmin. Safe: widens the ENUM only.
ALTER TABLE application_log
  MODIFY actor_type ENUM('applicant','owner','site_manager','admin','system') NOT NULL;
