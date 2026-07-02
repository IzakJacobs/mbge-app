-- gemB Application Engine — migration 2026-07-02
-- Adds the pet's name to application items (live `pets`.pet_name is NOT NULL).
-- Run ONCE on gemb.co.za and once on the mini PC. Safe: adds a nullable
-- column only; no existing data is modified.
ALTER TABLE application_items
  ADD COLUMN pet_name VARCHAR(80) NULL AFTER vehicle_colour;
