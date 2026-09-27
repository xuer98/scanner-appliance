-- Phase 5 schema (PLAN §20 Phase 5, §21): control-plane settings (the nmap
-- legal sign-off) and explicit module sets on schedules.

CREATE TABLE IF NOT EXISTS setting (
  key        text PRIMARY KEY,
  value      text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE schedule
  ADD COLUMN IF NOT EXISTS modules text[] NOT NULL DEFAULT '{}';
