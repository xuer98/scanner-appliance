-- Phase 6 schema (Qualys replacement): finding lifecycle and scope,
-- external scanner sources, retention bookkeeping.

ALTER TABLE finding
  ADD COLUMN IF NOT EXISTS status      text NOT NULL DEFAULT 'open',
  ADD COLUMN IF NOT EXISTS fixed_at    timestamptz,
  ADD COLUMN IF NOT EXISTS reopened_at timestamptz,
  ADD COLUMN IF NOT EXISTS reopens     int  NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS scope       text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS external_id text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS finding_status_idx ON finding(status);

-- Sources are no longer a closed set: an external scanner (qualys, ...)
-- is a finding source and a host source.
ALTER TABLE finding DROP CONSTRAINT IF EXISTS finding_source_check;
ALTER TABLE finding ADD CONSTRAINT finding_source_nonempty CHECK (source <> '');
ALTER TABLE host DROP CONSTRAINT IF EXISTS host_source_check;
ALTER TABLE host ADD CONSTRAINT host_source_known CHECK (source IN ('agent','appliance','both','external'));

ALTER TABLE result_batch ADD COLUMN IF NOT EXISTS purged boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS result_batch_retention_idx ON result_batch(received_at) WHERE NOT purged;
ALTER TABLE support_bundle ADD COLUMN IF NOT EXISTS purged boolean NOT NULL DEFAULT false;
