-- Phase 4 schema (PLAN §10.6, §16, §17.4, §19, §22): versioned site
-- policy with an audit log, scope requests approved by the vendor owner,
-- recurring schedules, finding review, engine-down tracking.

ALTER TABLE site
  ADD COLUMN IF NOT EXISTS fragile_cleared text[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS fragile_hosts   text[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS vt_excludes     text[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS version         int    NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS attested_at     timestamptz,
  ADD COLUMN IF NOT EXISTS attested_by     text   NOT NULL DEFAULT '';

ALTER TABLE finding
  ADD COLUMN IF NOT EXISTS review        text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS reviewed_at   timestamptz,
  ADD COLUMN IF NOT EXISTS reviewed_by   text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS review_reason text NOT NULL DEFAULT '';

ALTER TABLE job
  ADD COLUMN IF NOT EXISTS schedule_id text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS job_schedule_idx ON job(schedule_id) WHERE schedule_id <> '';

ALTER TABLE appliance
  ADD COLUMN IF NOT EXISTS engine_down_since timestamptz;

CREATE TABLE IF NOT EXISTS site_change (
  id         text PRIMARY KEY,
  site_id    text NOT NULL REFERENCES site(id) ON DELETE CASCADE,
  version    int  NOT NULL,
  at         timestamptz NOT NULL,
  actor      text NOT NULL DEFAULT '',
  kind       text NOT NULL,
  field      text NOT NULL DEFAULT '',
  old_value  text NOT NULL DEFAULT '',
  new_value  text NOT NULL DEFAULT '',
  reason     text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS site_change_site_idx ON site_change(site_id, at DESC);

CREATE TABLE IF NOT EXISTS scope_request (
  id             text PRIMARY KEY,
  site_id        text NOT NULL REFERENCES site(id) ON DELETE CASCADE,
  status         text NOT NULL CHECK (status IN ('pending','approved','rejected')),
  allowed_cidrs  text[] NOT NULL DEFAULT '{}',
  reason         text NOT NULL DEFAULT '',
  requested_at   timestamptz NOT NULL,
  requested_by   text NOT NULL DEFAULT '',
  decided_at     timestamptz,
  decided_by     text NOT NULL DEFAULT '',
  decision       text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS scope_request_site_idx ON scope_request(site_id, status);

CREATE TABLE IF NOT EXISTS schedule (
  id              text PRIMARY KEY,
  site_id         text NOT NULL REFERENCES site(id) ON DELETE CASCADE,
  appliance_id    text NOT NULL REFERENCES appliance(id) ON DELETE CASCADE,
  name            text NOT NULL DEFAULT '',
  mode            text NOT NULL,
  targets         text[] NOT NULL DEFAULT '{}',
  excludes        text[] NOT NULL DEFAULT '{}',
  ports           text NOT NULL DEFAULT '',
  cron            text NOT NULL,
  tz              text NOT NULL DEFAULT '',
  max_duration_s  int  NOT NULL DEFAULT 0,
  enabled         boolean NOT NULL DEFAULT true,
  next_occurrence timestamptz,
  next_job_id     text NOT NULL DEFAULT '',
  last_job_id     text NOT NULL DEFAULT '',
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS schedule_site_idx ON schedule(site_id);
