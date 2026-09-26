-- Phase 2 schema (PLAN §17.1): jobs, result batches, hosts/findings shared
-- with the agent track, NVT metadata mirror, site scope limits.

ALTER TABLE site
  ADD COLUMN IF NOT EXISTS max_concurrency int     NOT NULL DEFAULT 16,
  ADD COLUMN IF NOT EXISTS unsafe_ok       boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS allow_public    boolean NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS job (
  id             text PRIMARY KEY,
  site_id        text NOT NULL REFERENCES site(id),
  appliance_id   text NOT NULL REFERENCES appliance(id),
  status         text NOT NULL DEFAULT 'queued'
                 CHECK (status IN ('queued','dispatched','running','done','failed','rejected','cancelled')),
  spec           jsonb NOT NULL,
  scheduled_for  timestamptz,
  dispatched_at  timestamptz,
  started_at     timestamptz,
  finished_at    timestamptz,
  progress_pct   int  NOT NULL DEFAULT 0,
  phase          text NOT NULL DEFAULT '',
  reject_reason  text NOT NULL DEFAULT '',
  batches        int  NOT NULL DEFAULT 0,
  stats          jsonb,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS job_appliance_status_idx ON job(appliance_id, status, scheduled_for);
CREATE INDEX IF NOT EXISTS job_site_idx ON job(site_id, created_at DESC);

CREATE TABLE IF NOT EXISTS result_batch (
  job_id       text NOT NULL REFERENCES job(id),
  seq          int  NOT NULL,
  received_at  timestamptz NOT NULL DEFAULT now(),
  object_key   text NOT NULL,
  sha256       text NOT NULL,
  final        boolean NOT NULL DEFAULT false,
  hosts        int NOT NULL DEFAULT 0,
  PRIMARY KEY (job_id, seq)
);

CREATE TABLE IF NOT EXISTS host (
  id           text PRIMARY KEY,
  site_id      text NOT NULL REFERENCES site(id),
  ip           text NOT NULL DEFAULT '',
  mac          text NOT NULL DEFAULT '',
  hostname     text NOT NULL DEFAULT '',
  source       text NOT NULL CHECK (source IN ('agent','appliance','both')),
  agent_id     text NOT NULL DEFAULT '',
  os_guess     jsonb,
  ports        jsonb NOT NULL DEFAULT '[]',
  notes        jsonb NOT NULL DEFAULT '[]',
  agent_os     text NOT NULL DEFAULT '',
  packages     jsonb NOT NULL DEFAULT '[]',
  last_job_id  text NOT NULL DEFAULT '',
  first_seen   timestamptz NOT NULL DEFAULT now(),
  last_seen    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS host_site_idx ON host(site_id);
CREATE INDEX IF NOT EXISTS host_site_mac_idx ON host(site_id, mac);
CREATE INDEX IF NOT EXISTS host_site_ip_idx ON host(site_id, ip);

CREATE TABLE IF NOT EXISTS job_host (
  job_id   text NOT NULL REFERENCES job(id),
  host_id  text NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  PRIMARY KEY (job_id, host_id)
);

CREATE TABLE IF NOT EXISTS finding (
  id            text PRIMARY KEY,
  host_id       text NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  source        text NOT NULL CHECK (source IN ('agent','openvas','nuclei','both')),
  state         text NOT NULL CHECK (state IN ('confirmed','network_observed','suspected')),
  nvt_oid       text NOT NULL DEFAULT '',
  name          text NOT NULL DEFAULT '',
  family        text NOT NULL DEFAULT '',
  severity      text NOT NULL DEFAULT 'info',
  cvss          real NOT NULL DEFAULT 0,
  cve           text[] NOT NULL DEFAULT '{}',
  qod           int  NOT NULL DEFAULT 0,
  port          int  NOT NULL DEFAULT 0,
  proto         text NOT NULL DEFAULT '',
  solution      text NOT NULL DEFAULT '',
  evidence      jsonb NOT NULL DEFAULT '[]',
  feed_version  text NOT NULL DEFAULT '',
  first_seen    timestamptz NOT NULL DEFAULT now(),
  last_seen     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS finding_host_idx ON finding(host_id);
CREATE INDEX IF NOT EXISTS finding_cve_idx ON finding USING gin(cve);

CREATE TABLE IF NOT EXISTS nvt (
  oid           text PRIMARY KEY,
  name          text NOT NULL DEFAULT '',
  family        text NOT NULL DEFAULT '',
  cvss          real NOT NULL DEFAULT 0,
  cves          text[] NOT NULL DEFAULT '{}',
  qod           int  NOT NULL DEFAULT 0,
  solution      text NOT NULL DEFAULT '',
  feed_version  text NOT NULL DEFAULT '',
  updated_at    timestamptz NOT NULL DEFAULT now()
);
