-- Phase 1 schema (PLAN §17.1). Job/result/host tables land in Phase 2.

CREATE TABLE IF NOT EXISTS vendor (
  id          text PRIMARY KEY,
  name        text NOT NULL UNIQUE,
  tier        int  NOT NULL DEFAULT 3,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS site (
  id             text PRIMARY KEY,
  vendor_id      text NOT NULL REFERENCES vendor(id),
  name           text NOT NULL,
  allowed_cidrs  cidr[] NOT NULL DEFAULT '{}',
  excludes       cidr[] NOT NULL DEFAULT '{}',
  fragile_ports  int[]  NOT NULL DEFAULT '{9100,515,631,161,502,44818}',
  max_pps        int    NOT NULL DEFAULT 300,
  tz             text   NOT NULL DEFAULT 'UTC',
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (vendor_id, name)
);

CREATE TABLE IF NOT EXISTS appliance (
  id                 text PRIMARY KEY,
  site_id            text NOT NULL REFERENCES site(id),
  status             text NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','enrolled','revoked','wiped','quarantined')),
  cert_serial        text,
  cert_not_after     timestamptz,
  version            text NOT NULL DEFAULT '',
  bundle_version     text NOT NULL DEFAULT '',
  last_heartbeat_at  timestamptz,
  last_heartbeat     jsonb,
  skew_s             bigint NOT NULL DEFAULT 0,
  ifaces             jsonb NOT NULL DEFAULT '[]',
  fingerprint        jsonb,
  binary_hashes      jsonb NOT NULL DEFAULT '{}',
  enrolled_at        timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS appliance_site_idx ON appliance(site_id);
CREATE INDEX IF NOT EXISTS appliance_serial_idx ON appliance(cert_serial);

CREATE TABLE IF NOT EXISTS enrollment_code (
  appliance_id  text PRIMARY KEY REFERENCES appliance(id),
  code_hash     text NOT NULL UNIQUE,
  expires_at    timestamptz NOT NULL,
  used_at       timestamptz,
  attempts      int NOT NULL DEFAULT 0,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS enroll_attempt (
  id            bigserial PRIMARY KEY,
  at            timestamptz NOT NULL DEFAULT now(),
  source_ip     text NOT NULL,
  appliance_id  text,
  ok            boolean NOT NULL,
  reason        text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS enroll_attempt_at_idx ON enroll_attempt(at);

CREATE TABLE IF NOT EXISTS heartbeat (
  id            bigserial PRIMARY KEY,
  appliance_id  text NOT NULL REFERENCES appliance(id),
  at            timestamptz NOT NULL DEFAULT now(),
  payload       jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS heartbeat_appliance_at_idx ON heartbeat(appliance_id, at DESC);

CREATE TABLE IF NOT EXISTS directive (
  id            text PRIMARY KEY,
  appliance_id  text NOT NULL REFERENCES appliance(id),
  type          text NOT NULL,
  payload       jsonb NOT NULL DEFAULT '{}',
  created_at    timestamptz NOT NULL DEFAULT now(),
  delivered_at  timestamptz,
  acked_at      timestamptz
);
CREATE INDEX IF NOT EXISTS directive_pending_idx ON directive(appliance_id, created_at) WHERE acked_at IS NULL;

CREATE TABLE IF NOT EXISTS revoked_serial (
  serial      text PRIMARY KEY,
  revoked_at  timestamptz NOT NULL DEFAULT now(),
  reason      text NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS support_bundle (
  id            bigserial PRIMARY KEY,
  appliance_id  text NOT NULL REFERENCES appliance(id),
  at            timestamptz NOT NULL DEFAULT now(),
  object_key    text NOT NULL,
  bytes         bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS bundle (
  version       text PRIMARY KEY,
  object_key    text NOT NULL,
  sha256        text NOT NULL,
  sig           text NOT NULL,
  published_at  timestamptz NOT NULL DEFAULT now(),
  canary_until  timestamptz
);

CREATE TABLE IF NOT EXISTS release (
  component     text NOT NULL,
  version       text NOT NULL,
  object_key    text NOT NULL,
  sha256        text NOT NULL,
  sig           text NOT NULL,
  published_at  timestamptz NOT NULL DEFAULT now(),
  canary_until  timestamptz,
  PRIMARY KEY (component, version)
);
