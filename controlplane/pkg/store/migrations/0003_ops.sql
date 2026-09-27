-- Phase 3 schema (PLAN §13, §14, §15, §17.1): bundles + releases with
-- rollout state, content-addressed bundle files, canary group and platform
-- on the appliance, LAN routes on the site.

ALTER TABLE appliance
  ADD COLUMN IF NOT EXISTS canary          boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS os              text    NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS arch            text    NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS feed_version    text    NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS update_error    text    NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS reboot_required boolean NOT NULL DEFAULT false;

ALTER TABLE site
  ADD COLUMN IF NOT EXISTS lan_routes jsonb NOT NULL DEFAULT '[]';

-- nuclei findings (web add-on) are identified by template id, not an OID.
ALTER TABLE finding
  ADD COLUMN IF NOT EXISTS template_id text NOT NULL DEFAULT '';

ALTER TABLE bundle
  ADD COLUMN IF NOT EXISTS feed_version text   NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS files        int    NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS bytes        bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS status       text   NOT NULL DEFAULT 'canary',
  ADD COLUMN IF NOT EXISTS held_reason  text   NOT NULL DEFAULT '';

ALTER TABLE release
  ADD COLUMN IF NOT EXISTS bytes       bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS status      text   NOT NULL DEFAULT 'canary',
  ADD COLUMN IF NOT EXISTS held_reason text   NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS bundle_file (
  sha256      text PRIMARY KEY,
  size        bigint NOT NULL,
  object_key  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
