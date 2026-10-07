-- A canary appliance's confirmation of a bundle is remembered. With one
-- bundle a day the canaries run a newer bundle by the time the canary
-- period of an older one ends, so "a canary runs it now" can no longer be
-- the test for releasing it to the fleet.

ALTER TABLE bundle
  ADD COLUMN IF NOT EXISTS confirmed_at timestamptz;
