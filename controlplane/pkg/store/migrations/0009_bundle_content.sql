-- A bundle's content digest names its files and nothing else, so the daily
-- build can tell a day on which nothing changed: publishing such a bundle
-- would send every appliance the whole file list again for no new file.
-- Bundles published before this column have no digest and compare as
-- different from everything.

ALTER TABLE bundle
  ADD COLUMN IF NOT EXISTS content_sha256 text NOT NULL DEFAULT '';
