-- Scores, product inventory and names, after the first scans with the real
-- engine.

-- A CVSS score has one decimal. Stored as a 4-byte float, 9.8 came back as
-- 9.800000190734863.
ALTER TABLE finding ALTER COLUMN cvss TYPE double precision USING round(cvss::numeric, 1)::double precision;
ALTER TABLE nvt     ALTER COLUMN cvss TYPE double precision USING round(cvss::numeric, 1)::double precision;

-- The appliance's product inventory for a host: every CPE the engine
-- registered, wherever it placed the product.
ALTER TABLE host ADD COLUMN IF NOT EXISTS cpes text[] NOT NULL DEFAULT '{}';

-- The engine escapes the names of its results twice, and the appliance used
-- to pass "&lt;" on. One level comes off, ampersand last, which is exact
-- for text escaped that way.
UPDATE finding SET name = replace(replace(replace(name, '&lt;', '<'), '&gt;', '>'), '&amp;', '&')
  WHERE source IN ('openvas', 'both') AND name LIKE '%&%;%';
UPDATE nvt SET name = replace(replace(replace(name, '&lt;', '<'), '&gt;', '>'), '&amp;', '&')
  WHERE name LIKE '%&%;%';
