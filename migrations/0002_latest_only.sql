-- Lexiphanic Audit — one report per domain.
--
-- The original schema kept one row per domain per day. The product now keeps
-- only the latest report per domain; report_date remains as the date the
-- report was generated and is shown in the report itself.
--
-- Existing rows are deduplicated to the newest report for each domain.

CREATE TABLE reports_latest (
  domain        TEXT PRIMARY KEY,
  report_date   TEXT NOT NULL,
  url           TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued', 'running', 'complete', 'failed')),
  phase         TEXT NOT NULL DEFAULT 'queued',
  progress      INTEGER NOT NULL DEFAULT 0,
  score         INTEGER,
  grade         TEXT,
  payload_json  TEXT,
  workflow_id   TEXT,
  error         TEXT,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);

INSERT INTO reports_latest (
  domain, report_date, url, status, phase, progress,
  score, grade, payload_json, workflow_id, error, created_at, updated_at
)
SELECT
  domain, report_date, url, status, phase, progress,
  score, grade, payload_json, workflow_id, error, created_at, updated_at
FROM reports AS r
WHERE r.rowid = (
  SELECT r2.rowid
  FROM reports AS r2
  WHERE r2.domain = r.domain
  ORDER BY r2.report_date DESC, r2.updated_at DESC
  LIMIT 1
);

DROP TABLE reports;
ALTER TABLE reports_latest RENAME TO reports;

CREATE INDEX idx_reports_status ON reports (status);
