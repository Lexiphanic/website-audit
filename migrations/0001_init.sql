-- Lexiphanic Audit — report index and status.
--
-- One row per domain per day. The full report is JSON in payload_json, capped
-- well below D1's 100 KB statement limit. The dated URL is the permanent
-- snapshot; re-running on the same day updates that day's row.

CREATE TABLE reports (
  id            TEXT PRIMARY KEY,          -- domain:YYYY-MM-DD
  domain        TEXT NOT NULL,
  report_date   TEXT NOT NULL,             -- YYYY-MM-DD, Europe/London
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
  updated_at    TEXT NOT NULL,
  UNIQUE (domain, report_date)
);

CREATE INDEX idx_reports_domain_date ON reports (domain, report_date DESC);
CREATE INDEX idx_reports_status ON reports (status);
