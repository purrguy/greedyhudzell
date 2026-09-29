CREATE TABLE IF NOT EXISTS exec_stats (
    key TEXT PRIMARY KEY,
    username TEXT,
    execs INTEGER NOT NULL DEFAULT 0,
    max_level INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exec_stats_updated
ON exec_stats(updated_at);
