CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT,
    discord_id TEXT,
    user_id TEXT,
    text TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_messages_target
ON messages(key, user_id, discord_id);
