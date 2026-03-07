-- tomenu-users D1 schema
-- Already applied. Keep this file as source of truth.

CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    email        TEXT    NOT NULL UNIQUE,
    password_hash TEXT   NOT NULL,          -- bcrypt / PBKDF2 hash
    display_name TEXT,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    is_verified  INTEGER NOT NULL DEFAULT 0,
    is_premium   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT    PRIMARY KEY,          -- random 32-byte hex token (stored raw here, SHA-256 on server)
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT    NOT NULL,
    user_agent TEXT,
    ip         TEXT
);

CREATE TABLE IF NOT EXISTS user_preferences (
    user_id       INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    city_slug     TEXT,
    language      TEXT    NOT NULL DEFAULT 'sk',
    max_price     REAL,
    exclude_allergens TEXT,                  -- JSON array e.g. [1,7]
    delivery_only INTEGER NOT NULL DEFAULT 0,
    updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS user_taste_profile (
    user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    liked_tags TEXT    NOT NULL DEFAULT '[]',   -- JSON array of tag strings
    disliked_tags TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS user_favorites (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    restaurant_slug TEXT  NOT NULL,
    city_slug     TEXT    NOT NULL,
    saved_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, restaurant_slug, city_slug)
);

CREATE TABLE IF NOT EXISTS swipe_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item_name     TEXT    NOT NULL,
    restaurant_slug TEXT  NOT NULL,
    city_slug     TEXT    NOT NULL,
    swiped_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    direction     TEXT    NOT NULL CHECK(direction IN ('like','dislike','skip'))
);

CREATE INDEX IF NOT EXISTS idx_sessions_user     ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires  ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_swipes_user       ON swipe_history(user_id);
CREATE INDEX IF NOT EXISTS idx_favorites_user    ON user_favorites(user_id);