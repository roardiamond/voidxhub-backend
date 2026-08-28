import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "voidxhub.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    token_version INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,
    user_id INTEGER,
    username TEXT,
    ip_address TEXT,
    detail TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS games (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    slug TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS tournaments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    game_id INTEGER NOT NULL REFERENCES games(id),
    mode TEXT NOT NULL DEFAULT 'squad',
    description TEXT,
    entry_fee INTEGER NOT NULL DEFAULT 0,
    prize_pool INTEGER NOT NULL DEFAULT 0,
    slots_total INTEGER NOT NULL DEFAULT 25,
    match_date TEXT,
    status TEXT NOT NULL DEFAULT 'upcoming',
    room_id TEXT,
    room_pass TEXT,
    upi_id TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tournament_id INTEGER NOT NULL REFERENCES tournaments(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    team_name TEXT NOT NULL,
    players TEXT,
    payment_status TEXT NOT NULL DEFAULT 'pending',
    utr_number TEXT,
    slot_number INTEGER,
    registered_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(tournament_id, user_id)
);

CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tournament_id INTEGER NOT NULL REFERENCES tournaments(id),
    team_name TEXT NOT NULL,
    position INTEGER NOT NULL,
    kills INTEGER DEFAULT 0,
    prize_amount INTEGER DEFAULT 0
);
"""

SEED_GAMES = [
    "BGMI",
    "Free Fire",
    "Valorant",
    "Counter-Strike 2",
    "Call of Duty Mobile",
    "PUBG PC",
    "Apex Legends",
    "Fortnite",
    "Clash Squad",
]


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _migrate(conn):
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    if "token_version" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0")
    if "failed_attempts" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0")
    if "locked_until" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
    conn.commit()


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    _migrate(conn)
    for name in SEED_GAMES:
        slug = name.lower().replace(" ", "-")
        conn.execute(
            "INSERT OR IGNORE INTO games (name, slug) VALUES (?, ?)", (name, slug)
        )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at {DB_PATH}")
