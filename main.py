# main.py — CLI tool for ToMenu administration
# main.db holds: api_keys, scrape_log (cross-scraper audit trail)
# namenu.db (and future *.db) hold scraper-specific data
#
# Usage:
#   python main.py --add-key "my app"
#   python main.py --list-keys
#   python main.py --revoke-key 3
#   python main.py --scrape-log        (show recent scrape audit entries)

import sqlite3
import hashlib
import secrets
import os
import sys
from datetime import datetime

MAIN_DB = os.environ.get("MAIN_DB", "main.db")


# ── db init ───────────────────────────────────────────────────────────────────

def init_db(conn):
    """Create all main.db tables if they don't exist yet."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id         INTEGER PRIMARY KEY,
            key_hash   TEXT NOT NULL UNIQUE,
            label      TEXT,
            created_at TEXT NOT NULL,
            last_used  TEXT,
            active     INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS scrape_log (
            id          INTEGER PRIMARY KEY,
            source      TEXT NOT NULL,
            started_at  TEXT NOT NULL,
            finished_at TEXT,
            status      TEXT NOT NULL DEFAULT 'running',
            items       INTEGER DEFAULT 0,
            error       TEXT
        );
    """)
    conn.commit()


def get_conn():
    conn = sqlite3.connect(MAIN_DB)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


# ── api keys ──────────────────────────────────────────────────────────────────

def add_api_key(label):
    conn = get_conn()
    existing = conn.execute(
        "SELECT id FROM api_keys WHERE label = ? AND active = 1", (label,)
    ).fetchone()
    if existing:
        print(f"API key for '{label}' already exists (id={existing[0]}), skipping.")
        conn.close()
        return
    key      = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    conn.execute(
        "INSERT INTO api_keys (key_hash, label, created_at) VALUES (?, ?, ?)",
        (key_hash, label, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    print(f"API key created for '{label}':")
    print(f"  {key}")
    print("Save this — it won't be shown again.")


def list_api_keys():
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, label, created_at, last_used, active FROM api_keys ORDER BY id"
    ).fetchall()
    conn.close()
    if not rows:
        print("No API keys yet. Use --add-key <label> to create one.")
        return
    print(f"{'ID':>4}  {'Label':<25}  {'Created':<20}  {'Last used':<20}  Active")
    print("-" * 80)
    for r in rows:
        print(
            f"{r['id']:>4}  {(r['label'] or ''):.<25}  "
            f"{r['created_at'][:19]:<20}  "
            f"{(r['last_used'] or 'never')[:19]:<20}  "
            f"{'yes' if r['active'] else 'no'}"
        )


def revoke_api_key(key_id):
    conn = get_conn()
    conn.execute("UPDATE api_keys SET active = 0 WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()
    print(f"Key {key_id} revoked.")


# ── scrape log ────────────────────────────────────────────────────────────────

def scrape_log_start(source: str) -> int:
    """Call at the start of a scrape run. Returns the log entry id."""
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO scrape_log (source, started_at, status) VALUES (?, ?, 'running')",
        (source, datetime.now().isoformat())
    )
    log_id = cur.lastrowid
    conn.commit()
    conn.close()
    return log_id


def scrape_log_finish(log_id: int, items: int, error: str = None):
    """Call at the end of a scrape run to record result."""
    conn = get_conn()
    status = "error" if error else "ok"
    conn.execute(
        "UPDATE scrape_log SET finished_at=?, status=?, items=?, error=? WHERE id=?",
        (datetime.now().isoformat(), status, items, error, log_id)
    )
    conn.commit()
    conn.close()


def show_scrape_log(limit=20):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM scrape_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    if not rows:
        print("No scrape log entries yet.")
        return
    print(f"{'ID':>4}  {'Source':<20}  {'Started':<20}  {'Status':<8}  {'Items':>6}  Error")
    print("-" * 90)
    for r in rows:
        print(
            f"{r['id']:>4}  {r['source']:<20}  {r['started_at'][:19]:<20}  "
            f"{r['status']:<8}  {(r['items'] or 0):>6}  {r['error'] or ''}"
        )


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = sys.argv[1:]

    if not args or args[0] in ("--help", "-h"):
        print("ToMenu CLI")
        print("  python main.py --add-key <label>     create a new API key")
        print("  python main.py --list-keys            list all API keys")
        print("  python main.py --revoke-key <id>      revoke an API key")
        print("  python main.py --scrape-log           show recent scrape log")
        print("")
        print("  To scrape:  python -X utf8 scrapers/namenu.scrape.py [--today|--day <slug>]")
        print("          or: ./scrapeAll.sh [--today|--day <slug>]")
        sys.exit(0)

    if args[0] == "--add-key":
        add_api_key(args[1] if len(args) > 1 else "default")
    elif args[0] == "--list-keys":
        list_api_keys()
    elif args[0] == "--revoke-key":
        revoke_api_key(int(args[1]))
    elif args[0] == "--scrape-log":
        show_scrape_log()
    else:
        print(f"Unknown command: {args[0]}. Use --help for usage.")
        sys.exit(1)