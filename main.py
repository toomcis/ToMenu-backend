# main.py — CLI tool for namenu+ administration
# Scraping is now done via:  python -X utf8 scrapers/namenu.scrape.py
#                        or: ./scrape_all.sh
#
# Usage:
#   python main.py --add-key "my app"
#   python main.py --list-keys
#   python main.py --revoke-key 3

import sqlite3
import hashlib
import secrets
import os
import sys
from datetime import datetime

DB_PATH = os.environ.get("NAMENU_DB", "namenu.db")


def init_db(conn):
    """Minimal init — just ensure api_keys table exists."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id         INTEGER PRIMARY KEY,
            key_hash   TEXT NOT NULL UNIQUE,
            label      TEXT,
            created_at TEXT NOT NULL,
            last_used  TEXT,
            active     INTEGER NOT NULL DEFAULT 1
        )
    """)
    conn.commit()


def add_api_key(label):
    key      = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    conn     = sqlite3.connect(DB_PATH)
    init_db(conn)
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
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
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
        print(f"{r[0]:>4}  {(r[1] or ''):.<25}  {r[2][:19]:<20}  {(r[3] or 'never')[:19]:<20}  {'yes' if r[4] else 'no'}")


def revoke_api_key(key_id):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE api_keys SET active = 0 WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()
    print(f"Key {key_id} revoked.")


if __name__ == "__main__":
    args = sys.argv[1:]

    if not args or args[0] in ("--help", "-h"):
        print("namenu+ CLI")
        print("  python main.py --add-key <label>    create a new API key")
        print("  python main.py --list-keys           list all API keys")
        print("  python main.py --revoke-key <id>     revoke an API key")
        print("")
        print("  To scrape:  python -X utf8 scrapers/namenu.scrape.py [--today|--day <slug>]")
        print("          or: ./scrape_all.sh [--today|--day <slug>]")
        sys.exit(0)

    if args[0] == "--add-key":
        add_api_key(args[1] if len(args) > 1 else "default")
    elif args[0] == "--list-keys":
        list_api_keys()
    elif args[0] == "--revoke-key":
        revoke_api_key(int(args[1]))
    else:
        print(f"Unknown command: {args[0]}. Use --help for usage.")
        sys.exit(1)