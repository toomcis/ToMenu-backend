# scrapers/db.py — shared database helpers for all scrapers
import sqlite3
import os

DB_PATH = os.environ.get("NAMENU_DB", "namenu.db")


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cities (
            id    INTEGER PRIMARY KEY,
            name  TEXT NOT NULL,
            slug  TEXT NOT NULL UNIQUE,
            url   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS restaurants (
            id        INTEGER PRIMARY KEY,
            city_id   INTEGER NOT NULL REFERENCES cities(id),
            name      TEXT NOT NULL,
            slug      TEXT NOT NULL,
            url       TEXT,
            address   TEXT,
            phone     TEXT,
            delivery  INTEGER NOT NULL DEFAULT 0,
            info      TEXT,
            UNIQUE(city_id, slug)
        );

        CREATE TABLE IF NOT EXISTS scrape_runs (
            id         INTEGER PRIMARY KEY,
            city_id    INTEGER NOT NULL REFERENCES cities(id),
            source     TEXT    NOT NULL DEFAULT 'namenu',
            scraped_at TEXT    NOT NULL,
            day        TEXT    NOT NULL,
            date       TEXT    NOT NULL,
            UNIQUE(city_id, source, date)
        );

        CREATE TABLE IF NOT EXISTS menu_items (
            id            INTEGER PRIMARY KEY,
            restaurant_id INTEGER NOT NULL REFERENCES restaurants(id),
            scrape_run_id INTEGER NOT NULL REFERENCES scrape_runs(id),
            type          TEXT NOT NULL CHECK(type IN ('soup','main','dessert')),
            name          TEXT,
            description   TEXT,
            weight        TEXT,
            price_eur     REAL,
            menu_price    REAL,
            allergens     TEXT,
            nutrition     TEXT,
            raw           TEXT
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id         INTEGER PRIMARY KEY,
            key_hash   TEXT NOT NULL UNIQUE,
            label      TEXT,
            created_at TEXT NOT NULL,
            last_used  TEXT,
            active     INTEGER NOT NULL DEFAULT 1
        );

        CREATE INDEX IF NOT EXISTS idx_menu_items_run   ON menu_items(scrape_run_id);
        CREATE INDEX IF NOT EXISTS idx_menu_items_rest  ON menu_items(restaurant_id);
        CREATE INDEX IF NOT EXISTS idx_menu_items_type  ON menu_items(type);
        CREATE INDEX IF NOT EXISTS idx_scrape_runs_date ON scrape_runs(date);
        CREATE INDEX IF NOT EXISTS idx_scrape_runs_src  ON scrape_runs(source);
        CREATE INDEX IF NOT EXISTS idx_restaurants_city ON restaurants(city_id);
        CREATE INDEX IF NOT EXISTS idx_restaurants_slug ON restaurants(city_id, slug);
    """)

    # ── migrate existing DBs that don't have the source column yet ────────────
    cols = [r[1] for r in conn.execute("PRAGMA table_info(scrape_runs)").fetchall()]
    if "source" not in cols:
        conn.execute("ALTER TABLE scrape_runs ADD COLUMN source TEXT NOT NULL DEFAULT 'namenu'")
        print("  [db] migrated: added source column to scrape_runs")

    conn.commit()


def get_or_create_city(conn, name, slug, url):
    row = conn.execute("SELECT id FROM cities WHERE slug = ?", (slug,)).fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        "INSERT INTO cities (name, slug, url) VALUES (?, ?, ?)",
        (name, slug, url)
    )
    conn.commit()
    return cur.lastrowid


def upsert_restaurant(conn, city_id, name, slug, url, address, phone, delivery, info):
    existing = conn.execute(
        "SELECT id FROM restaurants WHERE city_id = ? AND slug = ?",
        (city_id, slug)
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE restaurants SET name=?, url=?, address=?, phone=?, delivery=?, info=? WHERE id=?",
            (name, url, address, phone, int(delivery), info, existing[0])
        )
        conn.commit()
        return existing[0]
    cur = conn.execute(
        "INSERT INTO restaurants (city_id, name, slug, url, address, phone, delivery, info) VALUES (?,?,?,?,?,?,?,?)",
        (city_id, name, slug, url, address, phone, int(delivery), info)
    )
    conn.commit()
    return cur.lastrowid


def upsert_scrape_run(conn, city_id, source, scraped_at, day, date):
    """
    Insert or replace a scrape run for (city, source, date).
    If one already exists, delete its menu_items first, then replace it.
    Returns the run_id.
    """
    existing = conn.execute(
        "SELECT id FROM scrape_runs WHERE city_id=? AND source=? AND date=?",
        (city_id, source, date)
    ).fetchone()

    if existing:
        old_id = existing[0]
        conn.execute("DELETE FROM menu_items WHERE scrape_run_id=?", (old_id,))
        conn.execute("DELETE FROM scrape_runs WHERE id=?", (old_id,))
        conn.commit()

    cur = conn.execute(
        "INSERT INTO scrape_runs (city_id, source, scraped_at, day, date) VALUES (?,?,?,?,?)",
        (city_id, source, scraped_at, day, date)
    )
    conn.commit()
    return cur.lastrowid