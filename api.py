# api.py - FastAPI app providing REST API for ToMenu data
import sqlite3
import hashlib
import json
import os
import secrets
import subprocess
from datetime import date
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Query, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

# ── config ────────────────────────────────────────────────────────────────────

MAIN_DB   = os.environ.get("MAIN_DB",    "main.db")    # api keys, scrape_log
NAMENU_DB = os.environ.get("NAMENU_DB",  "namenu.db")  # scraped menu data

app = FastAPI(
    title="ToMenu API",
    description="Lunch menus from Slovak restaurants",
    version="0.1.0",
)

# ── db helpers ────────────────────────────────────────────────────────────────

def get_auth_db():
    """Connection to main.db — api keys only."""
    conn = sqlite3.connect(MAIN_DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def get_db():
    """Connection to namenu.db — all scraped menu data."""
    conn = sqlite3.connect(NAMENU_DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
    finally:
        conn.close()


# ── auth ──────────────────────────────────────────────────────────────────────

def require_api_key(
    request: Request,
    auth_db: sqlite3.Connection = Depends(get_auth_db),
):
    key = request.headers.get("Authorization")
    if not key:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    key_hash = hashlib.sha256(key.encode()).hexdigest()
    row = auth_db.execute(
        "SELECT id FROM api_keys WHERE key_hash = ? AND active = 1",
        (key_hash,)
    ).fetchone()

    if not row:
        raise HTTPException(status_code=403, detail="Invalid or revoked API key")

    auth_db.execute(
        "UPDATE api_keys SET last_used = datetime('now') WHERE id = ?",
        (row["id"],)
    )
    auth_db.commit()
    return row["id"]


# ── helpers ───────────────────────────────────────────────────────────────────

def parse_json_field(value):
    if value is None:
        return None
    try:
        return json.loads(value)
    except Exception:
        return value


def row_to_dict(row):
    d = dict(row)
    if "allergens" in d:
        d["allergens"] = parse_json_field(d["allergens"]) or []
    if "nutrition" in d:
        d["nutrition"] = parse_json_field(d["nutrition"])
    return d


def latest_run_id(db: sqlite3.Connection, city_slug: str, on_date: str, source: str = None):
    q = """
        SELECT sr.id FROM scrape_runs sr
        JOIN cities c ON c.id = sr.city_id
        WHERE c.slug = ? AND sr.date = ?
    """
    params = [city_slug, on_date]
    if source:
        q += " AND sr.source = ?"
        params.append(source)
    q += " ORDER BY sr.id DESC LIMIT 1"
    row = db.execute(q, params).fetchone()
    return row["id"] if row else None


# ── static + UI ───────────────────────────────────────────────────────────────

app.mount("/static",  StaticFiles(directory="static"),         name="static")
app.mount("/locales", StaticFiles(directory="webUI/locales"),  name="locales")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    for path in ("webUI/favicon.ico", "static/favicon.ico"):
        if os.path.exists(path):
            return FileResponse(path)
    raise HTTPException(status_code=404)


@app.get("/")
def dashboard():
    with open("webUI/index.html", "r", encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content=content)


# ── public api routes ─────────────────────────────────────────────────────────

@app.get("/api/cities")
def list_cities(
    db: sqlite3.Connection = Depends(get_db),
    _: int = Depends(require_api_key),
):
    rows = db.execute("SELECT id, name, slug, url FROM cities").fetchall()
    return [dict(r) for r in rows]


@app.get("/api/{city}/restaurants")
def list_restaurants(
    city: str,
    delivery: Optional[bool] = None,
    on_date: Optional[str] = Query(default=None, description="YYYY-MM-DD, defaults to today"),
    db: sqlite3.Connection = Depends(get_db),
    _: int = Depends(require_api_key),
):
    target_date = on_date or date.today().isoformat()
    run_id = latest_run_id(db, city, target_date)
    if run_id is None:
        raise HTTPException(status_code=404, detail=f"No menu data for {city} on {target_date}")

    query = """
        SELECT r.id, r.name, r.slug, r.address, r.phone, r.delivery, r.info,
               COUNT(m.id) AS item_count,
               MIN(m.menu_price) AS menu_price
        FROM restaurants r
        JOIN cities c ON c.id = r.city_id
        LEFT JOIN menu_items m ON m.restaurant_id = r.id AND m.scrape_run_id = ?
        WHERE c.slug = ?
    """
    params = [run_id, city]

    if delivery is not None:
        query += " AND r.delivery = ?"
        params.append(1 if delivery else 0)

    query += " GROUP BY r.id ORDER BY r.name"
    rows = db.execute(query, params).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/{city}/restaurants/{slug}")
def get_restaurant(
    city: str,
    slug: str,
    on_date: Optional[str] = Query(default=None, description="YYYY-MM-DD, defaults to today"),
    db: sqlite3.Connection = Depends(get_db),
    _: int = Depends(require_api_key),
):
    target_date = on_date or date.today().isoformat()
    run_id = latest_run_id(db, city, target_date)
    if run_id is None:
        raise HTTPException(status_code=404, detail=f"No menu data for {city} on {target_date}")

    restaurant = db.execute("""
        SELECT r.* FROM restaurants r
        JOIN cities c ON c.id = r.city_id
        WHERE c.slug = ? AND r.slug = ?
    """, (city, slug)).fetchone()

    if not restaurant:
        raise HTTPException(status_code=404, detail="Restaurant not found")

    items = db.execute("""
        SELECT type, name, description, weight, price_eur, menu_price, allergens, nutrition, raw
        FROM menu_items
        WHERE restaurant_id = ? AND scrape_run_id = ?
        ORDER BY id
    """, (restaurant["id"], run_id)).fetchall()

    return {**dict(restaurant), "menu": [row_to_dict(i) for i in items]}


@app.get("/api/{city}/menu")
def get_menu(
    city: str,
    type: Optional[str] = Query(default=None, description="soup / main / dessert"),
    delivery: Optional[bool] = None,
    exclude_allergens: Optional[str] = Query(default=None, description="Comma-separated allergen numbers e.g. 1,7"),
    max_price: Optional[float] = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    on_date: Optional[str] = Query(default=None, description="YYYY-MM-DD, defaults to today"),
    db: sqlite3.Connection = Depends(get_db),
    _: int = Depends(require_api_key),
):
    target_date = on_date or date.today().isoformat()
    run_id = latest_run_id(db, city, target_date)
    if run_id is None:
        raise HTTPException(status_code=404, detail=f"No menu data for {city} on {target_date}")

    query = """
        SELECT m.type, m.name, m.description, m.weight, m.price_eur,
               m.menu_price, m.allergens, m.nutrition,
               r.name AS restaurant_name, r.slug AS restaurant_slug,
               r.delivery, r.address
        FROM menu_items m
        JOIN restaurants r ON r.id = m.restaurant_id
        JOIN cities c ON c.id = r.city_id
        WHERE c.slug = ? AND m.scrape_run_id = ?
    """
    params = [city, run_id]

    if type:
        query += " AND m.type = ?"
        params.append(type)
    if delivery is not None:
        query += " AND r.delivery = ?"
        params.append(1 if delivery else 0)
    if max_price is not None:
        query += " AND m.price_eur <= ?"
        params.append(max_price)
    if exclude_allergens:
        allergen_list = [a.strip() for a in exclude_allergens.split(",") if a.strip().isdigit()]
        for allergen in allergen_list:
            query += " AND (m.allergens IS NULL OR m.allergens NOT LIKE ?)"
            params.append(f"%{allergen}%")

    query += " ORDER BY r.name, m.id LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = db.execute(query, params).fetchall()
    return {"date": target_date, "count": len(rows), "offset": offset, "results": [row_to_dict(r) for r in rows]}


@app.get("/api/{city}/week")
def get_week(
    city: str,
    source: Optional[str] = Query(default=None),
    db: sqlite3.Connection = Depends(get_db),
    _: int = Depends(require_api_key),
):
    """Returns available dates and item counts for the current week."""
    from datetime import date, timedelta
    today  = date.today()
    monday = today - timedelta(days=today.weekday())
    week_dates = [(monday + timedelta(days=i)).isoformat() for i in range(5)]

    result = []
    for d in week_dates:
        run_id = latest_run_id(db, city, d, source)
        count  = 0
        if run_id:
            count = db.execute(
                "SELECT COUNT(*) FROM menu_items WHERE scrape_run_id=?", (run_id,)
            ).fetchone()[0]
        result.append({"date": d, "has_data": run_id is not None, "item_count": count})
    return result


# ── admin routes ──────────────────────────────────────────────────────────────

@app.get("/admin/stats")
def admin_stats(
    city: Optional[str] = Query(default=None),
    db: sqlite3.Connection = Depends(get_db),
    auth_db: sqlite3.Connection = Depends(get_auth_db),
    _: int = Depends(require_api_key),
):
    today = date.today().isoformat()
    city_clause  = "AND c.slug = ?" if city else ""
    city_params  = [city] if city else []

    restaurants = db.execute(
        f"SELECT COUNT(*) FROM restaurants r JOIN cities c ON c.id = r.city_id WHERE 1=1 {city_clause}",
        city_params
    ).fetchone()[0]

    delivery = db.execute(
        f"SELECT COUNT(*) FROM restaurants r JOIN cities c ON c.id = r.city_id WHERE r.delivery=1 {city_clause}",
        city_params
    ).fetchone()[0]

    scrape_runs = db.execute(
        f"SELECT COUNT(*) FROM scrape_runs sr JOIN cities c ON c.id = sr.city_id WHERE 1=1 {city_clause}",
        city_params
    ).fetchone()[0]

    items_today = db.execute(f"""
        SELECT COUNT(m.id) FROM menu_items m
        JOIN scrape_runs sr ON sr.id = m.scrape_run_id
        JOIN cities c ON c.id = sr.city_id
        WHERE sr.date = ? {city_clause}
    """, [today] + city_params).fetchone()[0]

    recent_runs = db.execute(f"""
        SELECT c.name AS city_name, c.slug AS city_slug,
               sr.date, sr.day, sr.scraped_at, COUNT(m.id) AS item_count
        FROM scrape_runs sr
        JOIN cities c ON c.id = sr.city_id
        LEFT JOIN menu_items m ON m.scrape_run_id = sr.id
        WHERE 1=1 {city_clause}
        GROUP BY sr.id ORDER BY sr.id DESC LIMIT 15
    """, city_params).fetchall()

    city_breakdown = db.execute("""
        SELECT c.name, c.slug,
               COUNT(DISTINCT r.id) AS restaurant_count,
               (SELECT COUNT(*) FROM menu_items m2
                JOIN scrape_runs sr2 ON sr2.id = m2.scrape_run_id
                WHERE sr2.city_id = c.id AND sr2.date = ?) AS items_today
        FROM cities c
        LEFT JOIN restaurants r ON r.city_id = c.id
        GROUP BY c.id ORDER BY c.name
    """, [today]).fetchall()

    # pull recent scrape_log entries from main.db
    scrape_log = auth_db.execute(
        "SELECT * FROM scrape_log ORDER BY id DESC LIMIT 10"
    ).fetchall()

    return {
        "restaurants":    restaurants,
        "delivery":       delivery,
        "items_today":    items_today,
        "scrape_runs":    scrape_runs,
        "recent_runs":    [dict(r) for r in recent_runs],
        "city_breakdown": [dict(r) for r in city_breakdown],
        "scrape_log":     [dict(r) for r in scrape_log],
    }


@app.get("/admin/runs")
def admin_runs(
    city: Optional[str] = Query(default=None),
    db: sqlite3.Connection = Depends(get_db),
    _: int = Depends(require_api_key),
):
    city_clause = "AND c.slug = ?" if city else ""
    city_params = [city] if city else []
    rows = db.execute(f"""
        SELECT c.name AS city_name, c.slug AS city_slug,
               sr.date, sr.day, sr.scraped_at, COUNT(m.id) AS item_count
        FROM scrape_runs sr
        JOIN cities c ON c.id = sr.city_id
        LEFT JOIN menu_items m ON m.scrape_run_id = sr.id
        WHERE 1=1 {city_clause}
        GROUP BY sr.id ORDER BY sr.id DESC LIMIT 50
    """, city_params).fetchall()
    return [dict(r) for r in rows]


@app.get("/admin/restaurants")
def admin_restaurants(
    city: Optional[str] = Query(default=None),
    db: sqlite3.Connection = Depends(get_db),
    _: int = Depends(require_api_key),
):
    city_clause = "AND c.slug = ?" if city else ""
    city_params = [city] if city else []
    rows = db.execute(f"""
        SELECT r.*, c.name AS city_name, c.slug AS city_slug
        FROM restaurants r
        JOIN cities c ON c.id = r.city_id
        WHERE 1=1 {city_clause}
        ORDER BY c.name, r.name
    """, city_params).fetchall()
    return [dict(r) for r in rows]


@app.get("/admin/menus")
def admin_menus(
    city: Optional[str] = Query(default=None),
    on_date: Optional[str] = Query(default=None, alias="date"),
    db: sqlite3.Connection = Depends(get_db),
    _: int = Depends(require_api_key),
):
    if not city:
        raise HTTPException(status_code=400, detail="city parameter is required")

    target_date = on_date or date.today().isoformat()
    run = db.execute("""
        SELECT sr.id FROM scrape_runs sr
        JOIN cities c ON c.id = sr.city_id
        WHERE c.slug = ? AND sr.date = ?
        ORDER BY sr.id DESC LIMIT 1
    """, (city, target_date)).fetchone()

    if not run:
        return {"restaurants": [], "city": city, "date": target_date}

    run_id = run[0]
    restaurants = db.execute("""
        SELECT r.* FROM restaurants r
        JOIN cities c ON c.id = r.city_id
        WHERE c.slug = ? ORDER BY r.name
    """, (city,)).fetchall()

    result = []
    for r in restaurants:
        items = db.execute("""
            SELECT type, name, description, weight, price_eur, menu_price,
                   allergens, nutrition, raw
            FROM menu_items WHERE restaurant_id=? AND scrape_run_id=? ORDER BY id
        """, (r["id"], run_id)).fetchall()
        if not items:
            continue
        result.append({
            **dict(r),
            "menu_price": items[0]["menu_price"] if items else None,
            "menu": [row_to_dict(i) for i in items],
        })
    return {"restaurants": result, "city": city, "date": target_date}


@app.post("/admin/scrape")
def admin_scrape(
    db: sqlite3.Connection = Depends(get_db),
    auth_db: sqlite3.Connection = Depends(get_auth_db),
    _: int = Depends(require_api_key),
):
    # log scrape start in main.db
    cur = auth_db.execute(
        "INSERT INTO scrape_log (source, started_at, status) VALUES ('namenu', datetime('now'), 'running')"
    )
    log_id = cur.lastrowid
    auth_db.commit()

    try:
        result = subprocess.run(
            ["python", "-X", "utf8", "scrapers/namenu.scrape.py", "--today"],
            capture_output=True, text=True, timeout=300, encoding="utf-8"
        )
        if result.returncode != 0:
            auth_db.execute(
                "UPDATE scrape_log SET finished_at=datetime('now'), status='error', error=? WHERE id=?",
                (result.stderr or "scrape failed", log_id)
            )
            auth_db.commit()
            raise HTTPException(status_code=500, detail=result.stderr or "scrape failed")

        run = db.execute("SELECT id FROM scrape_runs ORDER BY id DESC LIMIT 1").fetchone()
        run_id = run[0] if run else None
        items_scraped = db.execute(
            "SELECT COUNT(*) FROM menu_items WHERE scrape_run_id >= (SELECT MIN(id) FROM scrape_runs WHERE date = ?)",
            (date.today().isoformat(),)
        ).fetchone()[0] if run_id else 0

        auth_db.execute(
            "UPDATE scrape_log SET finished_at=datetime('now'), status='ok', items=? WHERE id=?",
            (items_scraped, log_id)
        )
        auth_db.commit()

        return {"ok": True, "run_id": run_id, "items_scraped": items_scraped, "output": result.stdout}

    except subprocess.TimeoutExpired:
        auth_db.execute(
            "UPDATE scrape_log SET finished_at=datetime('now'), status='error', error='timeout' WHERE id=?",
            (log_id,)
        )
        auth_db.commit()
        raise HTTPException(status_code=504, detail="scrape timed out")


class NewKeyRequest(BaseModel):
    label: str


@app.post("/admin/keys")
def admin_create_key(
    body: NewKeyRequest,
    auth_db: sqlite3.Connection = Depends(get_auth_db),
    _: int = Depends(require_api_key),
):
    key      = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    auth_db.execute(
        "INSERT INTO api_keys (key_hash, label, created_at) VALUES (?, ?, datetime('now'))",
        (key_hash, body.label)
    )
    auth_db.commit()
    return {"key": key, "label": body.label}


@app.get("/admin/keys")
def admin_list_keys(
    auth_db: sqlite3.Connection = Depends(get_auth_db),
    _: int = Depends(require_api_key),
):
    rows = auth_db.execute(
        "SELECT id, label, created_at, last_used, active FROM api_keys ORDER BY id"
    ).fetchall()
    return [dict(r) for r in rows]


@app.delete("/admin/keys/{key_id}")
def admin_revoke_key(
    key_id: int,
    auth_db: sqlite3.Connection = Depends(get_auth_db),
    _: int = Depends(require_api_key),
):
    auth_db.execute("UPDATE api_keys SET active=0 WHERE id=?", (key_id,))
    auth_db.commit()
    return {"ok": True}