# scrapers/namenu.scrape.py
# Scrapes lv.namenu.sk (and other namenu cities) for the full current week.
#
# Usage:
#   python -X utf8 scrapers/namenu.scrape.py           # scrape whole week
#   python -X utf8 scrapers/namenu.scrape.py --today   # scrape today only
#   python -X utf8 scrapers/namenu.scrape.py --day pondelok

import sys
import os
import io
import re
import json
import requests
from bs4 import BeautifulSoup
from datetime import datetime, date, timedelta

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# allow running from project root: python scrapers/namenu.scrape.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scrapers.db import connect, init_db, get_or_create_city, upsert_restaurant, upsert_scrape_run

SOURCE  = "namenu"
HEADERS = {"User-Agent": "namenu-scraper/1.0 (personal project)"}

# ── cities ────────────────────────────────────────────────────────────────────
# Only Levice (lv.namenu.sk) actually has data right now.
# Other namenu.sk/city/ URLs exist but show "Coming Soon".
# Add more here when they go live.

CITIES = [
    {"name": "Levice",           "slug": "levice",          "url": "https://lv.namenu.sk/"},
    {"name": "Nové Zámky",       "slug": "nove-zamky",      "url": "https://namenu.sk/nove_zamky/"},
    {"name": "Zlaté Moravce",    "slug": "zlate-moravce",   "url": "https://namenu.sk/zlate_moravce/"},
    {"name": "Žarnovica",        "slug": "zarnovica",       "url": "https://namenu.sk/zarnovica/"},
    {"name": "Zvolen",           "slug": "zvolen",          "url": "https://namenu.sk/zvolen/"},
    {"name": "Žiar nad Hronom",  "slug": "ziar-nad-hronom", "url": "https://namenu.sk/ziar_nad_hronom/"},
    {"name": "Banská Štiavnica", "slug": "banska-stiavnica","url": "https://namenu.sk/banska_stiavnica/"},
]

# ── day mapping ───────────────────────────────────────────────────────────────
# namenu uses Slovak day names in URLs.
# We map each to a weekday number (0=Mon … 4=Fri) so we can compute
# the actual calendar date for the current week.

DAYS = [
    {"slug": "pondelok", "weekday": 0, "label": "Pondelok"},  # Monday
    {"slug": "utorok",   "weekday": 1, "label": "Utorok"},    # Tuesday
    {"slug": "streda",   "weekday": 2, "label": "Streda"},    # Wednesday
    {"slug": "stvrtok",  "weekday": 3, "label": "Štvrtok"},   # Thursday
    {"slug": "piatok",   "weekday": 4, "label": "Piatok"},    # Friday
]

def day_url(city_base_url, day_slug):
    """
    Build the URL for a specific day.
    lv.namenu.sk uses /menu_den/menu_<day>/
    namenu.sk/city/ — unknown if day URLs exist; fall back to base URL.
    """
    if "lv.namenu.sk" in city_base_url:
        return f"https://lv.namenu.sk/menu_den/menu_{day_slug}/"
    # other namenu cities: try the same pattern, scraper will skip if no data
    base = city_base_url.rstrip("/")
    return f"{base}/menu_den/menu_{day_slug}/"

def week_date_for(weekday: int) -> date:
    """Return the date of the given weekday (0=Mon) in the current ISO week."""
    today = date.today()
    monday = today - timedelta(days=today.weekday())
    return monday + timedelta(days=weekday)

# ── classification ────────────────────────────────────────────────────────────

SOUP_KEYWORDS = [
    "polievka","vývar","kapustnica","gulášová","šošovicová","fazuľová",
    "paradajková","hrášková","frankfurtská","hŕstková","hokaido",
    "zemiaková pol","zeleninová pol","cícerovo-kel"
]
DESSERT_KEYWORDS = [
    "dezert","lievance","lievančeky","buchty","šišky","nákyp","chia",
    "tiramisu","perky naplnené","šúlance","orechové pečené rožky","palacinky"
]

def classify_type(text):
    t = text.lower()
    if re.match(r'^p\d?[.:\s]|^polievka\s*[č\d]', t): return "soup"
    if re.match(r'^dezert', t):                        return "dessert"
    for kw in SOUP_KEYWORDS:
        if kw in t: return "soup"
    for kw in DESSERT_KEYWORDS:
        if kw in t: return "dessert"
    return "main"

# ── field extractors ──────────────────────────────────────────────────────────

def extract_price(text):
    for pat in [
        r'(\d+[.,]\d{2})\s*(?:€|EUR|eur|Eur)(?!\w)',
        r'(?:€)\s*(\d+[.,]\d{2})',
        r'(\d+),-\s*(?:€|EUR)',
    ]:
        m = re.search(pat, text)
        if m: return float(m.group(1).replace(",", "."))
    m = re.search(r'(?:^|\s)(\d{1,2}[.,]\d{2})\s*$', text)
    if m:
        val = float(m.group(1).replace(',', '.'))
        if 3.0 <= val <= 25.0: return val
    return None

def extract_allergens(text):
    m = re.search(r'Alerg[eé]ny[:\s]+[-–]?\s*([0-9][0-9,\s]*)', text, re.IGNORECASE)
    if m: return [int(n) for n in re.findall(r'\d+', m.group(1)) if 1 <= int(n) <= 14]
    m = re.search(r'[(/]([0-9][0-9,\s]*)[)/]', text)
    if m and not re.search(r'[a-zA-ZáčďéíľňóšťúýžÁČĎÉÍĽŇÓŠŤÚÝŽ/]', m.group(1)):
        nums = [int(n) for n in re.findall(r'\d+', m.group(1)) if 1 <= int(n) <= 14]
        if nums: return nums
    m = re.search(r',\s*A:\s*([\d,\s]+)$', text)
    if m:
        nums = [int(n) for n in re.findall(r'\d+', m.group(1)) if 1 <= int(n) <= 14]
        if nums: return nums
    m = re.search(r'•[^|]*?\s([\d,]+)\s*\|', text)
    if m:
        nums = [int(n) for n in re.findall(r'\d+', m.group(1)) if 1 <= int(n) <= 14]
        if nums: return nums
    m = re.search(r'\s((?:\d{1,2},)+\d{1,2})\s+\(\d', text)
    if m:
        nums = [int(n) for n in re.findall(r'\d+', m.group(1)) if 1 <= int(n) <= 14]
        if nums and all(1 <= n <= 14 for n in nums): return nums
    m = re.search(r'(?:^|\s)((?:\d{1,2},)+\d{1,2})(?:\s+\d{1,2}[.,]\d{2}\s*(?:\w+)?)?\s*$', text)
    if m:
        nums = [int(n) for n in re.findall(r'\d+', m.group(1))]
        if nums and all(1 <= n <= 14 for n in nums): return nums
    m = re.search(r'(?<![,\d])\s+(\d{1,2})\s*$', text)
    if m:
        n = int(m.group(1))
        if 1 <= n <= 14: return [n]
    m = re.search(r'/\s*(\d{1,2})\s*$', text)
    if m:
        n = int(m.group(1))
        if 1 <= n <= 14: return [n]
    return []

def extract_weight(text):
    t = re.sub(r'^\w{1,2}[.:]\s*', '', text.strip())
    t = re.sub(r'(\d)gr\.', r'\1g', t)
    m = re.search(r'(\d+(?:[./]\d+)*\s*(?:g|kg|dcl|ml))(?!\s*(?:EUR|€|eur))', t, re.IGNORECASE)
    if m: return m.group(1).strip()
    m = re.search(r'(0[.,]\d+\s*l(?:iter)?)\b', t, re.IGNORECASE)
    return m.group(1).strip() if m else None

def clean_name(text):
    t = text
    t = re.sub(r'^(?:BIZNIS\s+MENU|XXL|Menu\s+\w{1,2}|Polievka\s*(?:č\.)?\s*\d*|Dezert|Vegán)[.:\s]+', '', t, flags=re.IGNORECASE)
    t = re.sub(r'^[A-Z]\s+(?=\d)', '', t)
    t = re.sub(r'^[A-Za-z0-9]\.\s*', '', t)
    t = re.sub(r'^\w\s*[.:)]\s+', '', t)
    t = re.sub(r'^\w{1,2}[.:)\s]\s+', '', t)
    t = re.sub(r'(\d)gr\.', r'\1g', t)
    t = re.sub(r'\d+(?:[.,/]\d+)*\s*(?:g|kg|l|ml|dcl)\s*', '', t, flags=re.IGNORECASE)
    t = re.sub(r'^r\.\s*', '', t)
    t = re.sub(r'^\w\s*:\s*', '', t)
    t = re.sub(r'\s*[-–]\s*(?:€\s*)?\d+[.,\-]\d*\s*(?:€|EUR|eur|Eur)?', '', t)
    t = re.sub(r'€\s*\d+[.,]\d{2}', '', t)
    t = re.sub(r'(?:€\s*)?\d+[.,]\d{2}\s*(?:€|EUR|eur|Eur)', '', t)
    t = re.sub(r'\d+,-\s*(?:€|EUR)', '', t)
    t = re.sub(r'\s*\([^)]*[a-zA-ZáčďéíľňóšťúýžÁČĎÉÍĽŇÓŠŤÚÝŽ][^)]*\)', '', t)
    t = re.sub(r'Alerg[eé]ny[:\s]*[-–]?\s*[0-9,\s]+', '', t, flags=re.IGNORECASE)
    t = re.sub(r'[(/]\s*[0-9][0-9,\s]*\s*[)/]', '', t)
    t = re.sub(r'\s*[-–|•]\s*\d+\s*kcal.*', '', t, flags=re.IGNORECASE)
    t = re.sub(r'\d+\s*(?:kcal|cal)\b.*', '', t, flags=re.IGNORECASE)
    t = re.sub(r'\bB:\d+.*', '', t)
    t = re.sub(r'^[●•]\s*', '', t)
    t = re.sub(r'[()]+', '', t)
    t = re.sub(r'^\d+\s+ks\s+', '', t)
    t = re.sub(r'\s*cena\s+bez\s+polievky.*', '', t, flags=re.IGNORECASE)
    t = re.sub(r'\s*•.*$', '', t)
    t = re.sub(r'\s*\(\d[/\d,\s]*kačice[^)]*\)', '', t, flags=re.IGNORECASE)
    t = re.sub(r'\s+(?:\d{1,2},)+\d{1,2}\s+\(', ' (', t)
    t = re.sub(r'\s+\d{1,2}\s*$', '', t)
    t = re.sub(r',\s*A:\s*[\d,\s]+$', '', t)
    t = re.sub(r'\s+(?:\d{1,2},)+\d{1,2}(?:\s+\d{1,2}[.,]\d{2}(?:\s*(?:€|EUR|eur|Eur))?)?\s*$', '', t)
    t = re.sub(r'\s+\d{1,2}[.,]\d{2}\s*$', '', t)
    t = re.sub(r'\s*/\s*\d{1,2}\s*$', '', t)
    t = re.sub(r'\s+(?:\d{1,2},)+\d{1,2}\s*$', '', t)
    t = re.sub(r'\s+\d{1,2}\s*$', '', t)
    return re.sub(r'\s+', ' ', t).strip(" |–-,/.")

def is_item_start(text):
    t = text.strip()
    if not t: return False
    if re.match(r'^[BTSVL]:\d', t): return False
    if re.match(r'^\(?\.?\d+\s*(?:kcal|cal)\b', t, re.IGNORECASE): return False
    patterns = [
        r'^\d+[.:]\s*\S', r'^\w[.:]\s', r'^[A-Za-z]\.\S', r'^\w\s*:\s*\w',
        r'^\w\)\s', r'^(?:Menu|MENU)\s+\w', r'^(?:BIZNIS\s+MENU|XXL)[.:\s]',
        r'^(?:Dezert|Vegán)[.:\s]', r'^P\d?[.:\s]',
        r'^(?:Polievka\s*(?:č\.)?\s*\d*)[.:\s]',
        r'^\d+[.,]\d+\s*[lLgGdD]', r'^\d+\s*[gG]\s',
        r'^\d+(?:/\d+)+\s*[gG]\s', r'^[A-Z]\s+\d',
    ]
    for pat in patterns:
        if re.match(pat, t, re.IGNORECASE): return True
    for kw in SOUP_KEYWORDS:
        if t.lower().startswith(kw): return True
    if re.match(r'^[A-ZÁČĎÉÍĽŇÓŠŤÚÝŽ]{3,}', t): return True
    return False

def group_lines_into_items(lines):
    items, current = [], None
    for line in lines:
        line = line.replace('\u00a0', ' ').strip()
        if not line: continue
        if is_item_start(line):
            if current: items.append(current)
            current = {"main_line": line, "extra": []}
        elif current is not None:
            current["extra"].append(line)
        else:
            current = {"main_line": line, "extra": []}
    if current: items.append(current)
    return items

def parse_macro_line(line):
    nutrition = {}
    for key, field in [('B','protein_g'),('T','fat_g'),('S','carbs_g'),('Vl','fiber_g'),('E','kcal')]:
        m = re.search(key + r':(\d+(?:[.,]\d+)?)\s*(?:g|kcal)?', line)
        if m: nutrition[field] = float(m.group(1).replace(',','.'))
    return nutrition if nutrition else None

def parse_item(group):
    main, extra = group["main_line"], group["extra"]
    all_text = main + " " + " ".join(extra)
    allergens = extract_allergens(all_text)
    price     = extract_price(all_text)
    weight    = extract_weight(main)
    name      = clean_name(main)
    kind      = classify_type(main)
    main_kcal = re.search(r'(\d+)\s*(?:kcal|cal)\b', main, re.IGNORECASE)
    main_nutrition = {'kcal': int(main_kcal.group(1))} if main_kcal else {}
    desc_parts, nutrition = [], {}
    for line in extra:
        line = line.replace('\u00a0', ' ').strip()
        if re.match(r'^[Aa]lerg[eé]ny', line): continue
        if re.match(r'^[BTSVL]:\d', line):
            n = parse_macro_line(line)
            if n: nutrition.update(n)
            continue
        km = re.match(r'^\(?.*?\)?\s*(\d+)\s*(?:kcal|cal)\b', line, re.IGNORECASE)
        if km: nutrition['kcal'] = int(km.group(1)); continue
        if re.match(r'^/', line) or len(line) < 5: continue
        desc_parts.append(line)
    description = " ".join(desc_parts).strip() or None
    if description:
        description = re.sub(r'Alerg[eé]ny[:\s]*[-–]?\s*[0-9,\s]+', '', description, flags=re.IGNORECASE)
        description = re.sub(r'[(/]\s*[0-9][0-9,\s]*\s*[)/]', '', description)
        description = re.sub(r'(?:€\s*)?\d+[.,]\d{2}\s*(?:€|EUR|eur|Eur)', '', description)
        description = re.sub(r'\s+', ' ', description).strip(" |–-,/.")
        if len(description) < 5: description = None
    merged = {**main_nutrition, **nutrition}
    return {"type": kind, "name": name, "description": description, "weight": weight,
            "price_eur": price, "allergens": allergens,
            "nutrition": merged if merged else None, "raw": main}

def make_slug(name):
    slug = name.lower()
    for src, dst in [('áä','a'),('čć','c'),('ď','d'),('éě','e'),('í','i'),
                     ('ľĺ','l'),('ň','n'),('óô','o'),('š','s'),('ť','t'),
                     ('úů','u'),('ý','y'),('ž','z')]:
        for ch in src: slug = slug.replace(ch, dst)
    slug = re.sub(r'[^\w\s-]', '', slug)
    slug = re.sub(r'[\s_-]+', '-', slug)
    return slug.strip('-')

# ── core scrape function ──────────────────────────────────────────────────────

def scrape_city_day(conn, city_def, day_def, menu_date: date):
    """Scrape one city × one day. Returns item count or 0."""
    url       = day_url(city_def["url"], day_def["slug"])
    date_str  = menu_date.isoformat()
    now       = datetime.now().isoformat()

    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
    except Exception as e:
        print(f"    ✗ network error: {e}")
        return 0

    response.encoding = "utf-8"
    soup = BeautifulSoup(response.text, "html.parser")

    restaurants_on_page = [h2 for h2 in soup.find_all("h2") if h2.find("a")]
    if not restaurants_on_page:
        print(f"    ✗ no data (Coming Soon or empty page)")
        return 0

    title_tag = soup.find("title")
    day_label = title_tag.text.strip().split("|")[0].strip() if title_tag else day_def["label"]

    city_id = get_or_create_city(conn, city_def["name"], city_def["slug"], city_def["url"])
    run_id  = upsert_scrape_run(conn, city_id, SOURCE, now, day_label, date_str)
    city_items = 0

    for h2 in restaurants_on_page:
        name_tag = h2.find("a")
        name = name_tag.text.strip()
        url_rest = name_tag.get("href", "")
        slug = make_slug(name)

        siblings = []
        node = h2.find_next_sibling()
        while node and node.name != "h2":
            siblings.append(node)
            node = node.find_next_sibling()

        full_text = " ".join(s.get_text(" ", strip=True) for s in siblings)
        phone_m   = re.search(r'[\+0][\d\s/]{7,}', full_text)
        phone     = phone_m.group(0).strip() if phone_m else ""
        delivery  = any("delivery_green" in img.get("src","")
                        for s in siblings for img in s.find_all("img"))
        address   = ""
        for s in siblings:
            pin = s.find("img", src=lambda x: x and "icon_pin" in x)
            if pin: address = pin.get("title","").strip(); break

        info_p = h2.find_next_sibling("p")
        info   = info_p.get_text(" ", strip=True) if info_p else ""

        menu_price  = None
        header_text = " ".join(s.get_text(" ", strip=True) for s in siblings[:4])
        for mp_pat in [r'(?:od|from|za)\s*(\d+[.,]\d{2})\s*(?:€|EUR|eur)',
                       r'^\s*(\d+[.,]\d{2})\s*(?:€|EUR)',
                       r'(\d+[.,]\d{2})\s*(?:€|EUR)']:
            mp = re.search(mp_pat, header_text, re.IGNORECASE)
            if mp: menu_price = float(mp.group(1).replace(',','.')); break

        rest_id = upsert_restaurant(conn, city_id, name, slug, url_rest,
                                    address, phone, delivery, info)

        raw_lines = []
        for s in siblings:
            table = s if s.name == "table" else s.find("table")
            if not table: continue
            for row in table.find_all("tr"):
                cells = row.find_all("td")
                if len(cells) >= 2:
                    lines = [l.strip() for l in cells[1].get_text("\n", strip=True).split("\n") if l.strip()]
                    raw_lines.extend(lines)

        groups = group_lines_into_items(raw_lines)
        items  = [parse_item(g) for g in groups]

        conn.executemany("""
            INSERT INTO menu_items
                (restaurant_id, scrape_run_id, type, name, description,
                 weight, price_eur, menu_price, allergens, nutrition, raw)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, [(rest_id, run_id, i["type"], i["name"], i["description"],
               i["weight"], i["price_eur"], menu_price,
               json.dumps(i["allergens"], ensure_ascii=False) if i["allergens"] else "[]",
               json.dumps(i["nutrition"],  ensure_ascii=False) if i["nutrition"]  else None,
               i["raw"]) for i in items])
        conn.commit()
        city_items += len(items)
        print(f"      {name}: {len(items)} items")

    if city_items == 0:
        # nothing scraped — roll back the empty run
        conn.execute("DELETE FROM scrape_runs WHERE id=?", (run_id,))
        conn.commit()
        print(f"    ✗ 0 items — run discarded")

    return city_items


def scrape(days_to_scrape=None):
    """
    days_to_scrape: list of day dicts from DAYS, or None = all weekdays.
    """
    conn = connect()
    init_db(conn)

    if days_to_scrape is None:
        days_to_scrape = DAYS

    grand_total = 0

    for city_def in CITIES:
        print(f"\n── {city_def['name']} ──")
        city_total = 0
        for day_def in days_to_scrape:
            menu_date = week_date_for(day_def["weekday"])
            print(f"  {day_def['label']} ({menu_date})")
            count = scrape_city_day(conn, city_def, day_def, menu_date)
            city_total  += count
            grand_total += count
        if city_total > 0:
            print(f"  → {city_total} items total")

    conn.close()
    print(f"\n✓ Done: {grand_total} items total")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = sys.argv[1:]

    if "--today" in args:
        today_weekday = date.today().weekday()
        matching = [d for d in DAYS if d["weekday"] == today_weekday]
        if not matching:
            print("Today is a weekend — namenu only has Mon–Fri menus.")
            sys.exit(0)
        scrape(days_to_scrape=matching)

    elif "--day" in args:
        idx  = args.index("--day")
        slug = args[idx + 1] if idx + 1 < len(args) else ""
        matching = [d for d in DAYS if d["slug"] == slug]
        if not matching:
            print(f"Unknown day '{slug}'. Valid: {', '.join(d['slug'] for d in DAYS)}")
            sys.exit(1)
        scrape(days_to_scrape=matching)

    else:
        # default: scrape full week
        scrape()