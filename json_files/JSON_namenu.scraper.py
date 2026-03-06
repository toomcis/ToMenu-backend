import requests
from bs4 import BeautifulSoup
import json
import re
from datetime import datetime

URL = "https://lv.namenu.sk/"
HEADERS = {"User-Agent": "namenu-scraper/1.0 (personal project)"}

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
    # formats: 7,00 € / 7.00 € / €7.00 / 7,00 EUR / 7,-€ / 7,- €
    patterns = [
        r'(\d+[.,]\d{2})\s*(?:€|EUR|eur|Eur)(?!\w)',  # 7,50 € or 7,50 EUR
        r'(?:€)\s*(\d+[.,]\d{2})',                     # €7.50
        r'(\d+),-\s*(?:€|EUR)',                        # 7,-€
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            val = m.group(1).replace(",", ".")
            return float(val)
    # bare price at end of line with no currency unit (e.g. Geurud: "...omáčkou 1,3,7 7,50")
    # only match if it looks like a realistic meal price (3.00 - 25.00)
    m = re.search(r'(?:^|\s)(\d{1,2}[.,]\d{2})\s*$', text)
    if m:
        val = float(m.group(1).replace(',', '.'))
        if 3.0 <= val <= 25.0:
            return val
    return None

def extract_allergens(text):
    # "Alergény: 1,3,7" or "(1,3,7)" or "/1,3,7/"
    # also handle "Alergény: – 1,3,7" (with dash)
    m = re.search(r'Alerg[eé]ny[:\s]+[-–]?\s*([0-9][0-9,\s]*)', text, re.IGNORECASE)
    if m:
        return [int(n) for n in re.findall(r'\d+', m.group(1)) if 1 <= int(n) <= 14]
    # allergen parens: only match if content is digits/commas/spaces only (no letters or slashes like "1/4 kačice")
    m = re.search(r'[(/]([0-9][0-9,\s]*)[)/]', text)
    if m and not re.search(r'[a-zA-ZáčďéíľňóšťúýžÁČĎÉÍĽŇÓŠŤÚÝŽ/]', m.group(1)):
        nums = [int(n) for n in re.findall(r'\d+', m.group(1)) if 1 <= int(n) <= 14]
        if nums: return nums
    # "A: 1, 6" or "A: 8" format (Bistro Sunshine)
    m = re.search(r',\s*A:\s*([\d,\s]+)$', text)
    if m:
        nums = [int(n) for n in re.findall(r'\d+', m.group(1)) if 1 <= int(n) <= 14]
        if nums: return nums
    # "• 150/200g 1,3 | price" format (TriP) — allergens between bullet+weight and pipe
    m = re.search(r'•[^|]*?\s([\d,]+)\s*\|', text)
    if m:
        nums = [int(n) for n in re.findall(r'\d+', m.group(1)) if 1 <= int(n) <= 14]
        if nums: return nums
    # "1,7 (0,33l)" — allergens before a liquid-weight paren (Tilia soup)
    m = re.search(r'\s((?:\d{1,2},)+\d{1,2})\s+\(\d', text)
    if m:
        nums = [int(n) for n in re.findall(r'\d+', m.group(1)) if 1 <= int(n) <= 14]
        if nums and all(1 <= n <= 14 for n in nums): return nums
    # bare inline allergens at end: "...ryža 1,3,7 7,50" or "1,3,9" (Geurud, Central Gastro)
    m = re.search(r'(?:^|\s)((?:\d{1,2},)+\d{1,2})(?:\s+\d{1,2}[.,]\d{2}\s*(?:\w+)?)?\s*$', text)
    if m:
        nums = [int(n) for n in re.findall(r'\d+', m.group(1))]
        if nums and all(1 <= n <= 14 for n in nums):
            return nums
    # single allergen at end — only if NOT preceded by a comma (so not tail of "1,3,9")
    # matches "/ 11" or a space-separated lone number like "...kačica 7"
    m = re.search(r'(?<![,\d])\s+(\d{1,2})\s*$', text)
    if m:
        n = int(m.group(1))
        if 1 <= n <= 14: return [n]
    # slash-prefixed single allergen: "/ 11"
    m = re.search(r'/\s*(\d{1,2})\s*$', text)
    if m:
        n = int(m.group(1))
        if 1 <= n <= 14: return [n]
    return []

def extract_weight(text):
    # strip leading label (e.g. "4." in "4.300g") before extracting weight
    t = re.sub(r'^\w{1,2}[.:]\s*', '', text.strip())
    # normalize "gr." suffix (100/80/160gr.) -> "g"
    t = re.sub(r'(\d)gr\.', r'\1g', t)
    # solid: 300g, 150/200g — not price-adjacent
    m = re.search(r'(\d+(?:[./]\d+)*\s*(?:g|kg|dcl|ml))(?!\s*(?:EUR|€|eur))', t, re.IGNORECASE)
    if m: return m.group(1).strip()
    # liquid volume: 0,33l / 0,25 l
    m = re.search(r'(0[.,]\d+\s*l(?:iter)?)\b', t, re.IGNORECASE)
    return m.group(1).strip() if m else None

def clean_name(text):
    t = text
    # strip known prefixes (BIZNIS MENU, XXL, Menu A, Polievka č.1, Dezert, Vegán:, etc.)
    t = re.sub(r'^(?:BIZNIS\s+MENU|XXL|Menu\s+\w{1,2}|Polievka\s*(?:č\.)?\s*\d*|Dezert|Vegán)[.:\s]+', '', t, flags=re.IGNORECASE)
    # strip Gourmet-style "A 140/200 g": single uppercase letter + space + digit
    t = re.sub(r'^[A-Z]\s+(?=\d)', '', t)
    # strip digit or letter label with or without space: "1. " "4.Word" "A.Word"
    t = re.sub(r'^[A-Za-z0-9]\.\s*', '', t)
    # strip single-char/digit labels: "1.", "A:", "A : ", "P1 ", "B) "
    t = re.sub(r'^\w\s*[.:)]\s+', '', t)
    t = re.sub(r'^\w{1,2}[.:)\s]\s+', '', t)
    # normalize gr. -> g before stripping (prevents 'r.' leftover e.g. from '160gr.')
    t = re.sub(r'(\d)gr\.', r'\1g', t)
    # strip ALL weight patterns
    t = re.sub(r'\d+(?:[.,/]\d+)*\s*(?:g|kg|l|ml|dcl)\s*', '', t, flags=re.IGNORECASE)
    # strip leftover 'r.' after 'gr.' weight was removed
    t = re.sub(r'^r\.\s*', '', t)
    # strip label that appears AFTER weight: e.g. "A: name" or "A : name"
    t = re.sub(r'^\w\s*:\s*', '', t)
    # strip price
    t = re.sub(r'\s*[-–]\s*(?:€\s*)?\d+[.,\-]\d*\s*(?:€|EUR|eur|Eur)?', '', t)
    t = re.sub(r'€\s*\d+[.,]\d{2}', '', t)              # €7.00 style
    t = re.sub(r'(?:€\s*)?\d+[.,]\d{2}\s*(?:€|EUR|eur|Eur)', '', t)
    t = re.sub(r'\d+,-\s*(?:€|EUR)', '', t)
    # strip paren blocks containing letters FIRST — these are portion notes, not allergens
    # e.g. "(1/4 kačice, 150, 200g)", "(za tepla)" — must happen before allergen block strip
    t = re.sub(r'\s*\([^)]*[a-zA-ZáčďéíľňóšťúýžÁČĎÉÍĽŇÓŠŤÚÝŽ][^)]*\)', '', t)
    # strip allergen blocks
    t = re.sub(r'Alerg[eé]ny[:\s]*[-–]?\s*[0-9,\s]+', '', t, flags=re.IGNORECASE)
    t = re.sub(r'[(/]\s*[0-9][0-9,\s]*\s*[)/]', '', t)
    # strip kcal / macro info
    t = re.sub(r'\s*[-–|•]\s*\d+\s*kcal.*', '', t, flags=re.IGNORECASE)
    t = re.sub(r'\d+\s*(?:kcal|cal)\b.*', '', t, flags=re.IGNORECASE)
    t = re.sub(r'\bB:\d+.*', '', t)
    # strip bullet chars
    t = re.sub(r'^[●•]\s*', '', t)
    # strip leftover parens
    t = re.sub(r'[()]+', '', t)
    # strip quantity prefix like "1 ks"
    t = re.sub(r'^\d+\s+ks\s+', '', t)
    # strip trailing notes like "cena bez polievky"
    t = re.sub(r'\s*cena\s+bez\s+polievky.*', '', t, flags=re.IGNORECASE)
    # strip TriP-style "• allergens | price | note" suffix
    t = re.sub(r'\s*•.*$', '', t)
    # strip Tilia-style portion note in parens before weight: "(1/4 kačice, 150,"
    t = re.sub(r'\s*\(\d[/\d,\s]*kačice[^)]*\)', '', t, flags=re.IGNORECASE)
    # strip inline allergens before a paren group: "1,3,7 (150, 200g)" or "1,3,7 (1/4 kačice...)"
    t = re.sub(r'\s+(?:\d{1,2},)+\d{1,2}\s+\(', ' (', t)
    # strip trailing single allergen digit: "...hranolčekmi 3" or "...syrom 1"
    t = re.sub(r'\s+\d{1,2}\s*$', '', t)
    # strip Sunshine-style allergen suffix ", A: 1, 6"
    t = re.sub(r',\s*A:\s*[\d,\s]+$', '', t)
    # strip bare inline allergens like "1,3,7" or "1,3,7,10" at end, optionally followed by price
    t = re.sub(r'\s+(?:\d{1,2},)+\d{1,2}(?:\s+\d{1,2}[.,]\d{2}(?:\s*(?:€|EUR|eur|Eur))?)?\s*$', '', t)
    # strip bare trailing price with no unit (e.g. " 7,50" at end after name)
    t = re.sub(r'\s+\d{1,2}[.,]\d{2}\s*$', '', t)
    # strip "/ 11" or "/11" trailing allergen-after-slash
    t = re.sub(r'\s*/\s*\d{1,2}\s*$', '', t)
    # final pass: strip any leftover bare allergen sequence at end (e.g. after price was already stripped)
    t = re.sub(r'\s+(?:\d{1,2},)+\d{1,2}\s*$', '', t)
    t = re.sub(r'\s+\d{1,2}\s*$', '', t)  # lone trailing digit
    return re.sub(r'\s+', ' ', t).strip(" |–-,/.")

def is_description_line(text):
    """Lines that are clearly descriptions/continuation, not new menu items."""
    t = text.strip()
    # pure allergen line
    if re.match(r'^[Aa]lerg[eé]ny', t): return True
    # pure macro line
    if re.match(r'^[BTSVL]:\d', t): return True
    # pure kcal line
    if re.match(r'^\d+\s*(?:kcal|cal)\b', t, re.IGNORECASE): return True
    # English translation line (Sorrento uses this)
    if re.match(r'^/', t): return True
    # Continuation text (no label, no weight at start, not a soup keyword start)
    # Heuristic: doesn't start with a label pattern
    if re.match(r'^(?:\w{1,2}[.:)\s]|\d+[.:\s]|P\d?[.:\s]|Menu\s)', t, re.IGNORECASE): return False
    if re.match(r'^(?:BIZNIS|XXL|Dezert|Vegán|Polievka)', t, re.IGNORECASE): return False
    # If it starts with a capital letter and is a long sentence without a label → description
    if len(t) > 40 and not re.match(r'^\d', t):
        return True
    return False

def is_item_start(text):
    """Does this line start a new menu item?"""
    t = text.strip()
    if not t: return False
    # macro/nutrition lines are NEVER item starts (e.g. "B:41g, T:9g, S:49g")
    if re.match(r'^[BTSVL]:\d', t): return False
    # kcal-only lines are never item starts
    if re.match(r'^\(?\.?\d+\s*(?:kcal|cal)\b', t, re.IGNORECASE): return False
    # explicit item starters
    patterns = [
        r'^\d+[.:]\s*\S',                       # "1. " "2: " "4.Grill..."
        r'^\w[.:]\s',                            # "A. " "B: "
        r'^[A-Za-z]\.\S',                        # "A.Word" no space (Stanley)
        r'^\w\s*:\s*\w',                        # "A: name" or "A : name" (Golden Eagle)
        r'^\w\)\s',                              # "A) "
        r'^(?:Menu|MENU)\s+\w',                 # "Menu 1:"
        r'^(?:BIZNIS\s+MENU|XXL)[.:\s]',        # "BIZNIS MENU:"
        r'^(?:Dezert|Vegán)[.:\s]',             # "Dezert:"
        r'^P\d?[.:\s]',                         # "P: " "P1 "
        r'^(?:Polievka\s*(?:č\.)?\s*\d*)[.:\s]', # "Polievka č.1."
        r'^\d+[.,]\d+\s*[lLgGdD]',             # "0,33l ..." volume at start (soup)
        r'^\d+\s*[gG]\s',                        # "300g Dish..."
        r'^\d+(?:/\d+)+\s*[gG]\s',             # "120/200/60 g ..." multi-slash weight
        r'^[A-Z]\s+\d',                          # "A 140/200 g ..." (Gourmet)
    ]
    for pat in patterns:
        if re.match(pat, t, re.IGNORECASE): return True
    # Lines that start directly with a soup keyword (no label)
    for kw in SOUP_KEYWORDS:
        if t.lower().startswith(kw): return True
    # Lines that start with ALL CAPS word (like "CELÁ PEČENÁ KAČICA")
    if re.match(r'^[A-ZÁČĎÉÍĽŇÓŠŤÚÝŽ]{3,}', t): return True
    return False

# ── line grouping ─────────────────────────────────────────────────────────────

def group_lines_into_items(lines):
    """
    Group raw lines into logical items.
    Each item is a dict with 'main_line' (the primary line) and 'extra' (description/allergen lines).
    """
    items = []
    current = None

    for line in lines:
        line = line.replace('\u00a0', ' ').strip()
        if not line:
            continue

        if is_item_start(line):
            if current:
                items.append(current)
            current = {"main_line": line, "extra": []}
        elif current is not None:
            current["extra"].append(line)
        else:
            # orphan line before any item starts — treat as item
            current = {"main_line": line, "extra": []}

    if current:
        items.append(current)

    return items

# ── item parsing ──────────────────────────────────────────────────────────────

def parse_macro_line(line):
    """Parse 'B:41g, T:9g, S:49g, Vl:0,8g' into nutrition dict."""
    nutrition = {}
    for key, field in [('B','protein_g'),('T','fat_g'),('S','carbs_g'),('Vl','fiber_g'),('E','kcal')]:
        m = re.search(key + r':(\d+(?:[.,]\d+)?)\s*(?:g|kcal)?', line)
        if m: nutrition[field] = float(m.group(1).replace(',','.'))
    return nutrition if nutrition else None

def parse_item(group):
    main = group["main_line"]
    extra = group["extra"]

    # Merge allergen-only extra lines back into main for allergen extraction
    all_text = main + " " + " ".join(extra)

    allergens = extract_allergens(all_text)
    price     = extract_price(all_text)
    weight    = extract_weight(main)  # weight from main line only
    name      = clean_name(main)
    kind      = classify_type(main)
    # extract kcal from main line if present (e.g. "540 cal" at end)
    main_kcal     = re.search(r'(\d+)\s*(?:kcal|cal)\b', main, re.IGNORECASE)
    main_nutrition = {'kcal': int(main_kcal.group(1))} if main_kcal else {}

    # Build description from extra lines, skipping pure allergen/macro/translation lines
    desc_parts = []
    nutrition = {}
    for line in extra:
        line = line.replace('\u00a0', ' ').strip()
        # skip pure allergen lines
        if re.match(r'^[Aa]lerg[eé]ny', line): continue
        # macro lines → parse into nutrition, skip from description
        if re.match(r'^[BTSVL]:\d', line):
            n = parse_macro_line(line)
            if n: nutrition.update(n)
            continue
        # kcal-only lines → store as nutrition
        km = re.match(r'^\(?.*?\)?\s*(\d+)\s*(?:kcal|cal)\b', line, re.IGNORECASE)
        if km:
            nutrition['kcal'] = int(km.group(1))
            continue
        # skip English translation lines (start with /)
        if re.match(r'^/', line): continue
        # skip short label-only artifacts
        if len(line) < 5: continue
        desc_parts.append(line)

    description = " ".join(desc_parts).strip() if desc_parts else None
    # Clean description too
    if description:
        description = re.sub(r'Alerg[eé]ny[:\s]*[-–]?\s*[0-9,\s]+', '', description, flags=re.IGNORECASE)
        description = re.sub(r'[(/]\s*[0-9][0-9,\s]*\s*[)/]', '', description)
        description = re.sub(r'(?:€\s*)?\d+[.,]\d{2}\s*(?:€|EUR|eur|Eur)', '', description)
        description = re.sub(r'\s+', ' ', description).strip(" |–-,/.")
        if len(description) < 5:
            description = None

    merged_nutrition = {**main_nutrition, **nutrition}  # extra overrides main if both have kcal
    return {
        "type":        kind,
        "name":        name,
        "description": description,
        "weight":      weight,
        "price_eur":   price,
        "allergens":   allergens,
        "nutrition":   merged_nutrition if merged_nutrition else None,
        "raw":         main
    }

# ── scraper ───────────────────────────────────────────────────────────────────

def scrape():
    response = requests.get(URL, headers=HEADERS, timeout=15)
    response.encoding = "utf-8"
    soup = BeautifulSoup(response.text, "html.parser")

    title_tag = soup.find("title")
    day_label = title_tag.text.strip().split("|")[0].strip() if title_tag else ""

    restaurants = []

    for h2 in soup.find_all("h2"):
        name_tag = h2.find("a")
        if not name_tag:
            continue

        name = name_tag.text.strip()
        url  = name_tag.get("href", "")

        siblings = []
        node = h2.find_next_sibling()
        while node and node.name != "h2":
            siblings.append(node)
            node = node.find_next_sibling()

        full_text = " ".join(s.get_text(" ", strip=True) for s in siblings)

        phone_m = re.search(r'[\+0][\d\s/]{7,}', full_text)
        phone   = phone_m.group(0).strip() if phone_m else ""

        delivery = any(
            "delivery_green" in img.get("src", "")
            for s in siblings for img in s.find_all("img")
        )

        address = ""
        for s in siblings:
            pin = s.find("img", src=lambda x: x and "icon_pin" in x)
            if pin:
                address = pin.get("title", "").strip()
                break

        info_p = h2.find_next_sibling("p")
        info   = info_p.get_text(" ", strip=True) if info_p else ""

        # extract menu price from header area — try several patterns, take the first match
        menu_price = None
        header_text = " ".join(s.get_text(" ", strip=True) for s in siblings[:4])
        for mp_pat in [
            r'(?:od|from|za)\s*(\d+[.,]\d{2})\s*(?:€|EUR|eur)',   # "od 7,00€" / "za 6,99€"
            r'^\s*(\d+[.,]\d{2})\s*(?:€|EUR)',                    # "6,65 € ..."
            r'(\d+[.,]\d{2})\s*(?:€|EUR)',                         # any first price
        ]:
            mp = re.search(mp_pat, header_text, re.IGNORECASE)
            if mp:
                menu_price = float(mp.group(1).replace(',', '.'))
                break

        raw_lines = []
        for s in siblings:
            table = s if s.name == "table" else s.find("table")
            if not table:
                continue
            for row in table.find_all("tr"):
                cells = row.find_all("td")
                if len(cells) >= 2:
                    lines = [l.strip() for l in cells[1].get_text("\n", strip=True).split("\n") if l.strip()]
                    raw_lines.extend(lines)

        groups = group_lines_into_items(raw_lines)
        menu   = [parse_item(g) for g in groups]

        restaurants.append({
            "name":       name,
            "url":        url,
            "address":    address,
            "phone":      phone,
            "delivery":   delivery,
            "info":       info,
            "menu_price": menu_price,
            "menu":       menu
        })

    result = {
        "source":           URL,
        "scraped_at":       datetime.now().isoformat(),
        "day":              day_label,
        "restaurant_count": len(restaurants),
        "restaurants":      restaurants
    }

    with open("lv.namenu.json", "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"Scraped {len(restaurants)} restaurants -> lv.namenu.json")

if __name__ == "__main__":
    scrape()