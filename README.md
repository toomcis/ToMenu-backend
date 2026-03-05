# namenu+ &nbsp;[![beta](https://img.shields.io/badge/status-beta-yellow)](https://namenuplus.toomcis.eu/api)

> Structured lunch menus from Slovak restaurants, served as a REST API.

namenu+ scrapes daily lunch menus from [namenu.sk](https://namenu.sk) and exposes them via a clean JSON API. Filter by city, day of week, allergens, price, and delivery availability. Built to be extended — adding new cities or scraper sources is straightforward.

**Currently covering:** Levice 🇸🇰 (more cities coming as namenu.sk expands)

---

## What's in this repo

```
namenuPlus/
  scrapers/
    db.py                  # shared DB helpers — used by all scrapers
    namenu.scrape.py       # namenu.sk scraper (multi-city, full week)
  webUI/
    index.html             # admin dashboard
    favicon.ico
  api.py                   # FastAPI REST API
  main.py                  # CLI — key management only
  scrape_all.sh            # runs all scrapers
```

---

## API

Base URL: `https://api.namenuplus.toomcis.eu` *(not yet publicly hosted — coming soon)*

All requests require an `Authorization` header with your API key.

### Endpoints

| Method  | Path                               | Description                            |
| ------- | ---------------------------------- | -------------------------------------- |
| `GET` | `/api/cities`                    | List all available cities              |
| `GET` | `/api/{city}/week`               | Which days have data this week         |
| `GET` | `/api/{city}/restaurants`        | Restaurants for a city on a given date |
| `GET` | `/api/{city}/restaurants/{slug}` | Full menu for one restaurant           |
| `GET` | `/api/{city}/menu`               | All dishes, filterable                 |

#### `/api/{city}/menu` query params

| Param                 | Type                  | Description                                    |
| --------------------- | --------------------- | ---------------------------------------------- |
| `date`              | `YYYY-MM-DD`        | Menu date, defaults to today                   |
| `type`              | `soup\|main\|dessert` | Dish type filter                               |
| `delivery`          | `bool`              | Delivery-only filter                           |
| `max_price`         | `float`             | Max price in EUR                               |
| `exclude_allergens` | `1,7,14`            | Comma-separated EU allergen numbers to exclude |
| `limit`             | `int`               | Max results (default 50, max 200)              |
| `offset`            | `int`               | Pagination offset                              |

Full interactive docs: [namenuplus.toomcis.eu/api](https://namenuplus.toomcis.eu/api)

---

## Getting an API key

namenu+ is in **early access beta**. Keys are free and issued manually.
Send a request to [contact@toomcis.eu](mailto:contact@toomcis.eu?subject=namenu%2B%20API%20Key%20Request) or use the button on the [API docs page](https://namenuplus.toomcis.eu/api).

---

## Setup & installation

> **Note:** Full Docker setup is coming. The instructions below are for local development only.

```bash
# clone
git clone https://github.com/toomcis/namenuPlus.git
cd namenuPlus

# install dependencies
pip install fastapi uvicorn requests beautifulsoup4

# create your first API key
python main.py --add-key "my key"

# scrape today's menus
python -X utf8 scrapers/namenu.scrape.py --today

# start the API + admin dashboard
uvicorn api:app --reload
# → http://127.0.0.1:8000
```

### Scraper commands

```bash
./scrape_all.sh                      # full week, all sources
./scrape_all.sh --today              # just today
./scrape_all.sh --day pondelok       # specific day (Slovak day slug)

# or run a single scraper directly
python -X utf8 scrapers/namenu.scrape.py --today
python -X utf8 scrapers/namenu.scrape.py --day streda
```

**Slovak day slugs:** `pondelok` `utorok` `streda` `stvrtok` `piatok`

### Key management

```bash
python main.py --add-key "label"     # create a key
python main.py --list-keys           # list all keys
python main.py --revoke-key 3        # revoke key #3
```

---

## Adding a new scraper source

1. Create `scrapers/yoursite.scrape.py`
2. Import shared helpers from `scrapers/db.py`:
   ```python
   from scrapers.db import connect, init_db, get_or_create_city, upsert_restaurant, upsert_scrape_run
   ```
3. Use `SOURCE = "yoursite"` so runs are tracked separately from namenu
4. Add a line to `scrape_all.sh`:
   ```bash
   python -X utf8 scrapers/yoursite.scrape.py $ARGS
   ```

The DB schema supports multiple sources per city per date via the `source` column on `scrape_runs`.

---

## Database schema

```sql
cities         id, name, slug, url
restaurants    id, city_id, name, slug, url, address, phone, delivery, info
scrape_runs    id, city_id, source, scraped_at, day, date
               UNIQUE(city_id, source, date)   ← re-scraping replaces, not stacks
menu_items     id, restaurant_id, scrape_run_id, type, name, description,
               weight, price_eur, menu_price, allergens, nutrition, raw
api_keys       id, key_hash, label, created_at, last_used, active
```

---

## Roadmap

- [ ] Docker image + compose setup
- [ ] Android app
- [ ] More cities (as namenu.sk expands)
- [ ] Additional scraper sources beyond namenu.sk
- [ ] Public API hosting at `api.namenuplus.toomcis.eu`
- [ ] Webhook support (get notified when today's menu is scraped)
- [ ] OpenAPI / Swagger docs auto-generated

---

## Contributing

PRs welcome, especially:

- **New cities** — if you know of a city portal with structured lunch menus
- **New scraper sources** — any Slovak/Czech lunch aggregator site
- **Parser improvements** — the namenu scraper handles a lot of edge cases but there's always more

Open an issue before starting anything large so we can align.

---

## License

MIT — do whatever, just don't pretend you made it.

---

*Made in Levice 🇸🇰 by [toomcis](https://toomcis.eu)*
