# ToMenu &nbsp;[![beta](https://img.shields.io/badge/status-beta-yellow)](https://tomenu.sk) [![license](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)

> Structured lunch menus from Slovak restaurants, served as a clean REST API.

ToMenu scrapes daily lunch menus from Slovak restaurants and exposes them via a JSON API. Filter by city, day, allergens, price, and delivery availability. Built to be self-hostable and easy to extend with new cities or scraper sources.

**Currently covering:** Levice 🇸🇰 — more cities as the project expands.

---

## Project structure

```
tomenu/
├── api.py                      # FastAPI REST API + admin dashboard
├── main.py                     # CLI — key management & scrape log
├── scrapeAll.sh                # runs all scrapers in sequence
├── start.sh                    # container entrypoint
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .gitignore
├── scrapers/
│   ├── db.py                   # shared DB helpers for all scrapers
│   └── namenu.scrape.py        # namenu.sk scraper (multi-city, full week)
├── static/                     # static assets served by the API
└── webUI/
    ├── index.html              # admin dashboard UI
    ├── favicon.ico
    └── locales/
        ├── en.json
        ├── sk.json
        └── cs.json
```

---

## How it works

On startup the container immediately runs a full scrape so the DB is never empty on first boot. After that, a cron job re-scrapes at **06:00, 12:00, 18:00, and 00:00** every day. You can also trigger a scrape manually via the admin dashboard or CLI.

Two separate SQLite databases are used:

| File          | Contains                                |
| ------------- | --------------------------------------- |
| `main.db`   | API keys, scrape audit log              |
| `namenu.db` | Cities, restaurants, menus, scrape runs |

This keeps auth data separate from scraped data — you can wipe `namenu.db` without touching your keys.

---

## API

**Base URL:** `https://api.tomenu.sk`

All requests require an `Authorization` header containing your API key.

```http
GET /api/levice/menu
Authorization: your-api-key-here
```

### Endpoints

| Method  | Path                               | Description                            |
| ------- | ---------------------------------- | -------------------------------------- |
| `GET` | `/api/cities`                    | List all available cities              |
| `GET` | `/api/{city}/week`               | Which days have data this week         |
| `GET` | `/api/{city}/restaurants`        | Restaurants for a city on a given date |
| `GET` | `/api/{city}/restaurants/{slug}` | Full menu for one restaurant           |
| `GET` | `/api/{city}/menu`               | All dishes, filterable                 |

### `/api/{city}/menu` query params

| Param                 | Type                      | Description                                      |
| --------------------- | ------------------------- | ------------------------------------------------ |
| `date`              | `YYYY-MM-DD`            | Menu date, defaults to today                     |
| `type`              | `soup \| main \| dessert` | Dish type filter                                 |
| `delivery`          | `bool`                  | Delivery-only restaurants                        |
| `max_price`         | `float`                 | Max price in EUR                                 |
| `exclude_allergens` | `1,7,14`                | EU allergen numbers to exclude (comma-separated) |
| `limit`             | `int`                   | Max results (default 50, max 200)                |
| `offset`            | `int`                   | Pagination offset                                |

Full API docs: [tomenu.sk/api](https://tomenu.sk/api)

---

## Getting an API key

ToMenu uses API keys to prevent abuse. Keys are **free** and issued manually.

Visit [tomenu.sk/api](https://tomenu.sk/api), scroll to the bottom, and use the email template button. Alternatively email [contact@tomenu.sk](mailto:contact@tomenu.sk?subject=ToMenu%20API%20Key%20Request) directly.

---

## Self-hosting with Docker

The recommended way to run ToMenu is via the published Docker image.

### Quick start

```bash
docker run -d \
  --name tomenu-api \
  -p 2332:2332 \
  -e PORT=2332 \
  -e MAIN_DB=/app/data/main.db \
  -e NAMENU_DB=/app/data/namenu.db \
  -v tomenu_data:/app/data \
  ghcr.io/toomcis/tomenu:latest
```

### With docker-compose (recommended)

```yaml
services:
  tomenu:
    image: ghcr.io/toomcis/tomenu:latest
    restart: unless-stopped
    container_name: tomenu-api
    environment:
      - PORT=2332
      - MAIN_DB=/app/data/main.db
      - NAMENU_DB=/app/data/namenu.db
    ports:
      - "2332:2332"
    volumes:
      - tomenu_data:/app/data

volumes:
  tomenu_data:
```

```bash
docker compose up -d
```

On first boot, watch the logs for your admin API key:

```bash
docker logs tomenu-api
```

```
==============================
 ToMenu ready
==============================
API key created for 'admin':
  <your-key-here>
Save this — it won't be shown again.
==============================
```

### Environment variables

| Variable      | Default       | Description                    |
| ------------- | ------------- | ------------------------------ |
| `PORT`      | `8000`      | Port the API listens on        |
| `MAIN_DB`   | `main.db`   | Path to the auth database      |
| `NAMENU_DB` | `namenu.db` | Path to the menu data database |

### ⚠️ Keep your image up to date

ToMenu is under active development. Always pull the latest image before reporting bugs.

```bash
docker compose pull && docker compose up -d
```

---

## Admin dashboard

The admin dashboard is available at `http://localhost:2332/` and is **intentionally not exposed publicly**. If proxying behind nginx or Caddy, restrict access to `/` and `/admin/*` to local IPs only.

Example nginx rule:

```nginx
server {
    server_name api.tomenu.sk;

    location ~ ^/(admin.*|)$ {
        allow 127.0.0.1;
        allow 192.168.0.0/16;
        deny all;
    }

    location / {
        proxy_pass http://127.0.0.1:2332;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Local development

```bash
git clone https://github.com/toomcis/tomenu.git
cd tomenu

pip install -r requirements.txt

# create your first API key
python main.py --add-key "dev"

# scrape today's menus
python -X utf8 scrapers/namenu.scrape.py --today

# start the API
uvicorn api:app --reload
# → http://127.0.0.1:8000
```

### Scraper commands

```bash
./scrapeAll.sh                        # full week, all sources
./scrapeAll.sh --today                # just today
./scrapeAll.sh --day pondelok         # specific day

python -X utf8 scrapers/namenu.scrape.py --today
python -X utf8 scrapers/namenu.scrape.py --day streda
```

**Slovak day slugs:** `pondelok` `utorok` `streda` `stvrtok` `piatok`

### Key management (CLI)

```bash
python main.py --add-key "label"      # create a key
python main.py --list-keys            # list all keys
python main.py --revoke-key 3         # revoke key #3
python main.py --scrape-log           # show recent scrape audit log
```

---

## Adding a new scraper source

1. Create `scrapers/yoursite.scrape.py`
2. Import the shared DB helpers:
   ```python
   from scrapers.db import connect, init_db, get_or_create_city, upsert_restaurant, upsert_scrape_run
   ```
3. Set `SOURCE = "yoursite"` so runs are tracked separately
4. Add a line to `scrapeAll.sh`:
   ```bash
   python -X utf8 scrapers/yoursite.scrape.py $ARGS
   ```

---

## Database schema

**`main.db`** — auth & audit

```sql
api_keys    id, key_hash, label, created_at, last_used, active
scrape_log  id, source, started_at, finished_at, status, items, error
```

**`namenu.db`** — menu data

```sql
cities        id, name, slug, url
restaurants   id, city_id, name, slug, url, address, phone, delivery, info
scrape_runs   id, city_id, source, scraped_at, day, date
              UNIQUE(city_id, source, date)
menu_items    id, restaurant_id, scrape_run_id, type, name, description,
              weight, price_eur, menu_price, allergens, nutrition, raw
```

---

## Data & privacy

ToMenu currently **does not collect any user data**. It only stores scraped restaurant and menu information from public sources.

A future update will introduce **opt-in** anonymous usage data collection to enable better recommendations. This will always be opt-in, clearly documented, and when self-hosting, all data stays entirely on your own machine.

---

## Roadmap

- [X] Docker image + compose setup
- [X] Multi-city support
- [X] Admin dashboard with scrape history
- [X] Allergen and price filtering
- [X] EN / SK / CS localization
- [ ] User accounts with opt-in preferences
- [ ] Personalised feed + swipe discovery
- [ ] More cities
- [ ] Additional scraper sources
- [ ] Webhook support

---

## Contributing

PRs welcome, especially for:

- **Translations** — improve or fix `SK / CS / EN` strings in [`webUI/locales/`](webUI/locales/)
- **New cities** — city portals with structured lunch menus
- **New scraper sources** — Slovak or Czech lunch aggregators
- **Parser improvements** — edge cases in the namenu scraper

Open an issue before starting anything large.

---

## License

MIT — do whatever, just don't pretend you made it.

---

*Made in Levice 🇸🇰 by [toomcis](https://toomcis.eu)*