#!/bin/bash
echo "Starting ToMenu on port ${PORT:-8000}"
# ensure data dir and both DB files exist
mkdir -p /app/data
touch /app/data/main.db
touch /app/data/namenu.db
# create admin key and capture output
KEY_OUTPUT=$(python main.py --add-key "admin")
echo "$KEY_OUTPUT"
# run scraper immediately on startup so DB isn't empty on first boot
bash scrapeAll.sh
# write the cron job
echo "0 6,12,18,0 * * * cd /app && bash scrapeAll.sh >> /var/log/scraper.log 2>&1" > /etc/cron.d/scraper
chmod 0644 /etc/cron.d/scraper
crontab /etc/cron.d/scraper
# start cron in background
cron
# reprint the key right before uvicorn so it's easy to find
echo ""
echo "=============================="
echo " ToMenu ready"
echo "=============================="
echo "$KEY_OUTPUT"
echo "=============================="
echo ""
# start API in foreground — keeps the container alive
uvicorn api:app --host 0.0.0.0 --port ${PORT:-8000}