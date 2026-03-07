#!/bin/bash
# scrapeAll.sh — runs all scrapers in sequence
# Usage:
#   ./scrapeAll.sh           # scrape full week for all sources
#   ./scrapeAll.sh --today   # scrape today only
#   ./scrapeAll.sh --day pondelok
set -e
cd "$(dirname "$0")"
ARGS="$@"
echo "=============================="
echo " ToMenu scrapeAll"
echo " $(date '+%Y-%m-%d %H:%M:%S')"
echo " args: ${ARGS:-'(full week)'}"
echo "=============================="
python -X utf8 scrapers/namenu.scrape.py $ARGS
# ── add more scrapers here as you build them ──
# python -X utf8 scrapers/someother.scrape.py $ARGS
echo ""
echo "=============================="
echo " all scrapers done"
echo "=============================="