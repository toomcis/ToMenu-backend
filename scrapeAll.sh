#!/bin/bash
# scrape_all.sh — runs all scrapers in sequence
# Usage:
#   ./scrape_all.sh           # scrape full week for all sources
#   ./scrape_all.sh --today   # scrape today only
#   ./scrape_all.sh --day pondelok

set -e
cd "$(dirname "$0")"

ARGS="$@"
echo "=============================="
echo " namenu+ scrape_all"
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