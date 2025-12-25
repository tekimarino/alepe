#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

# Port par défaut pour Alépé (évite le conflit avec 5000)
PORT="${1:-5001}"
export PORT

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

source .venv/bin/activate
pip install -r requirements.txt
python run.py
