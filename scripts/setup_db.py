"""Initialise the PhishBuster UK database."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
from src.database import init_db


def main():
    load_dotenv()
    init_db()
    print("Database initialised.")


if __name__ == "__main__":
    main()
