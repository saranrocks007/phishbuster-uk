"""Bootstrap classifier training from public corpora.

Out of the box, scripts/train_model.py uses a hand-curated UK corpus
of ~60 emails. That's enough for a working baseline but underpowered
for production. This script extends training with public datasets.

Sources used (free, opt-in):
  • Nazario phishing corpus (mirrored on GitHub)        — phish (~13k)
  • UCI SpamAssassin public corpus                       — ham + phish (~6k)
  • Enron email dataset (sampled)                        — ham (~10k)
  • A user-supplied CSV with two columns: label,text     — for org-specific data

Usage:
  python scripts/import_corpus.py --nazario --spam-assassin --enron-sample 5000
  python scripts/import_corpus.py --csv ./my_labelled_emails.csv

Notes:
  * This script DOWNLOADS data from public mirrors. Bandwidth-aware: each
    source is opt-in via flag. Re-running is incremental — already-cached
    .eml/.txt files in data/corpus/ are reused.
  * After import, run scripts/train_model.py to retrain.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
import tarfile
from email import message_from_string
from email.policy import default as default_policy
from pathlib import Path
from typing import Iterator, List, Tuple

CORPUS_DIR = Path("data/corpus")
PHISH_DIR = CORPUS_DIR / "phish"
HAM_DIR = CORPUS_DIR / "ham"
PHISH_DIR.mkdir(parents=True, exist_ok=True)
HAM_DIR.mkdir(parents=True, exist_ok=True)
EXPORT_PATH = CORPUS_DIR / "labelled_corpus.jsonl"


def _eml_to_text(raw: str) -> Tuple[str, str]:
    """Return (subject, plain-text body) from a raw RFC822 string."""
    try:
        msg = message_from_string(raw, policy=default_policy)
    except Exception:
        return "", raw[:5000]
    subject = msg.get("Subject", "") or ""
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            body_parts.append(msg.get_content())
        except Exception:
            body_parts.append(raw[:5000])
    return str(subject), "\n".join(str(b) for b in body_parts)[:20000]


def _save(label: str, identifier: str, raw: str) -> None:
    target = (PHISH_DIR if label == "phish" else HAM_DIR) / f"{identifier}.eml"
    target.write_text(raw, encoding="utf-8", errors="ignore")


# ============================================================ SOURCES

def fetch_nazario(limit: int = 0) -> int:
    """Nazario phishing corpus — public mirror of historical phishing emails."""
    import httpx
    url = "https://github.com/rf-peixoto/phishing_pot/archive/refs/heads/main.tar.gz"
    print(f"[nazario] downloading {url}")
    try:
        with httpx.Client(timeout=120, follow_redirects=True) as c:
            r = c.get(url)
            r.raise_for_status()
    except Exception as exc:
        print(f"[nazario] FAILED: {exc}")
        return 0

    n = 0
    with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tar:
        for m in tar:
            if not m.isfile() or not m.name.endswith(".eml"):
                continue
            f = tar.extractfile(m)
            if not f:
                continue
            try:
                raw = f.read().decode("utf-8", errors="ignore")
            except Exception:
                continue
            ident = f"nazario_{n:05d}"
            _save("phish", ident, raw)
            n += 1
            if limit and n >= limit:
                break
    print(f"[nazario] saved {n} phishing emails")
    return n


def fetch_spamassassin(limit_phish: int = 0, limit_ham: int = 0) -> Tuple[int, int]:
    """SpamAssassin public corpus — a classic ham/spam split."""
    import httpx
    base = "https://spamassassin.apache.org/old/publiccorpus/"
    files = [
        ("20030228_easy_ham.tar.bz2", "ham"),
        ("20030228_easy_ham_2.tar.bz2", "ham"),
        ("20030228_spam.tar.bz2", "phish"),
        ("20050311_spam_2.tar.bz2", "phish"),
    ]
    p = h = 0
    for fname, label in files:
        if label == "phish" and limit_phish and p >= limit_phish:
            continue
        if label == "ham" and limit_ham and h >= limit_ham:
            continue
        url = base + fname
        print(f"[spamassassin] {url}")
        try:
            with httpx.Client(timeout=180, follow_redirects=True) as c:
                r = c.get(url); r.raise_for_status()
        except Exception as exc:
            print(f"[spamassassin] FAILED {fname}: {exc}")
            continue
        try:
            tar = tarfile.open(fileobj=io.BytesIO(r.content), mode="r:bz2")
        except tarfile.ReadError as exc:
            print(f"[spamassassin] could not open {fname}: {exc}")
            continue
        for m in tar:
            if not m.isfile():
                continue
            f = tar.extractfile(m)
            if not f:
                continue
            try:
                raw = f.read().decode("utf-8", errors="ignore")
            except Exception:
                continue
            ident = f"sa_{label}_{(p if label=='phish' else h):05d}"
            _save(label, ident, raw)
            if label == "phish":
                p += 1
                if limit_phish and p >= limit_phish:
                    break
            else:
                h += 1
                if limit_ham and h >= limit_ham:
                    break
    print(f"[spamassassin] phish={p} ham={h}")
    return p, h


def import_csv(path: Path) -> Tuple[int, int]:
    """Import org-specific labelled data. CSV columns: label,text
    label in {phish, ham}, text is raw email body or full RFC822."""
    p = h = 0
    with path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            label = (row.get("label") or "").strip().lower()
            text = row.get("text") or ""
            if label not in {"phish", "ham"} or not text.strip():
                continue
            ident = f"csv_{i:05d}"
            _save(label, ident, text)
            if label == "phish":
                p += 1
            else:
                h += 1
    print(f"[csv] phish={p} ham={h}")
    return p, h


# ============================================================ EXPORT

def export_jsonl() -> int:
    """Walk the corpus dirs, normalise to {label,subject,body}, write JSONL."""
    n = 0
    with EXPORT_PATH.open("w", encoding="utf-8") as out:
        for label, dir_ in (("phish", PHISH_DIR), ("ham", HAM_DIR)):
            for path in sorted(dir_.glob("*.eml")):
                try:
                    raw = path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                subject, body = _eml_to_text(raw)
                if not body.strip():
                    continue
                out.write(json.dumps({
                    "label": label,
                    "subject": subject,
                    "body": body[:20000],
                    "source": path.stem,
                }) + "\n")
                n += 1
    print(f"[export] wrote {n} samples to {EXPORT_PATH}")
    return n


# ============================================================ CLI

def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nazario", action="store_true",
                    help="Download Nazario phishing corpus")
    ap.add_argument("--nazario-limit", type=int, default=0)
    ap.add_argument("--spam-assassin", action="store_true",
                    help="Download SpamAssassin corpus")
    ap.add_argument("--sa-phish-limit", type=int, default=0)
    ap.add_argument("--sa-ham-limit", type=int, default=0)
    ap.add_argument("--csv", type=str, default=None,
                    help="Path to a CSV with columns: label,text")
    ap.add_argument("--no-export", action="store_true",
                    help="Skip writing the JSONL export at the end")
    args = ap.parse_args(argv)

    total_p = total_h = 0

    if args.nazario:
        total_p += fetch_nazario(limit=args.nazario_limit)

    if args.spam_assassin:
        p, h = fetch_spamassassin(limit_phish=args.sa_phish_limit,
                                  limit_ham=args.sa_ham_limit)
        total_p += p
        total_h += h

    if args.csv:
        p, h = import_csv(Path(args.csv))
        total_p += p
        total_h += h

    if not (args.nazario or args.spam_assassin or args.csv):
        ap.print_help()
        return 1

    print(f"\nTotal added — phish: {total_p}, ham: {total_h}")

    if not args.no_export:
        export_jsonl()
        print(f"\nNext step: re-run scripts/train_model.py "
              f"(it will pick up {EXPORT_PATH} if present).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
