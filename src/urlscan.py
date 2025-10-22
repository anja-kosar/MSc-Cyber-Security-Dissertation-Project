# ========== URLSCAN.PY ==========
# This script samples URLs from PhishTank (data/urls/phishtank.csv),
# The URLs are scanned (fetched) and checked for cues using the same
# cue detection as the other tools (src/cues.py).
# The results are saved in a timestamped folder under outputs/.
# The outputs are:
#   outputs/<ts>/urlscan/summary.csv   ← redacted (no raw URLs)
#   outputs/<ts>/urlscan/summary.json  ← redacted (no raw URLs)
# Sampling is default 50 URLs, random, deduped by apex domain to avoid many from one site.
# Fetching can be: get | head | off (offline, URL only).
# For the purpose of this project, GET is preferred to get page text. 
# This request reads the HTML and extracts title + link texts (up to 200 links). 
# It does not execute any executable code (no JS, no browser).
# Use VPN or proxy if you want to hide your IP.

import argparse
import csv
import json
import random
import re
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

# HTTP + HTML parsing
# BeautifulSoup is used but is optional (if missing, we skip HTML parsing)
import requests
try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None 

# Below is the cue detection functions and lexicon
from src.cues import detect_cues, summarize_counts, CUE_LEXICON

# Below are path constants
ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = ROOT / "outputs"
PHISHTANK = ROOT / "data" / "urls" / "phishtank.csv"

DEFAULT_LIMIT  = 50         # how many URLs to scan
DEFAULT_RANDOM = True       # random sample by default
DEFAULT_SEED   = 2025       # reproducible sampling
DEFAULT_DEDUPE = "apex"     # 'apex' or 'none'
DEFAULT_FETCH  = "get"      # 'get' | 'head' | 'off', GET preferred for cues and this project
TIMEOUT        = 8          # HTTP timeout (seconds) to avoid hanging requests
MAX_LINKS      = 200        # cap link-texts scanned per page (to limit processing time)
USER_AGENT     = "msc-urlscan/1.0" # User-Agent header for requests

CATEGORY_COLUMNS = [f"sum_{cat}" for cat in CUE_LEXICON.keys()]

# Below is a list of simple suspicious keywords often seen in phishing URLs
# This is not exhaustive, and can be modified as needed
SUSPICIOUS = [
    "login","verify","update","secure","account","wallet","bank","password","billing","invoice",
    "appeal","case","support","help","gift","prize","bonus","urgent","suspend","limited","verify-now"
]

# Below creates the outputs directory if it doesn't exist
def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

# Below creates a timestamped run directory under outputs/
def ts_dir(base: Path) -> Path:
    d = base / datetime.now().strftime("%Y%m%d_%H%M%S") / "urlscan"
    ensure_dir(d)
    return d

# Below are functions for URL processing and feature extraction
# For example, getting the apex domain, example.co.uk to co.uk
def apex_from_host(host: str) -> str:
    parts = (host or "").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "").lower()

# Below checks if the host is an IP address (IPv4 or IPv6)
# This is done to flag URLs that use IPs instead of domain names
def is_ip_host(host: str) -> bool:
    if not host:
        return False
    if ":" in host:
        return True
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))

# Below normalizes text for cue detection
# It lowercases and removes non-alphanumeric characters (except spaces)
def normalize_text(s: str) -> str:
    s = (s or "").lower()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()

# Below detects cues in both raw and normalized text, merges counts, and adds heuristics
# Returns a dict of total counts per category
def cue_totals(text: str) -> dict:
    raw = detect_cues(text or "")
    norm = detect_cues(normalize_text(text or ""))
    merged = {}
    cats = set(list(raw.keys()) + list(norm.keys()))
    for cat in cats:
        merged[cat] = {}
        for d in (raw.get(cat, {}), norm.get(cat, {})):
            for phrase, cnt in (d or {}).items():
                merged[cat][phrase] = merged[cat].get(phrase, 0) + cnt
    return summarize_counts(merged)

# Below normalizes a URL to ensure it has a scheme for urlparse to work consistently
def normalise_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return ""
    if not u.lower().startswith(("http://","https://","www.")):
        u = "http://" + u
    return u

# Below reads URLs from a PhishTank CSV file with a 'url' column (case-insensitive)
def read_urls_from_phishtank(path: Path) -> list[str]:
    if not path.exists():
        print("Input not found:", path)
        return []
    out = []
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        rdr = csv.DictReader(f)
        url_field = None
        if rdr.fieldnames:
            for fn in rdr.fieldnames:
                if (fn or "").strip().lower() == "url":
                    url_field = fn
                    break
        if not url_field:
            print("Couldn't find a 'url' column in", path)
            return []
        for row in rdr:
            u = normalise_url(row.get(url_field, ""))
            if u:
                out.append(u)
    return out

# Below deduplicates URLs by apex domain if mode is 'apex', otherwise returns as is
# This is done to avoid many URLs from the same site skewing results
def dedupe_urls(urls: list[str], mode: str) -> list[str]:
    if mode.lower() != "apex":
        return urls
    seen = set()
    out = []
    for u in urls:
        ap = apex_from_host(urlparse(u).hostname or "")
        if ap in seen:
            continue
        seen.add(ap)
        out.append(u)
    return out

# Below samples up to 'limit' URLs, either randomly (with seed) or first N
# This is done to control the number of URLs processed in one run
def sample_urls(urls: list[str], limit: int, random_pick: bool, seed: int) -> list[str]:
    if limit and limit < len(urls):
        if random_pick:
            random.seed(seed)
            random.shuffle(urls)
        return urls[:limit]
    return urls

# Below is a basic URL feature extraction for heuristics
# These features are often useful in phishing detection
def url_heuristics(u: str) -> dict:
    p = urlparse(u)
    host = (p.hostname or "").lower()
    pathq = (p.path or "") + ("?" + p.query if p.query else "")
    uses_https = (p.scheme.lower() == "https")
    labels = [lbl for lbl in host.split(".") if lbl]
    subdomain_count = max(0, len(labels) - 2)
    hyphen_count = host.count("-")
    has_punycode = any(lbl.startswith("xn--") for lbl in labels)
    at_symbol = "@" in u
    digits = sum(ch.isdigit() for ch in host)
    letters_digits = sum(ch.isdigit() or ch.isalpha() for ch in host) or 1
    digit_ratio_host = round(digits / letters_digits, 3)
    sus_host = sum(1 for kw in SUSPICIOUS if kw in host)
    sus_path = sum(1 for kw in SUSPICIOUS if kw in pathq)
    return {
        "host": host,
        "apex": apex_from_host(host),
        "uses_https": int(uses_https),
        "has_ip_host": int(is_ip_host(host)),
        "has_punycode": int(has_punycode),
        "at_symbol": int(at_symbol),
        "subdomain_count": subdomain_count,
        "hyphen_count": hyphen_count,
        "digit_ratio_host": digit_ratio_host,
        "url_length": len(u),
        "path_length": len(p.path or ""),
        "query_length": len(p.query or ""),
        "sus_kw_host": sus_host,
        "sus_kw_path": sus_path,
    }

# Below fetches a URL based on mode (get, head, off) and extracts text for cues
# It returns (text_for_detection, fetch_metadata)
def fetch_text_for_cues(u: str, mode: str) -> tuple[str, dict]:
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml;q=0.9"}

    if mode in ("off", "0", "false"):
        return "", {"status": "", "final_url": "", "redirects": 0, "error": "skipped (offline)"}

    try:
        if mode == "head":
            r = requests.head(u, headers=headers, timeout=TIMEOUT, allow_redirects=True)
            return "", {"status": r.status_code, "final_url": r.url, "redirects": len(r.history), "error": ""}
        r = requests.get(u, headers=headers, timeout=TIMEOUT, allow_redirects=True)
    except Exception as e:
        return "", {"status": "", "final_url": "", "redirects": 0, "error": repr(e)}

    final_url = r.url
    redirects = len(r.history)
    ctype = (r.headers.get("Content-Type") or "").lower()
    meta = {"status": r.status_code, "final_url": final_url, "redirects": redirects, "error": ""}

    if "text/html" not in ctype or BeautifulSoup is None:
        # If not HTML or BS4 unavailable, don't parse
        return "", meta

    # Parse HTML and collect title + link texts
    try:
        soup = BeautifulSoup(r.text, "html.parser")
        title = (soup.title.string if soup.title and soup.title.string else "") or ""
        parts = [title, final_url]  # include final_url string as a signal if it contains cues
        link_texts = []
        for a in soup.find_all("a"):
            t = (a.get_text(strip=True) or "")[:200]
            if t:
                link_texts.append(t)
            if len(link_texts) >= MAX_LINKS:
                break
        parts.extend(link_texts)
        text = " \n ".join([p for p in parts if p])
        return text, meta
    except Exception:
        return "", meta

# Below redacts a URL for output summaries
# It keeps only the apex domain and a hint of the first path segment
def mask_url_for_output(u: str) -> str:
    try:
        p = urlparse(u)
        apx = apex_from_host(p.hostname or "")
        path = (p.path or "").strip()
        if path and path != "/":
            # keep only the first segment as a hint
            seg = path.split("/")
            first = ("/" + seg[1]) if len(seg) > 1 and seg[1] else "/"
        else:
            first = "/"
        return f"{apx}:{first}"
    except Exception:
        # Fallback to just apex
        try:
            return apex_from_host(urlparse(u).hostname or "")
        except Exception:
            return "[redacted]"

# Below is the main function to run the URL scanning and cue detection pipeline
# It saves results as JSON and CSV in a timestamped outputs folder
# It parses command-line options for sampling and fetching
# The outputs are redacted to avoid exposing raw URLs
def main():
    ap = argparse.ArgumentParser(prog="urlscan", description="No-API URL checker (phishtank.csv only, redacted outputs)")
    ap.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="max URLs to scan (default: 50)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--random", action="store_true", help="random sample (default)")
    mode.add_argument("--first",  action="store_true", help="take first N instead of random")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED, help="random seed (default: 2025)")
    ap.add_argument("--dedupe", choices=["apex","none"], default=DEFAULT_DEDUPE, help="dedupe mode (default: apex)")
    ap.add_argument("--fetch",  choices=["get","head","off"], default=DEFAULT_FETCH, help="fetch mode (default: get)")
    args = ap.parse_args()

    random_pick = DEFAULT_RANDOM if (not args.random and not args.first) else args.random

    # Load URL list
    if not PHISHTANK.exists():
        print("Expected:", PHISHTANK, "\nPlease place your PhishTank CSV there (must include a 'url' column).")
        return

    urls = read_urls_from_phishtank(PHISHTANK)
    if not urls:
        print("No URLs found in", PHISHTANK)
        return

    # Dedupe and sample
    urls = dedupe_urls(urls, args.dedupe)
    urls = sample_urls(urls, args.limit, random_pick, args.seed)

    # Prepare output folder
    run = ts_dir(OUTPUTS)

    # Save exact URLs used (full, non-redacted)
    with (run / "urls_used.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        for u in urls:
            w.writerow([u])

    print(f"[URLScan] {args.fetch.upper()} | {len(urls)} URLs | dedupe={args.dedupe} | "
          f"{'random' if random_pick else 'first'} | seed={args.seed} | timeout={TIMEOUT}s | links≤{MAX_LINKS}")

    # Process each URL
    rows = []
    for i, u in enumerate(urls, 1):
        print(f"  [{i}/{len(urls)}] {u}")
        h = url_heuristics(u)
        text, meta = fetch_text_for_cues(u, args.fetch)

        # If no page text, still cue-check the URL string itself
        text_source = text if text else u
        totals = cue_totals(text_source)

        # Redact URLs for output. Keep full URLs only in urls_used.csv
        url_red   = mask_url_for_output(u)
        final_red = mask_url_for_output(meta.get("final_url", "")) if meta.get("final_url") else ""

        row = {
            "n": i,
            "url_masked": url_red,               # redacted
            "final_url_masked": final_red,       # redacted
            "status": meta.get("status",""),
            "redirects": meta.get("redirects",0),
            "error": meta.get("error",""),
            **h
        }
        for col in CATEGORY_COLUMNS:
            cat = col.replace("sum_", "")
            row[col] = totals.get(cat, 0)
        rows.append(row)

    # Write CSV summary (redacted)
    headers = [
        "n","url_masked","final_url_masked","status","redirects","error",
        "host","apex","uses_https","has_ip_host","has_punycode","at_symbol",
        "subdomain_count","hyphen_count","digit_ratio_host","url_length","path_length","query_length",
        "sus_kw_host","sus_kw_path",
        *CATEGORY_COLUMNS
    ]
    with (run / "summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        w.writerows(rows)

    # Write JSON summary (redacted)
    (run / "summary.json").write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")

    print("[URLScan] Done →", run)

if __name__ == "__main__":
    main()
    