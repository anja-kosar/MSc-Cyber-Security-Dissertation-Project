# ========== NAZARIO (CSV-ONLY).PY ==========
# This script scans the sanitized Nazario corpus stored as CSV files.
# It detects persuasive/cognitive-bias cues in email text (subject, body_snippet, sanitized_body).
# The script:
#   - Reads all CSV files under data/sanitized/unzipped/
#   - Builds text from subject/body/html-like columns
#   - Deobfuscates indicators like hxxp → http and [.] → . (in memory only) for better detection
#   - Strips HTML tags for text analysis
#   - Detects persuasive cues using src/cues.py
#   - Masks email addresses (PII) in subject and metadata for privacy before saving 
#   - Saves detailed JSON and CSV summaries under outputs/<timestamp>/nazario

from pathlib import Path
from datetime import datetime
import csv
import json
import re
from email.header import decode_header, make_header
from src.cues import detect_cues, summarize_counts, CUE_LEXICON

# Below sets up root paths
ROOT = Path(__file__).resolve().parents[1]
INPUT_DIR = ROOT / "data" / "sanitized" / "unzipped"
OUTPUTS = ROOT / "outputs"

# Below only process CSV files (others are ignored)
CSV_EXTS = {".csv"}

# Below are likely column names for subject, body text, and HTML content
# These are used to heuristically identify which columns to analyze
# If none are found, all columns except metadata are used as body text
# They are all lowercase for case-insensitive matching
LIKELY_SUBJECT_KEYS = {"subject", "subj", "title", "headline"}
LIKELY_BODY_KEYS = {
    "body", "text", "message", "content", "payload", "snippet",
    "description", "body_text", "email", "data", "body_snippet"
}
LIKELY_HTML_KEYS = {
    "html", "body_html", "message_html", "content_html", "sanitized_body"
}

# Below are extra regexes for heuristics
RE_ALL_CAPS = re.compile(r"\b[A-Z]{2,}\b")          # Detect words in ALL CAPS
RE_EXCLAM = re.compile(r"!+")                       # Detect exclamation marks
RE_MONEY = re.compile(r"[£$€]")                     # Detect money symbols
RE_LINK = re.compile(r"(https?://|www\.)", re.IGNORECASE)  # Detect links

# Create columns for cue category totals in CSV summary
CATEGORY_COLUMNS = [f"sum_{cat}" for cat in CUE_LEXICON.keys()]

# Below are regexes and functions for PII redaction
# Email address pattern (simple version)
# This is used to mask email addresses in subject and metadata for privacy
EMAIL_RX = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# Below redacts email addresses in a string
def redact_email_addresses(s: str) -> str:
    if not s:
        return ""
    return EMAIL_RX.sub("[redacted-email]", s)

# Below redacts email addresses in contact fields (from, to)
# These fields are in plain text, so we just mask emails for privacy
def redact_contacts(value: str) -> str:
    return redact_email_addresses(value or "")

# Below are utility functions for file and directory handling
# If a directory does not exist, it is created
def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

# Below creates a timestamped directory under a base path
# The directory is named with the current date and time
def timestamp_dir(base: Path) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = base / ts / "nazario"
    ensure_dir(out_dir)
    return out_dir

# Below saves a Python object as a JSON file with pretty formatting
# The file is written with UTF-8 encoding for broad character support
# This helps ensure the output is easily readable and correctly encoded
def save_json(path: Path, obj):
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")

# Below saves a list of dictionaries as a CSV file
# Newlines in values are sanitized to spaces to avoid breaking the CSV format
# This ensures the CSV is well-formed and easy to read
def save_csv(path: Path, rows):
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    headers = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            clean = {h: str(row.get(h, "")).replace("\n", " ").replace("\r", " ") for h in headers}
            writer.writerow(clean)

# Below decodes MIME-encoded words in email headers
# This handles encoded subjects like =?ISO-8859-1?b?...?=
# It returns a UTF-8 string for easier processing and display
# This is important for correctly interpreting email subjects
def decode_mime_words(s: str) -> str:
    try:
        return str(make_header(decode_header(s or "")))
    except Exception:
        return s or ""

# Below normalizes text for cue detection
# It lowercases and removes special characters (except spaces)
def normalize_text(s: str) -> str:
    if not s:
        return ""
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()

# Below are regexes and functions for fixing obfuscated indicators (for example hxxp, [.] etc.)
# This helps improve cue detection by converting common obfuscations back to standard forms
# This is done to improve detection of URLs and domains in the text
DEOBF_HXXP = re.compile(r"\bhxxps?://", re.IGNORECASE)
DEOBF_DOT = re.compile(r"\[(\.)\]")

def deobfuscate_iocs(s: str) -> str:
    # Convert hxxp → http and [.] → . for better detection (not saved anywhere)
    if not s:
        return ""
    s = DEOBF_HXXP.sub(lambda m: "https://" if m.group(0).lower().startswith("hxxps") else "http://", s)
    s = DEOBF_DOT.sub(".", s)
    return s

# Below are regexes and functions for stripping HTML tags from text content
# Removes <script>/<style> sections and all remaining tags
# This helps extract readable text from HTML content for analysis
RE_SCRIPTS = re.compile(r"<\s*(script|style)[^>]*>.*?<\s*/\s*\1\s*>", re.IGNORECASE | re.DOTALL)
RE_TAGS = re.compile(r"<[^>]+>")

def html_to_text(html: str) -> str:
    # Remove HTML tags and scripts/styles
    if not html:
        return ""
    html = RE_SCRIPTS.sub(" ", html)
    html = RE_TAGS.sub(" ", html)
    return re.sub(r"\s+", " ", html).strip()

# Below identifies which columns in a CSV are subject, text, and HTML
# It uses likely column names for matching (case-insensitive)
# If no text or HTML columns are found, all non-metadata columns are used as text
def pick_columns(header):
    lower = [h.strip().lower() for h in (header or [])]
    subj_cols, text_cols, html_cols = [], [], []

    for i, h in enumerate(lower):
        if h in LIKELY_SUBJECT_KEYS:
            subj_cols.append(header[i])
        if h in LIKELY_BODY_KEYS:
            text_cols.append(header[i])
        if h in LIKELY_HTML_KEYS:
            html_cols.append(header[i])

    # If no text or HTML columns found, take all except metadata
    if not text_cols and not html_cols:
        for i, h in enumerate(lower):
            if h not in {"id", "date", "from", "from_domain", "to", "timestamp"}:
                text_cols.append(header[i])
    return subj_cols, text_cols, html_cols

# Below safely gets a value from a CSV row 
# If the key is missing or the value is None, returns an empty string
def safe_get(row, key):
    val = row.get(key, "")
    return "" if val is None else str(val)

# Below builds text content from a CSV row
# It extracts metadata (subject, from, to, date) and combines body text and HTML
# HTML content is converted to plain text before combining
# Returns (meta_dict, combined_text)
# This is done to prepare the text for cue detection
def build_text_from_csv_row(row, subj_cols, text_cols, html_cols):
    meta = {}
    for k in subj_cols:
        val = safe_get(row, k)
        if val:
            meta["subject"] = decode_mime_words(val)
            break
    for k in ("from", "to", "date"):
        if k in row:
            meta[k] = safe_get(row, k)

    # Combine body text and HTML content into a single text blob
    parts = []
    for k in text_cols:
        v = safe_get(row, k)
        if v:
            parts.append(v)
    for k in html_cols:
        v = safe_get(row, k)
        if v:
            parts.append(html_to_text(v))

    text = "\n".join(parts)
    return meta, text

# Below detects cues in text and calculates extra heuristics
def detect_with_extras(text: str):
    if text is None:
        text = ""
    text = deobfuscate_iocs(text)  # Fix hxxp/[.] patterns

    # Detect cues using src/cues
    matches = detect_cues(text)
    totals = summarize_counts(matches)

    # Calculate extra heuristics
    extras = {
        "all_caps_words": len(RE_ALL_CAPS.findall(text)),
        "exclamations": len(RE_EXCLAM.findall(text)),
        "money_symbols": len(RE_MONEY.findall(text)),
        "links": len(RE_LINK.findall(text))
    }
    return totals, extras

# Below scans individual CSV files
# It tries utf-8 first, then latin-1 if that fails
# For each row, it builds text, detects cues, and collects results
# Returns a list of result dictionaries for each row
# This is done to process each CSV file and extract relevant information
def scan_csv(path: Path):
    results = []
    for enc in ("utf-8", "latin-1"):
        try:
            with path.open("r", encoding=enc, errors="ignore", newline="") as f:
                reader = csv.DictReader(f)
                header = reader.fieldnames or []
                subj_cols, text_cols, html_cols = pick_columns(header)

                for idx, row in enumerate(reader, start=1):
                    meta, raw_text = build_text_from_csv_row(row, subj_cols, text_cols, html_cols)
                    totals, extras = detect_with_extras(raw_text)

                    meta_pub = {
                        "subject": redact_email_addresses(meta.get("subject", "")),
                        "from": redact_contacts(meta.get("from", "")),
                        "to": redact_contacts(meta.get("to", "")),
                        "date": meta.get("date", "")
                    }

                    results.append({
                        "path": f"{path}#row={idx}",
                        "status": "ok",
                        "bytes": 0,
                        "meta": meta_pub,
                        "text_len": len(raw_text or ""),
                        "cues_total": totals,
                        "extras": extras
                    })
            return results
        except Exception:
            continue

    # If all encodings fail, return an error entry
    results.append({
        "path": str(path),
        "status": "error",
        "error": "Failed to read CSV with utf-8 or latin-1"
    })
    return results

# Below is the main directory scanning function
# It recursively finds all CSV files and processes them
# Returns a list of result dictionaries for all rows in all CSVs
def scan_dir(root: Path):
    rows = []
    if not root.exists():
        return rows

    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in CSV_EXTS:
            continue
        try:
            rows.extend(scan_csv(p))
        except Exception as e:
            rows.append({"path": str(p), "status": "error", "error": repr(e)})
    return rows

# Below is the main function to run the Nazario CSV scanning pipeline
# It saves results as JSON and CSV in a timestamped outputs folder
def main():
    if not INPUT_DIR.exists():
        print("Input not found:", INPUT_DIR)
        return
    run_dir = timestamp_dir(OUTPUTS)
    print("[Nazario CSV] Scanning:", INPUT_DIR)
    rows = scan_dir(INPUT_DIR)
    save_json(run_dir / "nazario_scan.json", rows)

    # Build a flat CSV summary
    flat = []
    for r in rows:
        if r.get("status") != "ok":
            flat.append({
                "path": r.get("path", ""),
                "bytes": 0,
                "text_len": 0,
                "subject": "",
                "from": "",
                "date": "",
                **{col: 0 for col in CATEGORY_COLUMNS},
                "all_caps_words": 0,
                "exclamations": 0,
                "money_symbols": 0,
                "links": 0,
                "error": r.get("error", "")
            })
            continue

        meta = r.get("meta", {}) or {}
        totals = r.get("cues_total", {}) or {}
        extras = r.get("extras", {}) or {}

        row = {
            "path": r.get("path", ""),
            "bytes": r.get("bytes", 0),
            "text_len": r.get("text_len", 0),
            "subject": meta.get("subject", ""),
            "from": meta.get("from", ""),
            "date": meta.get("date", "")
        }

        # Add cue category totals
        for col in CATEGORY_COLUMNS:
            cat = col.replace("sum_", "")
            row[col] = totals.get(cat, 0)

        # Add heuristic counts
        row["all_caps_words"] = extras.get("all_caps_words", 0)
        row["exclamations"] = extras.get("exclamations", 0)
        row["money_symbols"] = extras.get("money_symbols", 0)
        row["links"] = extras.get("links", 0)

        flat.append(row)

    # Save CSV summary
    save_csv(run_dir / "nazario_scan_summary.csv", flat)
    print("[Nazario CSV] Done →", run_dir)
    
if __name__ == "__main__":
    main()
