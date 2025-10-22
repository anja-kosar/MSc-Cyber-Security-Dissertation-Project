# ========== src/nazario_census.py ==========
# This file is designed to analyze a corpus of Nazario phishing emails 
# stored as CSV files under data/sanitized/unzipped/.
# It deduplicates emails based on a simple signature and estimates the number 
# of unique phishing emails per year from 2005 to 2024.
# It outputs tidy CSV and JSON summaries to a timestamped folder under outputs/nazario_census/.
# It marks rows as "email-like" if they have a subject or any body text.
# It uses a simple heuristic to guess the year of each email from the 'date' field or filename.
# It is designed to be run as a script or module: python -m src.nazario_census.py.

from pathlib import Path
import csv
import re
import hashlib
from collections import defaultdict, Counter
from datetime import datetime
import json
import sys


# Below sets up root paths and input/output directories
ROOT = Path(__file__).resolve().parents[1]
INPUT_DIR = ROOT / "data" / "sanitized" / "unzipped"
OUTPUTS = ROOT / "outputs"

# Below defines the valid year range for extraction and guessing
# Only years within [YEAR_MIN, YEAR_MAX] are accepted
# This helps avoid spurious years from random text as the Nazario dataset runs from 2005 to 2024
YEAR_MIN = 2005
YEAR_MAX = 2024

# Below increases the CSV field size limit to handle large fields
# This is important for rows with large HTML bodies, which in this case (Nazario dataset) can be very large.
def _bump_csv_field_limit():
    max_int = sys.maxsize
    while True:
        try:
            csv.field_size_limit(max_int)
            break
        except OverflowError:
            max_int = int(max_int / 10)

_bump_csv_field_limit()

# Below is the minimum content length for hashing
# If normalized body text is shorter than this, treat as "empty body" for hashing.
MIN_CONTENT_CHARS = 5

# Below is the maximum number of example subjects to save per signature
# This keeps memory usage reasonable while still providing useful examples.
MAX_EXAMPLES_PER_SIG = 3

# Below is the maximum number of top duplicate clusters to save
# This keeps the output manageable while highlighting the largest duplicate groups.
TOP_DUP_CLUSTERS = 50

# Below compiles regexes for HTML stripping and year extraction
# Remove <script> and <style> blocks entirely
# This is important to avoid spurious text from scripts/styles.
RE_SCRIPTS = re.compile(
    r"<\s*(script|style)[^>]*>.*?<\s*/\s*\1\s*>",
    re.IGNORECASE | re.DOTALL
)
# Remove all other HTML tags
RE_TAGS = re.compile(r"<[^>]+>")

# Below converts HTML to plain text by stripping tags and collapsing whitespace
# If input is empty or None, returns empty string.
def html_to_text(html: str) -> str:
    if not html:
        return ""
    html = RE_SCRIPTS.sub(" ", html)
    html = RE_TAGS.sub(" ", html)
    return re.sub(r"\s+", " ", html).strip()

# below normalizes text for hashing and cue detection
# It lowercases, keeps only a–z/0–9, and collapses whitespace
# This helps standardize text for more reliable matching.
def normalize_text(s: str) -> str:
    s = (s or "").lower()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()

# Below compiles a regex to find all-caps words (for heuristics)
# This is used to count the number of all-caps words in the text.
def normalize_subject(subj: str) -> str:
    s = (subj or "").strip().lower()
    s = re.sub(r"^(re|fw|fwd)\s*:\s*", "", s)
    return re.sub(r"\s+", " ", s)

# Below is a regex to find likely words in ALL CAPS
# This is used for heuristic counting of all-caps words.
LIKELY_SUBJECT_KEYS = ["subject", "subj", "title", "headline"]
LIKELY_HTML_KEYS    = ["sanitized_body", "body_html", "message_html", "content_html"]
LIKELY_BODY_KEYS    = ["body_snippet","body","text","message","content","payload",
                       "description","body_text","email","data"]

# Below returns a safe string from a dict row, defaulting to "" if missing or None
def safe_get(row, key):
    # Always return a string
    v = row.get(key, "")
    return "" if v is None else str(v)

def first_present(row, keys):
    # Return the first non-empty field among candidate keys
    for k in keys:
        v = safe_get(row, k)
        if v.strip():
            return v
    return ""

# Below sets valid minimum and maximum years for extraction
# This helps avoid spurious years from random text.
YEAR_RX = re.compile(r"\b(19|20)\d{2}\b")

def _valid_year(y: str) -> bool:
    if not y or not y.isdigit() or len(y) != 4:
        return False
    yi = int(y)
    return YEAR_MIN <= yi <= YEAR_MAX

def extract_year_from_text(s: str) -> str:
    if not s:
        return ""
    m = YEAR_RX.search(s)
    if not m:
        return ""
    y = m.group(0)
    return y if _valid_year(y) else ""

def guess_year_with_audit(row, filename: str, audit: dict) -> str:
    # Try 'date' first. If valid then use it.
    # If 'date' contains an out-of-range year then count audit and fall back to filename.
    # If filename also fails then return unknown.
    raw_date = safe_get(row, "date")
    y_date = extract_year_from_text(raw_date)
    if _valid_year(y_date):
        audit["date_valid"] += 1
        return y_date
    else:
        # Below handle out-of-range or missing date year
        if raw_date and YEAR_RX.search(raw_date) and not _valid_year(YEAR_RX.search(raw_date).group(0)):
            audit["date_out_of_range"] += 1
        # Try filename
        y_file = extract_year_from_text(filename)
        if _valid_year(y_file):
            audit["fallback_file"] += 1
            return y_file
        # Unknown
        audit["unknown"] += 1
        return ""

# Below determines if a row looks like an email
# It checks for presence of a subject or any body content
# This helps filter out non-email rows in the dataset.
def is_email_like(row) -> bool:
    subj = first_present(row, LIKELY_SUBJECT_KEYS)
    body_any = first_present(row, LIKELY_HTML_KEYS + LIKELY_BODY_KEYS)
    return bool((subj and subj.strip()) or (body_any and body_any.strip()))

# Below builds a deduplication signature for an email-like row
# The signature is a tuple of (from_domain, normalized_subject, content_hash)   
# from_domain is lowercased and stripped of whitespace.
def build_signature(row) -> tuple:
    # Subject (normalized)
    subj = first_present(row, LIKELY_SUBJECT_KEYS)
    subj_norm = normalize_subject(subj)

    # From-domain (lowercased)
    from_domain = safe_get(row, "from_domain").lower().strip()

    # Body content: prefer HTML stripped, else plain text
    body_html = first_present(row, LIKELY_HTML_KEYS)
    body_text = first_present(row, LIKELY_BODY_KEYS)
    content = html_to_text(body_html) if body_html.strip() else body_text

    # Normalized content for hashing
    cont_norm = normalize_text(content)
    if len(cont_norm) < MIN_CONTENT_CHARS:
        content_sig = ""
    else:
        content_sig = hashlib.sha1(cont_norm.encode("utf-8")).hexdigest()

    return (from_domain, subj_norm, content_sig)

# Below ensures a directory exists, creating it if necessary
def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

# Below creates a timestamped directory under the given base path
def ts_dir(base: Path) -> Path:
    return base / datetime.now().strftime("%Y%m%d_%H%M%S")

# Below is the main function to run the Nazario census analysis
# It scans all CSV files under INPUT_DIR, processes them, and writes outputs.
# The outputs include per-year counts, per-file summaries, top duplicate clusters, and overall JSON.
def main():
    # Make sure input folder exists
    if not INPUT_DIR.exists():
        print("Input not found:", INPUT_DIR)
        return

    # Find all CSV files recursively
    csv_files = sorted([p for p in INPUT_DIR.rglob("*.csv") if p.is_file()])
    if not csv_files:
        print("No CSV files found under:", INPUT_DIR)
        return

    # Global counters
    total_rows_all = 0
    email_like_all = 0

    # Per-file summary
    file_counts = []

    # Global dedupe maps
    sig_counter = Counter()            # this is signature -> count
    sig_examples = defaultdict(list)   # this is signature -> list of (filename, subject)
    sig_first_year = {}                # this is signature -> earliest year seen

    # Per-year tallies
    per_year_raw = Counter()           # counts of email-like rows per year
    per_year_unique = Counter()        # counts of unique signatures per year

    # Year audit counters
    year_audit = {
        "date_valid": 0,        # date header produced a valid year in [2005, 2024]
        "fallback_file": 0,     # used filename year because date was missing/invalid/out-of-range
        "unknown": 0,           # no valid year found anywhere
        "date_out_of_range": 0  # saw a year in the date field, but it was outside [2005, 2024]
    }

    # Process each CSV
    for path in csv_files:
        rows_in_file = 0
        email_like_in_file = 0
        seen_sigs_this_file = set()

        with path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
            rdr = csv.DictReader(f)
            for row in rdr:
                rows_in_file += 1
                total_rows_all += 1

                # Skip rows that don't look like emails
                if not is_email_like(row):
                    continue

                email_like_in_file += 1
                email_like_all += 1

                # Build signature and count it
                sig = build_signature(row)
                sig_counter[sig] += 1

                # Save up to a few example subjects for this signature
                if len(sig_examples[sig]) < MAX_EXAMPLES_PER_SIG:
                    subj = first_present(row, LIKELY_SUBJECT_KEYS)
                    sig_examples[sig].append((path.name, (subj or "")[:200]))

                # Year guess (with hard limits + audit)
                yr = guess_year_with_audit(row, path.name, year_audit)
                if yr:
                    per_year_raw[yr] += 1
                    # Keep earliest observed year for this signature
                    if sig not in sig_first_year or yr < sig_first_year[sig]:
                        sig_first_year[sig] = yr

                # Track distinct signatures found in this file
                if sig not in seen_sigs_this_file:
                    seen_sigs_this_file.add(sig)

        # Record per-file summary
        file_counts.append({
            "file": str(path),
            "rows_total": rows_in_file,
            "email_like_rows": email_like_in_file,
            "unique_signatures_in_file": len(seen_sigs_this_file),
        })

    # Global unique + duplicates
    unique_emails = len(sig_counter)
    duplicates = max(0, email_like_all - unique_emails)
    dup_rate = (duplicates / email_like_all * 100.0) if email_like_all else 0.0

    # Per-year UNIQUE counts (by earliest year per signature)
    for sig, yr in sig_first_year.items():
        if yr:
            per_year_unique[yr] += 1

    # Below prepares output directory and writes outputs
    # Timestamped output folder
    outdir = ts_dir(OUTPUTS) / "nazario_census"
    ensure_dir(outdir)

    # Below writes per-year counts CSV
    # Columns: year, email_like_rows, unique_emails, estimated_duplicates
    years_sorted = sorted(set(list(per_year_raw.keys()) + list(per_year_unique.keys())))
    with (outdir / "per_year_counts.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["year", "email_like_rows", "unique_emails", "estimated_duplicates"])
        for y in years_sorted:
            raw_y = per_year_raw.get(y, 0)
            uniq_y = per_year_unique.get(y, 0)
            dup_y = max(0, raw_y - uniq_y)
            w.writerow([y, raw_y, uniq_y, dup_y])

    # Below writes per-file summary CSV
    # Columns: file, rows_total, email_like_rows, unique_signatures_in_file
    with (outdir / "files_summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["file","rows_total","email_like_rows","unique_signatures_in_file"])
        w.writeheader()
        for rec in file_counts:
            w.writerow(rec)

    # Below writes top duplicate clusters CSV
    # Columns: count, from_domain, normalized_subject, content_hash_prefix, earliest_year, examples
    # Only includes clusters with at least 2 emails, capped at TOP_DUP_CLUSTERS
    # This is useful to identify the largest duplicate groups in the dataset.
    top_dups = [item for item in sig_counter.most_common(TOP_DUP_CLUSTERS) if item[1] >= 2]
    with (outdir / "duplicates_top.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["count","from_domain","normalized_subject","content_hash_prefix","earliest_year","examples"])
        for (sig, count) in top_dups:
            from_domain, subj_norm, content_sig = sig
            y = sig_first_year.get(sig, "")
            examples = " | ".join([f"{fn} :: {sj}" for (fn, sj) in sig_examples[sig]])
            w.writerow([count, from_domain or "-", subj_norm or "-", (content_sig or "")[:10], y, examples])

    # Below writes a sample of unique emails CSV
    # This includes up to 200 unique signatures with examples
    # This is done to provide a manageable sample of unique emails for review.
    with (outdir / "unique_examples.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["from_domain","normalized_subject","content_hash_prefix","earliest_year","example_subjects"])
        count_written = 0
        for sig in sig_counter:
            if count_written >= 200:
                break
            from_domain, subj_norm, content_sig = sig
            y = sig_first_year.get(sig, "")
            examples = " | ".join([sj for (_, sj) in sig_examples[sig]])
            w.writerow([from_domain or "-", subj_norm or "-", (content_sig or "")[:10], y, examples])
            count_written += 1

    # Below writes overall summary JSON
    # This includes global stats, per-year counts, year audit, and input/output paths
    # This provides a comprehensive overview of the analysis results.
    overview = {
        "input_dir": str(INPUT_DIR),
        "files_scanned": len(csv_files),
        "rows_total": total_rows_all,
        "email_like_rows": email_like_all,
        "unique_emails": unique_emails,
        "estimated_duplicates": duplicates,
        "duplicate_rate_percent": round(dup_rate, 2),
        "years": years_sorted,
        "per_year_raw": dict(per_year_raw),
        "per_year_unique": dict(per_year_unique),
        "year_window": {"min": YEAR_MIN, "max": YEAR_MAX},
        "year_audit": year_audit,
        "output_dir": str(outdir),
    }
    (outdir / "overall.json").write_text(json.dumps(overview, indent=2), encoding="utf-8")

    # Below prints summary to console
    # This is useful for quick feedback when running the script.
    print("\n=== Nazario Census (All CSVs) ===")
    print("Files scanned:           ", len(csv_files))
    print("Total rows:              ", total_rows_all)
    print("Email-like rows:         ", email_like_all)
    print("Unique emails (deduped): ", unique_emails)
    print("Estimated duplicates:    ", f"{duplicates} ({dup_rate:.2f}% of email-like)")
    print("Per-year counts written to:", outdir / "per_year_counts.csv")
    print("Overall JSON:", outdir / "overall.json")
    print("Done →", outdir)

# Below runs main() if executed as a script
if __name__ == "__main__":
    main()
