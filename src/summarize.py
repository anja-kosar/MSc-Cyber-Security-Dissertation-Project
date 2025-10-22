# ========== SUMMARIZE.PY ==========
# This script finds the latest outputs from the three tools:
#   - images:   outputs/<ts>/images_ocr_summary.csv
#   - nazario:  outputs/<ts>/nazario/nazario_scan_summary.csv
#   - urlscan:  outputs/<ts>/urlscan/summary.csv
# It reads those CSVs, sums the cue totals per category (sum_<category>),
# also sums simple extras (ALL_CAPS, exclamations, money symbols, links),
# and writes two combined files:
#   - outputs/<now>/summary/combined_summary.csv
#   - outputs/<now>/summary/combined_summary.json
# If a source is missing, it is skipped.

from pathlib import Path
from datetime import datetime
import csv
import json

# Below imports CUE_LEXICON to get the list of categories
from src.cues import CUE_LEXICON

# Below are constants for input/output folders
ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = ROOT / "outputs"

# Below builds the list of category columns (sum_<category>)
# based on the keys in CUE_LEXICON
# For example urgency, authority etc.
CAT_COLS = [f"sum_{name}" for name in CUE_LEXICON.keys()]

# Below are the extra columns we want to sum if present
EXTRA_COLS = ["all_caps_words", "exclamations", "money_symbols", "links"]

# Below creates a directory if it doesn't exist
def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

# below creates a timestamped directory under a base path
def ts_dir(base: Path) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    d = base / ts / "summary"
    ensure_dir(d)
    return d

# Below finds the latest file matching a pattern under outputs/
# It finds the most recent by the parent timestamp folder name
# If no matches, returns None
def latest_file(pattern: str) -> Path | None:
    matches = list(OUTPUTS.glob(pattern))
    if not matches:
        return None

# Below is a helper to get the timestamp folder of a path
    def ts_parent(p: Path) -> Path:
        # If the immediate parent is a named subfolder (nazario/urlscan), step one more up
        if p.parent.name in ("nazario", "urlscan"):
            return p.parent.parent
        return p.parent

    # Sort by the timestamp string (YYYYMMDD_HHMMSS sorting works lexically)
    matches.sort(key=lambda p: ts_parent(p).name)
    return matches[-1]

# Below safely converts int-like strings such as "3", "3.0", or "3.00" into int
# Returns 0 on failure (None, empty, non-numeric)
# This is used to sum up CSV columns that may be missing or malformed
def safe_int_like(x):
    try:
        if x is None:
            return 0
        s = str(x).strip()
        if not s:
            return 0
        return int(float(s))
    except Exception:
        return 0

# Below sums one CSV file for categories and extras
# It also counts how many rows and how many had an "error" message
def sum_csv_file(path: Path, source_name: str) -> dict:
    totals = {c: 0 for c in CAT_COLS}
    extras = {e: 0 for e in EXTRA_COLS}
    n_rows = 0
    n_errors = 0
    headers = []

    with path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        rdr = csv.DictReader(f)
        headers = [h.strip() for h in (rdr.fieldnames or [])]

        for row in rdr:
            n_rows += 1

            # If there's an "error" column and it contains any text, count it
            err_text = (row.get("error") or "").strip()
            if err_text:
                n_errors += 1

            # Add up category columns
            for c in CAT_COLS:
                if c in row:
                    totals[c] += safe_int_like(row.get(c))

            # Add up extras only if present in this CSV
            for e in EXTRA_COLS:
                if e in headers:
                    extras[e] += safe_int_like(row.get(e))

    # Below extract the timestamp from the path
    # If the parent is nazario/urlscan, go one level up
    if path.parent.name in ("nazario", "urlscan"):
        ts = path.parent.parent.name
    else:
        ts = path.parent.name

    return {
        "source": source_name,   # "images", "nazario", or "urlscan"
        "file": str(path),       # which file is read
        "timestamp": ts,         # run timestamp folder
        "n_items": n_rows,       # number of rows processed
        "errors": n_errors,      # how many rows had error text
        "totals": totals,        # dict of summed sum_<category> values
        "extras": extras,        # dict of summed extras
    }

# Below writes a flat CSV with one row per source + a TOTAL row
# The columns are: source, timestamp, n_items, errors, <categories>, <extras>
# This is done to create the combined_summary.csv file easily readable in Excel
def write_csv(path: Path, rows: list[dict]):
    headers = ["source", "timestamp", "n_items", "errors", *CAT_COLS, *EXTRA_COLS]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in rows:
            line = {
                "source": r["source"],
                "timestamp": r["timestamp"],
                "n_items": r["n_items"],
                "errors": r["errors"],
            }
            for c in CAT_COLS:
                line[c] = r["totals"].get(c, 0)
            for e in EXTRA_COLS:
                line[e] = r["extras"].get(e, 0)
            w.writerow(line)

# Below writes a JSON file with pretty formatting
def write_json(path: Path, obj): 
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")

# Below finds the newest timestamped file in outputs for each tool (if any exist)
def main():
    p_images  = latest_file("*/images_ocr_summary.csv")
    p_nazario = latest_file("*/nazario/nazario_scan_summary.csv")
    p_urlscan = latest_file("*/urlscan/summary.csv")

    # Below collects the summaries from each source if present
    sources = []
    if p_images and p_images.exists():
        sources.append(sum_csv_file(p_images, "images"))
    if p_nazario and p_nazario.exists():
        sources.append(sum_csv_file(p_nazario, "nazario"))
    if p_urlscan and p_urlscan.exists():
        sources.append(sum_csv_file(p_urlscan, "urlscan"))

    # If nothing is present, tell the user what to run
    if not sources:
        print("No recent outputs found. Run one of: images / nazario / urlscan first.")
        return

    # Print a small status to explain what was found
    print("[Summary] Sources included:", ", ".join(s["source"] for s in sources))

    # Build overall totals (across all sources)
    overall_totals = {c: 0 for c in CAT_COLS}
    overall_extras = {e: 0 for e in EXTRA_COLS}
    overall_n = 0
    overall_err = 0

    for s in sources:
        overall_n += s["n_items"]
        overall_err += s["errors"]
        for c in CAT_COLS:
            overall_totals[c] += s["totals"].get(c, 0)
        for e in EXTRA_COLS:
            overall_extras[e] += s["extras"].get(e, 0)

    # Prepare the output folder for this combine run
    outdir = ts_dir(OUTPUTS)

    # Write a CSV with each source + a TOTAL row
    rows_for_csv = sources + [{
        "source": "TOTAL",
        "file": "",
        "timestamp": "—",
        "n_items": overall_n,
        "errors": overall_err,
        "totals": overall_totals,
        "extras": overall_extras,
    }]
    write_csv(outdir / "combined_summary.csv", rows_for_csv)

    # Write the same information as JSON for easier parsing
    payload = {
        "sources": sources,
        "overall": {
            "n_items": overall_n,
            "errors": overall_err,
            "totals": overall_totals,
            "extras": overall_extras,
        }
    }
    write_json(outdir / "combined_summary.json", payload)

    print("[Summary] Wrote:", outdir)

if __name__ == "__main__":
    main()
