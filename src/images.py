# ========== IMAGES.PY (BEGINNER-FRIENDLY) ==========
# This file is designed to run a simple optical character recognition (OCR)
# and cue detection pipeline on images stored in data/images/.
# It uses Tesseract via the pytesseract wrapper. 
# The results are saved in outputs/<timestamp>/ as JSON and CSV.
# The cue detection uses the same lexicon from src/cues.py.

import csv
import json
import re
from datetime import datetime
from pathlib import Path

from PIL import Image, ImageOps
import pytesseract

# Below imports the cue detection functions and lexicon
from src.cues import detect_cues, summarize_counts, CUE_LEXICON

# Root paths
ROOT = Path(__file__).resolve().parents[1]
IMAGES_DIR = ROOT / "data" / "images"
OUTPUTS = ROOT / "outputs"

# Below is the path to the Tesseract executable.
# Change this if Tesseract is installed elsewhere.
# For Windows, it might be something like:
# pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
# For macOS/Linux, if Tesseract is in your PATH, you may not need to set this.
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# Supported image types
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp"}

# Extra heuristics: ALL-CAPS words, exclamations, money symbols, and link patterns
RE_ALL_CAPS = re.compile(r"\b[A-Z]{2,}\b")
RE_EXCLAM   = re.compile(r"!+")
RE_MONEY    = re.compile(r"[£$€]")
RE_LINK     = re.compile(r"(https?://|www\.)", re.IGNORECASE)

# CSV columns for cue totals (sum_<category>)
CATEGORY_COLUMNS = []
for category_name in CUE_LEXICON.keys():
    CATEGORY_COLUMNS.append("sum_" + category_name)

# Below creates the outputs directory if it doesn't exist
def ensure_dir(path_obj):
    path_obj.mkdir(parents=True, exist_ok=True)

# Below creates a timestamped run directory
def timestamp_run_dir():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = OUTPUTS / ts
    ensure_dir(run_dir)
    return run_dir

# Below saves JSON data to a file with pretty formatting and UTF-8 encoding
def save_json(path_obj, data_obj):
    text = json.dumps(data_obj, indent=2, ensure_ascii=False)
    path_obj.write_text(text, encoding="utf-8")

# Below saves a list of dicts as CSV, sanitizing newlines in values
def save_csv(path_obj, rows):
    if not rows:
        path_obj.write_text("", encoding="utf-8")
        return
    headers = list(rows[0].keys())
    with path_obj.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            clean_row = {}
            for h in headers:
                value = row.get(h, "")
                value = str(value).replace("\n", " ").replace("\r", " ")
                clean_row[h] = value
            writer.writerow(clean_row)

# Below normalizes text for cue detection
# It lowercases and removes non-alphanumeric characters (except spaces)
def normalize_text(text):
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()

# Below detects cues in both raw and normalized text, merges counts, and adds heuristics
# Returns (totals_dict, extras_dict)
def detect_with_extras(text):
    if text is None:
        text = ""
    matches_raw = detect_cues(text)

    # Detect cues in normalized text
    norm = normalize_text(text)
    matches_norm = detect_cues(norm)

    # Merge phrase-level counts from raw and normalized passes
    merged_phrase = {}
    # First, copy raw counts
    for category, phrase_counts in matches_raw.items():
        merged_phrase[category] = {}
        for phrase, count in phrase_counts.items():
            merged_phrase[category][phrase] = count
    # Then, add normalized counts
    for category, phrase_counts in matches_norm.items():
        if category not in merged_phrase:
            merged_phrase[category] = {}
        for phrase, count in phrase_counts.items():
            old_count = merged_phrase[category].get(phrase, 0)
            merged_phrase[category][phrase] = old_count + count

    # Sum totals per category
    totals = summarize_counts(merged_phrase)

    # Extra simple heuristics
    extras = {
        "all_caps_words": len(RE_ALL_CAPS.findall(text)),
        "exclamations":   len(RE_EXCLAM.findall(text)),
        "money_symbols":  len(RE_MONEY.findall(text)),
        "links":          len(RE_LINK.findall(text)),
    }
    return totals, extras

# Below performs OCR on a single image and returns extracted text
# It uses a basic pipeline: grayscale, upscaling, thresholding, then Tesseract OCR
# Returns extracted text as a string
def ocr_image(image_path):
    img = Image.open(image_path)
    img = ImageOps.grayscale(img)

    w, h = img.size
    # If the image is tiny, scale it up to help OCR
    if min(w, h) < 800:
        # Use a simple integer scale factor
        smallest_side = min(w, h)
        if smallest_side < 1:
            smallest_side = 1
        scale = int(800 / smallest_side)
        if scale < 2:
            scale = 2
        img = img.resize((w * scale, h * scale))

    # Simple threshold to increase contrast (wrapped in try just in case)
    try:
        img = img.point(lambda p: 255 if p > 170 else 0)
    except Exception:
        pass

    # OCR configuration:
    # --oem 3 = default engine
    # --psm 6 = assume a block of text
    config = "--oem 3 --psm 6"
    text = pytesseract.image_to_string(img, config=config)
    return text

# Below scans all images in the given directory, performs OCR and cue detection
# Returns a list of result dicts, one per image
def scan_image_dir(images_dir):
    results = []
    if not images_dir.exists():
        return results

    # Walk all files under data/images/
    for path_obj in images_dir.rglob("*"):
        if not path_obj.is_file():
            continue
        suffix = path_obj.suffix.lower()
        if suffix not in IMAGE_EXTS:
            continue

        try:
            text = ocr_image(path_obj)
            totals, extras = detect_with_extras(text)
            result_row = {
                "path": str(path_obj),
                "status": "ok",
                "text_len": len(text) if text else 0,
                "cues_total": totals,  # dict per category
                "extras": extras       # extra heuristics
            }
            results.append(result_row)
        except Exception as e:
            # Capture the error but keep the pipeline going
            err_row = {
                "path": str(path_obj),
                "status": "error",
                "error": repr(e)
            }
            results.append(err_row)

    return results

# Below is the main function to run the OCR and cue detection pipeline
# It saves results as JSON and CSV in a timestamped outputs folder
def main():
    if not IMAGES_DIR.exists():
        print("Images folder not found:", IMAGES_DIR)
        return

    run_dir = timestamp_run_dir()
    print("[Images] Scanning:", IMAGES_DIR)

    rows = scan_image_dir(IMAGES_DIR)
    save_json(run_dir / "images_ocr.json", rows)

    # Build flat CSV rows
    flat_rows = []
    for r in rows:
        if r.get("status") == "ok":
            totals = r.get("cues_total", {})
            extras = r.get("extras", {})
            row = {
                "path": r.get("path", ""),
                "text_len": r.get("text_len", 0)
            }
            # Add sum_<category> columns
            for col_name in CATEGORY_COLUMNS:
                cat_name = col_name.replace("sum_", "")
                row[col_name] = totals.get(cat_name, 0)
            # Add heuristic counts
            row["all_caps_words"] = extras.get("all_caps_words", 0)
            row["exclamations"]   = extras.get("exclamations", 0)
            row["money_symbols"]  = extras.get("money_symbols", 0)
            row["links"]          = extras.get("links", 0)
            flat_rows.append(row)
        else:
            # Error rows still go in CSV for audit trail
            flat_rows.append({
                "path": r.get("path", ""),
                "text_len": 0,
                "error": r.get("error", "")
            })

    save_csv(run_dir / "images_ocr_summary.csv", flat_rows)
    print("[Images] Done →", run_dir)

if __name__ == "__main__":
    main()
