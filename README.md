This project forms part of a Master's dissertation investigating how cognitive biases and persuasive cues are exploited in phishing content. The technical component is a Python based analysis tool designed to detect, quantify, and summarize linguistic and visual cues of persuasion (e.g., authority, urgency, scarcity, social proof) across multiple phishing dataset tyles. The aim is to demonstrate the intersection between cybersecurity and human psychology, providing an educational model for understanding how attackers manipulate user behavior. 

For ethical and security reasons, all datasets and output files used in this project have been excluded from this repository. Only the code, lexicon, and supported documentation are provided. 

# Research Context

Phishing remains one of the most common and effective cyber attack vectors, primarily because it targets human cognition rather than technical vulnerabilities. This artefact translates established psychological theories into a technical detection framework, drawing from:

- Cialdini's Principle of Persuasion (1984, revised 2007)
- Kahneman and Tversky's Heuristics and Biases (1974)

By incorporating these psychological foundations into a rule based lexicon, the tool identifies common cognitive triggers such as authority, urgency, scarcity, and fear within phishing datasets.

# Core Functionality

The artefact processes three types of phishing data, emails, images, and URLs, to identify bias based persuasive cues. Each component operates independently but contributes to a combined summary output.

- Emails (nazario.py) processes phishing emails from the Nazario phishing corpus in .mbox or .csv format. Each message is normalized, cleaned, and scanned for linguistic patterns and emotional indicators such as capitalization, exclamation marks, and urgency related words.
- Images (images.py) extracts and analyzes text from phishing screenshots using Optical Character Recognition (OCR) via the pytesseract library. This captures visual phishing messages such as fake login pages and reward banners. 
- URLs (urlscan.py) examines a random sample of phishing URLs, taken from a larger PhishTank dataset, to identify linguistic tokens suggesting manipulation, such as "secure update" or "verify login".
- Cues (cues.py) defines the core lexicon containing phrases, words, and expressions linked to each cognitive bias category. 
Summarize (summarize.py) aggregates results from all modules into timestamped folders, producing summary csv and json files for analysis.

# Design and Implementation

The tool is developed entirely in Python 3 and allows a modular design approach to support transparency, reproducibility and ease of testing. Each module can operate independently, allowing users to analyze specific datasets (emails, images, URLs) without executing the full pipeline. The system was developed using the Agile Kanban framework, allowing iterative refinement as new patterns and challenges emerged during data analysis. Execution takes place via Visual Studio Code within an isolated environment (.venv) to prevent external dependency conflicts and ensure ethical handling of potentially malicious content. 

# Outputs

The artefact generates timestamped result folders containing:

- Individual module outputs for emails, images, and URLs
- A combined summary file (csv and json) aggregating frequency counts per bias type
- Descriptive statistics showing total detections, errors, and category distributions. Results are presented visually within the dissertation using charts and tables to illustrate cue frequency across datasets. 

# System Requirements and Setup

To ensure safe and consistent execution, the artefact should be run in a contained virtual environment on a local machine. The tool does not connect to any live API's or scan live websites. All data should remain offline and pre sanitized. The OCR module requires Tesserat OCT to be installed locally. Ensure that the executable is added to your system path.  The recommended setup is as follows:

- Operating system: Windows 10/11, macOS, or Linux 
- Python Version: Python 3.12 or higher
- Required Libraries:
1. pandas - for data processing and output generation
2. regex or re - for lexicon pattern matching
3. pytesseract - for Optical Character Recognition (OCR) on image samples
4. pillow - image handling and format compatibility for OCR
5. json and csv - for structured output formats
6. os and sys - for file handling and directory management

All dependencies can be installed using the command: pip install -r requirements.txt

A virtual environment (.venv) is used to isolate the dependencies from the system environment. To create one, run: python -m venv .venv, then activate it before running any scripts. To activate use the following command: 
- Windows - .\.venv\Scripts\activate
- Linux/Mac - source .venv/bin/activate

# Execution

1. Ensure the virtual environment is installed
2. Place datasets in their respective folders under /data/ (sanitized emails, URLs, images)
3. Run the full analysis pipeline from the project root directory using: python -m src.cli run

The commands can also be run individually by using: python -m src.images, python -m src.nazario, python -m src.urlscan and python -m src.summarize.

