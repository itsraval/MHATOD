<img align="right" src=".github/assets/MHATOD.png" width="200" height="200">

# MHATOD - Malware Hash Analysis Tool via Open-source Data

MHATOD is a Python tool that gathers and classifies malware metadata by querying online databases - [VirusTotal](https://www.virustotal.com/gui/search/) and [MalwareBazaar](https://bazaar.abuse.ch/) - and enriching the results with family and tag classification via [AVClass](https://github.com/malicialab/avclass/tree/master). Results are exported as structured JSON and CSV files for downstream analysis.

This project was developed during the dissertation [**"Behavioural Analysis of Current Evolution Ransomware Attack Exfiltration Methods"**](https://github.com/itsraval/MHATOD/blob/main/Docs/Behavioural_Analysis_of_Current_Evolution_Ransomware_Attack_Exfiltration_Methods.pdf) - MSc Advanced Security & Digital Forensics at [Edinburgh Napier University](https://www.napier.ac.uk/courses/msc-cyber-security-postgraduate-full-time).

---

## Features

- **VirusTotal integration** - fetches file type, first submission date, threat classification, YARA results, and per-AV-engine detections
- **MalwareBazaar integration** - fetches file type, architecture, signature, ClamAV results, and vendor intelligence (ANY.RUN, Intezer, Triage, ReversingLabs)
- **AvClass labeling** - derives malware family names and threat tags from VirusTotal output using the AvClass classifier
- **Parallel querying** - VirusTotal and MalwareBazaar requests run concurrently via `ThreadPoolExecutor`
- **Threat tag aggregation** - token-level tag extraction and frequency ranking across all data sources; optional top-5 filtering
- **Structured output** - individual JSON files per hash plus consolidated JSON and CSV files for each module and a final combined dataset
- **Resumable scans** - `--skip-lines` lets you pick up from where a previous run left off

---

## Academic Background

MHATOD was developed as part of the MSc dissertation **"Behavioural Analysis of Current Evolution Ransomware Attack Exfiltration Methods"** (Edinburgh Napier University, 2024). The dissertation investigates the classification and behavioural analysis of exfiltration-based ransomware. Malware that steals data before or instead of encrypting it (double extortion). The full dissertation is available in `Docs/`.

---

## Project Structure

```
MHATOD/
├── MHATOD.py                        # Entry point
├── .env                             # API keys (not committed)
├── pyproject.toml
├── README.md
├── requirements.txt
├── Docs/
│   └── Behavioural_Analysis_of_Current_Evolution_Ransomware_Attack_Exfiltration_Methods.pdf
├── scripts/
│   └── hash_gathering/
│       ├── HashesCleaner.html       # Browser tool: extract & clean SHA256 hashes
│       └── README.md                # Usage guide for hash gathering scripts
└── src/
    ├── cli.py                       # Argument parsing and .env loading
    ├── utils.py                     # Shared helpers (I/O, folder setup, tag extraction)
    └── modules/
        ├── virustotal_client.py     # VirusTotal API v3 client
        ├── malwarebazaar_client.py  # MalwareBazaar API v1 client
        ├── avclass_labeler.py       # AvClass subprocess wrapper
        └── combine_modules.py       # Merges outputs into a unified dataset
```

---

## Requirements

- Python 3.8+
- A **VirusTotal** API key (free tier supported) - [get one here](https://www.virustotal.com/gui/join-us)
- A **MalwareBazaar** API key - [get one here](https://bazaar.abuse.ch/api/)
- [AvClass](https://github.com/malicialab/avclass) installed and available on `PATH`

> At least one of the two API keys is required. The tool will warn you and ask for confirmation if one is missing.

---

## Installation

```bash
git clone https://github.com/itsraval/MHATOD.git
cd MHATOD
pip install -r requirements.txt
pip install avclass2          # or follow AvClass installation instructions
```

---

## Configuration

Create a `.env` file in the project root:

```env
VIRUSTOTAL_API_KEY=your_virustotal_key_here
MALWAREBAZAAR_API_KEY=your_malwarebazaar_key_here
```

Keys can also be passed directly as CLI flags, which will override `.env` values.

---

## Usage

```
python MHATOD.py <input_file> [options]
```

### Arguments

| Argument | Description |
|---|---|
| `input_file` | Path to a text file with one SHA256 hash per line |
| `-o`, `--output` | Output directory (default: `malware-metadata-TIMESTAMP`) |
| `-s`, `--skip-lines` | Number of hashes to skip (useful for resuming a scan) |
| `-ttt`, `--top-threat-tags` | Limit threat tags to the top 5 by frequency |
| `--vtkey` | VirusTotal API key (overrides `.env`) |
| `--mbkey` | MalwareBazaar API key (overrides `.env`) |
| `-b`, `--banner` | Display the ASCII banner |
| `-i`, `--info` | Display developer info |

### Example

```bash
# Basic scan using keys from .env
python MHATOD.py hashes.txt

# Custom output directory and top-5 threat tags only
python MHATOD.py hashes.txt -o results/my_scan --top-threat-tags

# Skip the first 50 hashes (resume a previous run)
python MHATOD.py hashes.txt -s 50

# Provide keys inline
python MHATOD.py hashes.txt --vtkey YOUR_VT_KEY --mbkey YOUR_MB_KEY
```

### Input file format

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
44d88612fea8a8f36de82e1278abb02f2fe2be51a9f0b9b0f5d5f8a7c2a8e4b1
...
```
One SHA256 hash per line, no headers or extra whitespace.

---

## Hash Gathering Workflow

Before running MHATOD, you need an input file of SHA256 hashes. The `scripts/hash_gathering/` directory provides tools to collect and prepare them from online malware databases.

### Step 1 - Extract hashes from MalwareBazaar or Triage

Open `HashesCleaner.html` in your browser and click **Copy Extractor JS**. This copies a JavaScript snippet to your clipboard. Then:

1. Go to [MalwareBazaar](https://bazaar.abuse.ch) or [Triage](https://tria.ge) and search for a ransomware family by tag or signature.
2. Open the browser DevTools console (`F12`).
3. Paste and run the copied JS. It scrapes all visible SHA256 hashes on the page and copies them to your clipboard.
4. Paste the result into the `HashesCleaner.html` textarea.

### Step 2 - Clean and format the hashes

With raw text in the textarea (console output, logs, or any mixed content), click **Clean Text**. The tool extracts all valid SHA256 hashes via regex, deduplicates them, sorts them, and displays one hash per line - ready to use as MHATOD input.

Click **Copy Hashes** to copy to clipboard, then save to a `.txt` file.

### Step 3 - Run MHATOD

```bash
python MHATOD.py hashes.txt -o results/my_scan
```

See `scripts/hash_gathering/README.md` for full details.

---

## Output Structure

```
<output_dir>/
├── VirusTotal/
│   └── <sha256>.json          # Raw API response per hash
├── MalwareBazaar/
│   └── <sha256>.json          # Raw API response per hash
├── AvClass/
│   └── <sha256>.json          # AvClass result per hash
├── json/
│   ├── VirusTotal.json        # Aggregated VT metadata
│   ├── MalwareBazaar.json     # Aggregated MB metadata
│   ├── AvClass.json           # Aggregated AvClass metadata
│   └── Combined_metadata.json # Merged dataset from all sources
└── csv/
    ├── VirusTotal.csv
    ├── MalwareBazaar.csv
    ├── AvClass.csv
    └── Combined_metadata.csv  # Final output for analysis
```

### Combined metadata fields

| Field | Source | Description |
|---|---|---|
| `sha256` | All | Hash of the sample |
| `fs_date` / `fs_time` | VT / MB | Earliest known first-seen date |
| `file_type` | VT + MB | Combined file type / architecture |
| `signature` | MB | Malware signature name |
| `threat_tags` | VT + MB | Frequency-ranked threat tag dictionary |
| `AV_family` | AvClass | Consensus malware family name |
| `AV_threat_tags` | AvClass | Behavioral/category tags |
| `error` | All | Error messages if a source failed |

---

## Limitations

MHATOD's output quality depends on what the databases contain. If a hash has no record on VirusTotal or MalwareBazaar, no metadata will be generated for that sample. Discrepancies between sources are common - this is expected and is one of the reasons the tool queries multiple databases simultaneously.

Classification results (AVClass family, threat tags) should be treated as evidence to guide analysis, not as ground truth. Manual review of the combined output is recommended when building a curated dataset.

---

## Author

Developed by **Alessandro Ravizzotti** 
Website: [alessandro.ravizzotti.dev](https://alessandro.ravizzotti.dev)  
Contact: alessandro[@]ravizzotti[.]dev

---

## License

This project is open-source. MIT License.
