# Hash Gathering — `scripts/hash_gathering/`

Utilities for collecting and preparing SHA256 hash lists to use as input for MHATOD.

---

## Files

| File | Description |
|---|---|
| `HashesCleaner.html` | Browser-based tool to extract, deduplicate, and format SHA256 hashes from raw text, and to generate a JS extractor for MalwareBazaar and Triage |

---

## HashesCleaner.html

A single-file, self-contained HTML page that runs entirely in your browser — no server, no dependencies, no data sent anywhere.

It solves two problems in the hash-gathering workflow:

1. **Extracting hashes from a database page** using the built-in JS extractor snippet (MalwareBazaar and Triage supported)
2. **Cleaning raw text** (console output, logs, mixed content) down to a clean, deduplicated, sorted list of SHA256 hashes

---

## Full Workflow

### Step 1 — Search the database

Go to [MalwareBazaar](https://bazaar.abuse.ch) or [Triage](https://tria.ge) and search for samples by family name, signature, or tag.

> **Tip:** Modify the URL query parameters or use the browser's network inspector to increase the number of results shown per page so you can collect all hashes in one pass.

### Step 2 — Extract hashes from the page

In `HashesCleaner.html`, click **Copy Extractor JS**. This copies a JavaScript snippet to your clipboard.

Then, on the database page:
1. Open the browser DevTools console (`F12` → Console tab)
2. Paste and run the snippet

The script automatically detects whether you are on MalwareBazaar or Triage and queries the correct DOM elements:

```js
// On Triage → reads data-clipboard attributes from .clipboard elements
// On MalwareBazaar → reads .shortify element text content
```

It deduplicates the hashes, sorts them, and copies the result to your clipboard. A browser alert will confirm how many hashes were found.

### Step 3 — Clean and format

Paste the clipboard content into the `HashesCleaner.html` textarea. Then click **Clean Text**.

The tool will:
- Scan the text for any 64-character hexadecimal strings (SHA256 regex: `\b[A-Fa-f0-9]{64}\b`)
- Strip surrounding quotes and whitespace
- Remove duplicates
- Sort alphabetically
- Display one hash per line in the textarea

Click **Copy Hashes** to copy the result to your clipboard, then save it to a `.txt` file — one hash per line, which is the required input format for MHATOD.

### Step 4 — Run MHATOD

```bash
python MHATOD.py hashes.txt
```

---

## Button Reference

| Button | Action |
|---|---|
| **Clean Text** | Extracts, deduplicates, and sorts all SHA256 hashes found in the textarea |
| **Copy Hashes** | Copies the current textarea content to the clipboard |
| **Copy Extractor JS** | Copies the JS snippet for use in the browser DevTools console on MalwareBazaar or Triage |

---

## Supported Databases for the JS Extractor

| Database | URL | Detection method |
|---|---|---|
| MalwareBazaar | `bazaar.abuse.ch` | `.shortify` element `innerText` |
| Triage | `tria.ge` | `.clipboard [data-clipboard]` attribute |

For any other source (CSV exports, technical reports, text files), paste the content directly into the textarea and use **Clean Text** — the SHA256 regex will find all valid hashes regardless of surrounding text.

---

## Notes

- The tool is fully offline. No data leaves your browser at any point.
- **Clean Text** performs exact deduplication — the same hash from multiple sources will appear only once in the output.
- Non-SHA256 hashes (MD5, SHA1, etc.) are ignored automatically since they do not match the 64-character hex pattern.
