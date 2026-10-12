# ThreatIntel Scanner

A local-first Flask dashboard for URL heuristic inspection, streaming SHA-256 file hashing, optional VirusTotal v3 reputation lookups, and browser-local scan history.

## Features

- URL checks for HTTP, IP-address hosts, punycode, long URLs, deep subdomains, and selected suspicious paths.
- SHA-256 hashing of files up to 10 MB without executing or saving them.
- Optional VirusTotal lookup: URL is sent **only if selected**; file lookup sends **only the SHA-256 hash**, never file contents.
- Browser-local history of the last 20 scan summaries. Clear it from the dashboard.
- Flask API endpoints and Pytest tests.

**Important:** Heuristic scores are not a malware verdict. VirusTotal results may be unavailable or unknown. Do not use this as a production security control. Don't upload private URLs or sensitive hashes to third-party services without authorization.

## Run locally (Windows PowerShell)

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python -m pytest -q
python app.py
```

Open http://127.0.0.1:5001

## Optional VirusTotal integration

In the same PowerShell session, before starting the server:

```powershell
$env:VIRUSTOTAL_API_KEY = "YOUR_API_KEY"
python app.py
```

Never commit your API key. Leave the checkbox off to use the app without an API key. The app performs GET lookups against VirusTotal v3 and does not submit samples for scanning.

## API

- `POST /api/url` JSON: `{"url":"https://example.com", "reputation":false}`
- `POST /api/hash` multipart: `file=<binary>`, `reputation=false`

## Tests

Run `python -m pytest -q`. Tests cover successful requests, invalid URL schemes, hashing accuracy, missing/oversized uploads, and opt-in behavior.

## Architecture

Browser dashboard → Flask API → URL heuristics / SHA-256 stream → optional VirusTotal lookup. Scan summaries are stored in browser `localStorage` rather than a backend database.

## Limitations

- No dynamic sandboxing or antivirus scanning.
- No user accounts, authentication, or centralized history.
- URL heuristics can generate false positives and false negatives.
- Development server is localhost-only, not production deployment.

## Resume-friendly description

Built a Flask security dashboard featuring URL heuristic analysis, streaming SHA-256 hashing, optional VirusTotal reputation lookups, browser-local scan history, and automated API tests.


## Malware reputation verdicts (v2)

The dashboard now shows VirusTotal engine counts and individual detections from **existing reports** when `VIRUSTOTAL_API_KEY` is configured and the user opts in. File bytes are **never uploaded**, opened, or executed. The SHA-256 hash is shared with VirusTotal; URL lookups send the full URL.

- **DETECTED:** at least one engine reported malicious.
- **SUSPICIOUS:** one or more engines reported suspicious, none malicious.
- **NO_DETECTIONS:** existing report with zero detections; **not proof of safety**.
- **UNKNOWN:** no existing report; **not proof of safety**.
- **NOT_SCANNED:** no API key or lookup unavailable.
- **HASH_ONLY / HEURISTIC_ONLY:** VirusTotal lookup was not requested.

This is reputation analysis, **not a local antivirus scanner**. New, private or unknown malware may not be detected. Never open or execute suspicious attachments. To check previously unseen files, use a reputable antivirus scanner locally or submit samples only with explicit authorization and awareness of privacy risks.

### Enable VirusTotal (PowerShell)

```powershell
$env:VIRUSTOTAL_API_KEY = "YOUR_API_KEY"
python app.py
```

Get a key from your VirusTotal account. Never commit it to GitHub. API quotas and access restrictions apply. Run `python -m pytest -q` to run the test suite.

## Security operations dashboard (v2.1)

The refreshed UI has a responsive dark SOC-style layout, detailed VirusTotal engine results, recent investigation history, and collapsible technical JSON output. To use live VirusTotal data, set `VIRUSTOTAL_API_KEY` in the terminal **before** starting Flask and explicitly check the lookup option for each scan. A lookup retrieves **existing reports only**; it does not submit a new scan. The URL lookup shares the entered URL with VirusTotal; the file lookup shares only the SHA-256 hash. Files are not executed or uploaded to VirusTotal. Results showing no detections do not prove an indicator is safe.

Never commit your API key or private samples. If you previously exposed a key, revoke it and use a new one.
