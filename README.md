# SentinelScan

SentinelScan is a defensive web vulnerability scanner designed to help security analysts identify common web security misconfigurations, exposed metadata, weak HTTP security headers, insecure forms, and SSL/TLS issues. The tool focuses on safe passive analysis and produces structured risk-based reports suitable for analyst workflows.

## Stack

- Python
- FastAPI
- SQLite by default, with PostgreSQL-ready configuration support
- Jinja2 report templates
- WeasyPrint PDF export
- LaTeX (.tex) report export
- React dashboard planned later

## Build Order

1. Header scanner
2. Crawler
3. Form analyzer
4. SSL checker
5. Report generator
6. Database storage
7. React dashboard
8. GitHub README with screenshots

## Run

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip3 install -r requirements.txt
python3 run.py
```

```windows
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

## Test

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H "Content-Type: application/json" \
  -d "{\"target_url\":\"https://example.com\"}"
```

## API

- `POST /scan` - runs passive checks against a target URL
- `GET /scan/{scan_id}` - retrieves a stored scan result
- `GET /report/{scan_id}` - returns the HTML report for a scan
- `GET /report/{scan_id}/tex` - downloads the report as a LaTeX `.tex` file
- `GET /report/{scan_id}/pdf` - returns a PDF report for a scan
- `GET /health` - health check
