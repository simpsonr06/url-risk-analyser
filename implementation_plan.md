# Intelligent Phishing Detection Platform

Build a system that analyzes URLs and determines their risk level using heuristic analysis, domain intelligence, a risk scoring engine, a SQLite database, and a clean modern frontend.

## Proposed Changes

### Configuration and Setup
* `requirements.txt`: FastAPI, Uvicorn, httpx, and python-multipart.
* `config/settings.py`: Include fundamental configurations like database file path.

### Database Layer
* `database/db.py`: SQLite connection setup.
* `database/models.py`: Database schema definitions using Pydantic (for API) and pure python logic for tables.
* `database/queries.py`: SQL scripts for `insert_scan`, `get_recent_scans`, `get_dashboard_stats`.

### Services
* `services/rdap_service.py`: Defines HTTP requests to `rdap.org` to fetch domain intel.

### Detection Engine
* `engine/heuristics.py`: Includes checks for HTTPS, `@` symbol, TLD analysis, length, and subdomain logic.
* `engine/entropy.py`: Analyzes string entropy to detect randomized domains.
* `engine/rdap.py`: Exposes logical processing over raw RDAP info (e.g., extracting dates and calculating domain age).
* `engine/scoring.py`: Computes risk score out of 100 based on modules with specified weights (HTTPS missing +20, Suspicious TLD +20, @ symbol +20, High entropy +20, Domain age < 90 days +25).
* `engine/aggregator.py`: Coordinates outputs from the heuristics, entropy, and RDAP modules to generate a final classification output (0-29 SAFE, 30-59 SUSPICIOUS, 60-100 PHISHING).

### Web API
* `app/main.py`: FastAPI application setup inclusive of mounting routes, CORS, and serving the frontend.
* `app/routes/scan.py`: The `POST /scan` endpoint returning JSON scores.

### Frontend
* `frontend/index.html`: A clean, modern HTML/JS interface with a dark theme leveraging CSS variables for dynamic rendering, to show dashboard stats, history, and the primary analysis field.

## Verification Plan

### Manual Verification
* Start the server with `uvicorn app.main:app`.
* Interact with the frontend to test normal URLs (e.g., https://google.com) and suspicious ones (e.g., http://login-update-paypal.xyz).
* Verify that recent scans and general stats persist via SQLite.
