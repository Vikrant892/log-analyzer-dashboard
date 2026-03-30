# Log Analyzer — SIEM Dashboard

I started building this while working at SecurDI because I wanted a lightweight alternative to Splunk that I could actually spin up on a single VM without selling a kidney. Most of our team was drowning in raw syslog output and nobody had time to grep through auth.log at 2am when alerts fired. So I built this.

It's a Flask-based dashboard that parses common log formats, runs basic threat detection rules, and shows you what's going on with some Chart.js visualizations. Not trying to replace a full SIEM — just trying to make log analysis less painful for small teams.

## What It Does

- **Parses** syslog (RFC 3164), auth.log, Apache/Nginx access logs
- **Detects** brute force attacks, port scans, suspicious user agents, path traversal attempts
- **Visualizes** top IPs, event timelines, severity breakdowns
- **Alerts** with severity levels mapped to MITRE ATT&CK where applicable

## Supported Log Formats

| Format | What Gets Parsed |
|--------|-----------------|
| Syslog RFC 3164 | Timestamp, hostname, app, PID, message |
| auth.log | SSH success/failure, sudo commands, auth failures |
| Apache/Nginx | IP, method, path, status, user-agent, bytes |

## Detection Rules

| Rule | MITRE ATT&CK | Trigger |
|------|--------------|---------|
| Brute Force | T1110 | >5 failed SSH from same IP |
| Port Scan | T1046 | >20 unique ports from same IP |
| Scanning Tools | T1595 | Known scanner user-agents (Nikto, sqlmap, etc.) |
| Path Traversal | — | Access to sensitive paths (/.env, /wp-admin, etc.) |

## How to Run

```bash
# clone it
git clone https://github.com/Vikrant892/log-analyzer-dashboard.git
cd log-analyzer-dashboard

# set up venv (optional but recommended)
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on windows

# install deps
pip install -r requirements.txt

# run it
python app.py
```

Dashboard will be at `http://localhost:5000`. It auto-loads the sample logs on startup so you'll see data immediately.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard |
| `/upload` | GET/POST | Upload log files via browser |
| `/alerts` | GET | JSON array of all alerts |
| `/api/stats` | GET | Stats for charts (JSON) |
| `/api/upload` | POST | Programmatic upload (curl-friendly) |

### Upload via curl

```bash
curl -X POST -F "logfile=@/var/log/auth.log" http://localhost:5000/api/upload
```

## Running Tests

```bash
pytest tests/ -v
```

## Project Structure

```
├── app.py                # flask app, routes, glue code
├── analyzer/
│   ├── parser.py         # log format parsers (regex central)
│   ├── detector.py       # threat detection rules
│   └── stats.py          # aggregation for charts
├── templates/            # jinja2 templates
├── static/
│   ├── css/style.css     # dark cyber theme
│   └── js/charts.js      # chart.js visualizations
├── sample_logs/          # sample data to play with
└── tests/                # pytest suite
```

## Roadmap

Things I want to add when I get around to it:

- **SQLite persistence** — right now everything lives in memory, which is fine for demos but not great for anything serious
- **Real-time tail mode** — watch a log file and stream new events to the dashboard via websockets
- **Sigma rule support** — import community detection rules instead of hand-coding everything

## License

MIT — do whatever you want with it.
