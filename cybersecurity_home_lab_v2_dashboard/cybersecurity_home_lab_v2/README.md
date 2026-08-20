# Cybersecurity Home Lab — Version 2: Security Monitoring Dashboard

A defensive cybersecurity portfolio project built with Python and Tkinter.

## Features
- Graphical security monitoring dashboard
- Authentication-event parsing
- Failed/successful login metrics
- Potential brute-force detection
- Successful-login-after-failures detection
- Suspicious source-IP count
- Failed-login breakdown by source IP
- Targeted-account breakdown
- Load arbitrary authorised/synthetic `.log` files

## Run
From this project directory:

```bash
python dashboard/security_dashboard.py
```

Python's Tkinter GUI library is included with most Windows Python installations.

## Portfolio demonstration
The included `data/auth.log` is synthetic. The dashboard should display:
- 11 events
- 8 failed logins
- 3 successful logins
- 2 alerts
- 1 suspicious IP

## Next development steps
- Add a live chart using matplotlib.
- Add CSV/JSON export.
- Add configurable detection thresholds.
- Add a Linux VM log collector.
- Integrate Nmap results into an asset panel.
- Document Wireshark traffic captures.
- Add automated unit tests.

## Ethical scope
Only analyse logs and systems you own or have explicit permission to test.
