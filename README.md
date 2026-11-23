# NetGuard

## Overview

NetGuard is a browser-based network traffic analyser with basic rule-based
threat detection. It captures packet metadata, displays live traffic information
and provides understandable alerts for selected unusual network patterns.

It is a Windows-focused, current-session-only student project. Npcap and Scapy
capture packet metadata, while a local Flask dashboard presents the current
capture.

Version: **1.0.0** · Database schema: **8**

NetGuard does not store raw packet payloads and does not guarantee that a device
is safe. Use it only on networks and systems you own or are authorized to test.

## Key features

- Browser-only dashboard at `http://127.0.0.1:5000`
- Windows adapter discovery with friendly names and Npcap capture identifiers
- IPv4/IPv6 normalization and adapter-aware traffic-direction classification
- Bounded capture queue, dropped-packet visibility, and clean Ctrl+C shutdown
- Explainable grouped alerts with evidence, recommendations, and timelines
- Human-readable TCP flag labels with exact flags retained in technical details
- Current-session Safety Score (`100 - internal risk score`)
- Current Session PDF, Packet Metadata CSV, and Alert Incidents CSV downloads
- Schema-version-8 SQLite runtime storage without packet payloads

## How NetGuard works

Npcap exposes Windows capture adapters to Scapy. A capture thread normalizes
packet headers into a bounded queue. A processing thread records metadata,
updates live statistics, runs conservative rules, groups related detections,
and stores the temporary current session in SQLite. Flask exposes that service
to local browser pages and JSON endpoints.

## Architecture

The main layers are:

- `capture/`: adapter discovery, capture lifecycle, packet normalization
- `core/`: data models, statistics, risk, and Safety Score
- `detection/`: rule-based detectors and incident grouping
- `database/`: schema migrations and temporary SQLite persistence
- `application/`: UI-independent lifecycle and process attribution
- `reports/`: PDF generation
- `webapp/`: local Flask API, templates, JavaScript, and CSS

## Browser-only mode

`app.py` is the application entry point. Flask binds to loopback by default and
should remain local because the API does not provide authentication.

## Current-session workflow

1. Open NetGuard and choose an available adapter.
2. Start capture in Normal or Development Mode.
3. Review live packets, statistics, alerts, and Safety Score.
4. Stop capture.
5. Download the Current Session Report and/or the two CSV metadata exports.
6. Start another capture to replace the previous temporary session.
7. Close NetGuard to clear all temporary runtime data.

Reports must be downloaded before starting another capture or closing NetGuard.
Restarting NetGuard begins with an empty runtime database.

## Requirements

- Windows 10 or Windows 11
- Python 3.11 or newer
- [Npcap](https://npcap.com/) with its WinPcap compatibility option enabled
- Administrator privileges when required to open the selected capture adapter

Runtime Python dependencies are Flask, Scapy, fpdf2, and psutil.

## Installation

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Install test tools with:

```powershell
pip install -r requirements-dev.txt
```

## Running NetGuard

Run the terminal as Administrator if Npcap requires elevated access:

```powershell
python app.py
```

Open `http://127.0.0.1:5000`. Stop with Ctrl+C; NetGuard stops and joins capture
workers, clears temporary session rows, and closes SQLite.

## Using the dashboard

The sidebar contains Dashboard, Network Capture, Live Packets, Alerts,
Statistics, Reports & Exports, and Settings. Numeric database session IDs are
not displayed. Adapter selection and Development Mode are locked while capture
runs. A dropped-packet warning is a capture-quality warning, not an attack
alert.

## Detection rules

NetGuard maintains these seven user-facing detection rules:

- Port Scan
- Repeated Connection Attempts
- HTTP Request Flood
- DNS Query Flood
- Unusual Network Activity
- High Outbound Data Transfer
- Suspicious Port Activity

These rules use understandable thresholds and indicate activity worth
reviewing. An alert is not proof that an attack or data theft occurred, and
legitimate activity may sometimes trigger an alert. Their known-good thresholds
are covered by automated tests.

## Technologies used

- Python
- Flask
- Scapy with Npcap
- SQLite
- fpdf2
- psutil
- HTML, CSS, and JavaScript
- pytest

## Development Mode

Development Mode uses lower detection thresholds for safe testing. Generate
only authorized synthetic traffic in an isolated lab. It is not intended for
normal monitoring because ordinary bursts can trigger more alerts.

## Database and privacy

SQLite is temporary runtime storage. Additive transactional migrations preserve
schema version 8, while `clear_runtime_data()` removes capture sessions, packets,
connections, alert timelines, statistics, and score/risk rows at startup, before
a new capture, and during clean shutdown. Schema metadata and required settings
remain. WAL is enabled internally.

The repository must not contain runtime databases, captures, logs, exports,
secrets, personal paths, adapter GUIDs, or real network identifiers.

NetGuard stores normalized packet metadata rather than raw packet payloads. It
does not decrypt HTTPS or inspect encrypted messages, passwords, or
credentials.

## Reports and exports

After capture stops, Reports & Exports provides:

- Current Session PDF
- Packet Metadata CSV
- Alert Incidents CSV

Filenames contain no numeric session ID. CSV headings and values are
human-readable and contain no payloads. Application names are shown only when
the existing psutil socket mapping confirms them; otherwise they say
`Unknown application`. NetGuard does not identify websites, browser tabs, or
online services. Download files before another capture or shutdown.

## Testing

```powershell
python -m pytest
python -m compileall -q .
python -m pip check
```

Tests use synthetic documentation ranges and copied temporary databases; they
must never target a real user database.

## Project structure

```text
NetGuard/
|-- .github/
|-- application/
|-- capture/
|-- core/
|-- database/
|-- detection/
|-- reports/
|-- tests/
|-- webapp/
|   |-- static/
|   `-- templates/
|-- app.py
|-- config.py
|-- config.example.env
|-- version.py
|-- README.md
|-- requirements.txt
|-- requirements-dev.txt
|-- pytest.ini
|-- LICENSE
|-- SECURITY.md
`-- .gitignore
```

## Known limitations

- Host capture visibility depends on the adapter and virtualization topology.
  VirtualBox Host-Only VM-to-VM unicast may bypass the Windows host capture path.
- Rule-based detections can produce false positives and false negatives.
- Process attribution is best effort and can be unavailable or race with socket
  closure.
- A mapped application was active during the observed connection; NetGuard does
  not claim that the process caused an alert.
- NetGuard reports activity for review but does not automatically block traffic.
- Rule-based monitoring does not guarantee complete threat detection and is not
  a replacement for a professional IDS or IPS.
- There is no remote authentication; keep the service bound to loopback.
- An unexpected hard process termination can leave temporary rows until the
  next startup cleanup.

## Ethical and legal use

Capture only traffic you are authorized to inspect. Prefer isolated lab
networks, synthetic addresses, and systems you own. Do not use NetGuard to
monitor other people without clear permission.

## Troubleshooting

- Missing adapters: install/reinstall Npcap and enable compatibility mode.
- Permission errors: start the terminal as Administrator.
- Adapter unavailable: refresh the page and choose an adapter that is up.
- VirtualBox traffic not visible: use capture inside a VM, bridged networking,
  or a mirrored/TAP/SPAN capture point; Host-Only host capture may see only
  broadcasts such as ARP.
- Dropped packets: reduce traffic, close expensive applications, or treat the
  session totals as incomplete.

  ## Problem Statement
Monitoring local network activity and spotting unusual traffic patterns on Windows often involves heavy enterprise tools or raw packet captures that retain sensitive payload data. NetGuard provides a lightweight, current-session-only local dashboard that inspects packet metadata, applies explainable rule-based checks, and clears runtime session data on exit.

## Future improvements

Possible student-project extensions include authenticated remote deployment,
additional tested protocol metadata, configurable rule profiles, and improved
process attribution. These are outside the current browser-only design.

## License

NetGuard uses the MIT License contained in [LICENSE](LICENSE).

## Author / student project note

Author: **Rase Kikhi**

NetGuard is an educational student project and is not a production IDS or IPS.
