# TRINETRA SENTINEL — Complete Application Report

**Version:** 1.0.0  
**Platform:** Windows (Offline-First Local EDR)  
**Last Updated:** June 2026

---

## 1. PROJECT OVERVIEW

Trinetra Sentinel is an **offline-first local Endpoint Detection and Response (EDR) prototype** for Windows. It monitors endpoint activity in real-time, detects threats using rule-based engines and ML anomaly detection, correlates events across multiple sources, and provides risk scoring — all running locally without any internet dependency.

### Core Design Principles
- **Offline-first:** No external APIs required. All analysis runs locally.
- **Real-time monitoring:** WebSocket-based live updates every ~3 seconds.
- **Lightweight:** SQLite storage, minimal dependencies, single-machine deployment.
- **Privacy-safe:** No telemetry sent to cloud. All data stays on the endpoint.

---

## 2. TECHNOLOGY STACK

### Backend
| Component | Technology | Version |
|-----------|-----------|---------|
| Web Framework | FastAPI | 0.115.6 |
| Server | Uvicorn | 0.34.0 |
| Process Monitoring | psutil | 6.1.1 |
| ML Anomaly Detection | scikit-learn (Isolation Forest) | 1.6.0 |
| Numerical Computing | numpy | 2.2.1 |
| Windows Event Logs | pywin32 | 308 |
| USB Device Discovery | WMI | 1.5.1 |
| File System Monitoring | watchdog | 6.0.0 |
| Database | SQLite | Built-in |
| Language | Python | 3.13 |

### Frontend
| Component | Technology | Version |
|-----------|-----------|---------|
| UI Library | React | 19.0.0 |
| Build Tool | Vite | 6.0.5 |
| Rendering | React DOM | 19.0.0 |
| Real-time Updates | WebSocket | Native |
| Language | JavaScript (JSX) | ES Module |

---

## 3. APPLICATION ARCHITECTURE

```
┌─────────────────────────────────────────────────────┐
│                   FRONTEND (React)                   │
│  ┌─────────┐ ┌──────────┐ ┌────────┐ ┌──────────┐  │
│  │Dashboard │ │Live Feed │ │AI Panel│ │Log Stream│  │
│  └────┬─────┘ └────┬─────┘ └───┬────┘ └────┬─────┘  │
│       │  WebSocket + REST API   │           │         │
└───────┼────────────┼────────────┼───────────┼─────────┘
        │            │            │           │
┌───────┼────────────┼────────────┼───────────┼─────────┐
│       ▼            ▼            ▼           ▼         │
│                 BACKEND (FastAPI)                     │
│  ┌────────────────────────────────────────────────┐   │
│  │              SystemMonitor (3s loop)            │   │
│  │  ┌──────────┐ ┌──────────┐ ┌────────────────┐  │   │
│  │  │ Process  │ │ Resource │ │ System Activity │  │   │
│  │  │ Scanner  │ │ Analyzer │ │    Engine       │  │   │
│  │  └──────────┘ └──────────┘ └────────────────┘  │   │
│  │  ┌──────────────────────────────────────────┐   │   │
│  │  │         TelemetryManager                 │   │   │
│  │  │  Security Log │ App Log │ USB │ Registry │   │   │
│  │  │  PowerShell   │ Setup   │ FS  │ Watcher  │   │   │
│  │  └──────────────────────────────────────────┘   │   │
│  └────────────────────────────────────────────────┘   │
│  ┌──────────┐ ┌──────────┐ ┌────────────────────┐    │
│  │ Threat   │ │ Risk     │ │ AI Analysis Module  │    │
│  │ Engine   │ │ Scoring  │ │ (Local Algorithm)   │    │
│  └──────────┘ └──────────┘ └────────────────────┘    │
│  ┌──────────┐ ┌──────────┐ ┌────────────────────┐    │
│  │ SQLite   │ │ Notifica-│ │ Log Stream Buffer   │    │
│  │ Database │ │ tions    │ │ (300 entries)       │    │
│  └──────────┘ └──────────┘ └────────────────────┘    │
└───────────────────────────────────────────────────────┘
```

---

## 4. 9 CORE ENGINES — Detailed Capabilities

### Engine 1: System Activity Monitoring Engine
**File:** `backend/engines/system_activity.py`

- Tracks process creation and termination in real-time
- Groups processes by **name** (not individual PIDs) to eliminate sub-process noise
- "App opened" fires only when a process name first appears
- "App closed" fires only when all instances of a process name disappear
- Maintains a rolling buffer of 200 recent activity events
- **Smart deduplication:** Chrome, Edge, svchost sub-processes don't flood the feed

### Engine 2: Resource Usage Analyzer
**File:** `backend/engines/resource_analyzer.py`

- Collects CPU, RAM, disk I/O, and network connections per process
- Aggregates same-named processes (e.g., multiple chrome.exe instances)
- Ranks processes by resource score (CPU + memory + recency boost)
- Tracks disk read/write in MB per process
- Counts active network connections per PID
- Flags processes with CPU > 90% or RAM > 80% as "High" status
- Recent processes (< 3 minutes old) get priority ranking boost

### Engine 3: AI Activity Attribution Engine
**File:** `backend/engines/ai_attribution.py`

- Detects AI coding tool processes by analyzing process chains
- **Supported tools:** Cursor AI, Claude Code, GitHub Copilot, VS Code/Copilot, Cline, Roo Code, Windsurf, Aider
- Inspects parent process chain (up to 5 levels deep)
- Detects dangerous commands: `git reset --hard`, `rm -rf`, `del /s`, `diskpart`, `format`, `shutdown`, `bcdedit`, `cipher /w`
- Confidence scoring: 70% base + bonuses for shell processes (+10), dangerous commands (+12), parent chain (+5)
- Maximum confidence capped at 98%

### Engine 4: Code Protection Engine
**File:** `backend/engines/code_protection.py`

- Monitors file system events (create, modify, delete, rename) via watchdog
- Sliding window of 12 seconds for burst detection
- **Thresholds:**
  - 20+ deletions in 12s → Mass File Deletion alert
  - 30+ renames in 12s → Mass File Rename alert
  - 50+ modifications in 12s → Bulk File Modification alert
- 45-second cooldown between alerts to prevent flooding
- Recommends snapshot or git backup before large changes
- Detects file extension changes (potential ransomware behavior)

### Engine 5: USB Security Engine
**File:** `backend/engines/usb_security.py`

- Auto-detects USB storage devices via WMI + Windows API + drive enumeration
- **Scans for:**
  - Autorun files (`autorun.inf`) → High risk
  - Suspicious executables (`setup.exe`, `crack.exe`, `keygen.exe`, etc.) → High risk
  - Double-extension tricks (`report.pdf.exe`, `invoice.docx.exe`) → High risk
  - Script files (`.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`) → Medium risk
  - Portable executables (`.exe`, `.scr`, `.com`, `.msi`) → Medium risk
  - Hidden files → Low risk
- Scans up to 1000 files per device
- Threat levels: clean, low, medium, high
- Tracks device insertion and removal events

### Engine 6: Threat Detection Engine
**File:** `backend/detection.py`

- **Process inspection:**
  - Encoded PowerShell execution detection (`-enc`, `-encodedcommand`, `frombase64`, `-windowstyle hidden`)
  - High CPU usage alerts (> 90%)
  - High memory usage alerts (> 80%)
  - Abnormal process resource usage (CPU > 88% or memory > 55%)
  - AI-origin shell process detection
  - Dangerous command execution from AI tools
- **Anomaly Detection:**
  - Isolation Forest ML model (scikit-learn)
  - Trains on last 120 resource snapshots (CPU, memory, processes, connections)
  - Refits model every 30 seconds
  - Contamination rate: 8%
  - Fallback: CPU > 97% or memory > 98% when model unavailable
- **Event creation** with severity (low/medium/high/critical) and score (0-100)

### Engine 7: Log Correlation Engine
**File:** `backend/detection.py` (correlate method)

- Correlates events across multiple detection categories
- Triggers "Correlated Intrusion Pattern" when 3+ distinct categories appear within 5 minutes
- 3-minute cooldown between correlation alerts
- Categories tracked: ai-attribution, authentication, behavior, code-protection, command, correlation, device, file, persistence, process, resource, security, system, usb-security

### Engine 8: Risk Scoring Engine
**File:** `backend/engines/risk.py`

- **Event-based scoring (0-100):**
  - Normal activity: 0 points
  - High CPU/Memory: 5 points
  - USB device: 20 points
  - Suspicious process: 30 points
  - AI-assisted dangerous command: 35 points
  - Mass file deletion: 45 points
  - Registry persistence: 50 points
  - Malware signature: 50 points
  - System error: 55 points
  - USB threat: 55 points
  - Intrusion correlation: 70 points
  - Threat detected: 75 points
  - Ransomware activity: 80 points

- **Time-decay algorithm:**
  - 20-minute rolling window
  - Older events decay proportionally (min 25% weight)
  - Critical events: minimum score 85, multiplied by 1.1
  - High events: minimum score 60
  - Deduplication by (event_type, source, record, pid, title)

- **Risk posture:**
  - 0-19: Safe
  - 20-49: Warning
  - 50-79: High Risk
  - 80-100: Critical

### Engine 9: AI Analysis Module (Local Algorithm)
**File:** `backend/engines/ai_analysis.py`

- **100% local analysis — no external API needed**
- 30-second cache TTL to avoid recomputation
- **Core analysis algorithm:**
  - Temporal burst detection (> 15 events in 10 minutes)
  - Critical/high event categorization with type breakdown
  - USB activity analysis with device identification
  - AI tool attribution with per-tool event counts
  - File system threat analysis
  - Intrusion pattern correlation tracking
  - Resource anomaly reporting
  - Risk score context reporting

- **Interactive Q&A system — routes questions to specialized analyzers:**
  | Question Keywords | Analysis Provided |
  |---|---|
  | process, cpu, memory, ram | Top 5 processes by resource usage + anomaly alerts |
  | risk, threat, danger, score | Score breakdown + severity distribution + high-risk events |
  | usb, device, storage | Device list + scan results + suspicious events |
  | ai, copilot, cursor, claude | Active AI tools + per-tool event counts + high-risk AI |
  | file, delete, modify | File operation alerts with titles and summaries |
  | log, event, windows | Log source breakdown + level distribution + errors |
  | summary, overview, status | Full analysis report with findings + recommendations |

- **Dynamic recommendations based on findings:**
  - USB: scan before opening files
  - AI: approval mode for destructive commands
  - Files: verify no important files deleted
  - Threats: check process chains and registry
  - Resources: top CPU consumers listed
  - High risk: consider endpoint isolation

---

## 5. TELEMETRY COLLECTORS

### Windows Event Log Collectors
**File:** `backend/telemetry.py`

| Log Source | Collector | Details |
|------------|-----------|---------|
| Security | SecurityEventCollector | Authentication events, failed logins, account lockouts, brute force detection (5+ failures in 60s) |
| System | ApplicationLogCollector | Service failures (Event IDs 7000-7036), system errors, warnings |
| Application | ApplicationLogCollector | Application crashes (Event IDs 1000-1008), errors, threat keywords |
| Setup | ApplicationLogCollector | OS installation and update events |
| Windows PowerShell | ApplicationLogCollector | PowerShell execution events |

- **Bootstrap:** Loads 150 recent records on startup (12-hour window)
- **Buffer:** 300 entries in memory (ring buffer)
- **Real-time push:** New entries pushed via WebSocket every ~3 seconds
- **Polling backup:** Frontend also polls `/api/logs/recent` every 4 seconds
- **Suspicious detection:** Errors, service failures, crashes, threat keywords (malware, trojan, ransom, etc.)
- **Alert throttle:** 180-second cooldown per (log_name:event_id:source) to prevent alert flooding

### USB Device Monitor
- Detects USB storage via WMI (Win32_DiskDrive), Windows API (GetDriveTypeW), and psutil
- Tracks device insertion and removal
- Auto-scans on insertion for risky files

### Startup Registry Monitor
- Monitors `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Detects new or modified startup entries (persistence mechanism)

### File Activity Watcher
- Monitors Desktop, Documents, Downloads folders via watchdog
- Ransomware-like behavior detection:
  - 100+ writes in 10 seconds
  - 25+ renames in 10 seconds
  - 15+ extension changes in 10 seconds

---

## 6. API ENDPOINTS

### REST API
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/overview` | Full dashboard overview (score, severity, categories, telemetry status) |
| GET | `/api/alerts?limit=40` | Visible alerts (deduped, noise-filtered) |
| GET | `/api/snapshots?limit=24` | System resource snapshots history |
| GET | `/api/processes` | Current active processes (ranked by resource usage) |
| GET | `/api/activity?limit=120` | Live activity feed (process open/close + USB) |
| GET | `/api/usb/activity?limit=30` | USB-specific activity history |
| GET | `/api/usb/status` | Connected USB devices with scan results |
| GET | `/api/modules` | 9 engine module inventory with status |
| GET | `/api/ai-analysis` | AI analysis report (local algorithm) |
| POST | `/api/ai-question` | Ask questions about system state |
| GET | `/api/telemetry` | Collector health status |
| GET | `/api/logs/recent?limit=80` | Recent Windows event log entries |
| POST | `/api/reset` | Clear all events and reset dashboard |
| GET | `/api/report.csv` | Download incident report as CSV |

### WebSocket
| Endpoint | Messages |
|----------|----------|
| `/ws` | `connected` (initial state), `alert` (new alerts), `snapshot` (resource data), `processes` (active processes), `activity` (open/close events), `logs` (new log entries), `reset` (dashboard cleared) |

---

## 7. FRONTEND DASHBOARD SECTIONS

| Section | Component | Description |
|---------|-----------|-------------|
| Header | `Header.jsx` | Platform name, monitoring status, local time |
| Security Index | `SecurityIndex.jsx` | Risk score gauge (0-100), severity badge |
| Endpoint Status | `EndpointStatus.jsx` | CPU, RAM, disk, network stats |
| Stat Cards | `StatCards.jsx` | Alert counts, AI events, USB events summary |
| Live Activity Feed | `LiveThreatFeed.jsx` | Real-time alerts + process open/close with scrolling (stretches to Alert Timeline level) |
| USB Security | `USBSecurity.jsx` | Connected USB devices with scan status |
| AI Analysis | `AIAnalysis.jsx` | Local algorithm report with findings + recommendations + interactive Q&A |
| Threat Summary | `ThreatSummary.jsx` | Categorized alert counts + action items |
| Alert Timeline | `AlertTimeline.jsx` | Bar chart of alert frequency over time |
| Module Matrix | `ModuleMatrix.jsx` | 9 engine cards with status (Active/Limited) |
| Log Detection | `LogDetection.jsx` | Real-time Windows Event Log stream table (System, Application, Security, Setup, PowerShell) |
| Collector Health | `CollectorHealth.jsx` | Monitoring collector status indicators |
| Active Processes | `ActiveProcesses.jsx` | Ranked process list with CPU, RAM, disk I/O |
| System Activity | `SystemActivity.jsx` | App open/close history |
| Toast | `Toast.jsx` | Alert notification popups |

---

## 8. DATA FLOW

### Real-Time Loop (every ~3 seconds)
1. **Snapshot Collection** → CPU, memory, disk, network stats → stored in SQLite
2. **Process Scan** → detect new/removed apps, inspect for threats → record events
3. **Resource Collection** → aggregate process resources → broadcast to frontend
4. **Telemetry Poll** → Security/System/Application/Setup/PowerShell logs, USB devices, registry, file system
5. **Log Push** → new log entries sent via WebSocket

### Alert Processing Pipeline
1. Engine detects event → `ThreatEngine.create_event()` (assigns score + severity)
2. Monitor applies **time-based dedup** (120s cooldown per event_type + title + process_name)
3. Stored in SQLite database
4. Broadcast via WebSocket to all connected frontend clients
5. If source is USB-related → also added to USB activity feed
6. If severity is high/critical → desktop notification sent
7. `ThreatEngine.correlate()` checks for cross-category intrusion patterns

### Noise Filtering (for display)
- Hidden event types: system_warning, usb_removed, usb_scan_clean, process_started/stopped, normal_activity
- Minimum score threshold: 20 (unless severity is high/critical)
- Query-level deduplication by (event_type, title, summary[:120])

---

## 9. DEDUPLICATION SYSTEMS

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| Process Activity | Name-based grouping | Prevents sub-process flood (Chrome, Edge, etc.) |
| Event Recording | Time-based dedup (120s) | Same event_type + title + process can't fire within 120s |
| Alert Display | Query-level dedup | Same event_type + title + summary[:120] shown once |
| CSV Export | Same query-level dedup | Clean report without duplicates |
| Log Stream | Record + log_name dedup | Frontend merges without duplicates |
| Alert Throttle | 180s per log source:key | Prevents log-based alert flooding |

---

## 10. SCORING & SEVERITY MATRIX

| Event Type | Score | Default Severity |
|------------|-------|-----------------|
| ransomware_activity | 80 | Critical |
| threat_detected | 75 | High |
| intrusion_correlation | 70 | High |
| system_error | 55 | High |
| usb_threat_detected | 55 | High |
| malware_signature | 50 | Medium |
| registry_persistence | 50 | Medium |
| application_crash | 45 | Medium |
| mass_file_deletion | 45 | Medium |
| suspicious_chain | 45 | Medium |
| powershell_encoded | 40 | Medium |
| dangerous_command | 40 | Medium |
| service_failure | 40 | Medium |
| ai_assisted_command | 35 | Medium |
| ai_bulk_file_change | 35 | Medium |
| account_lockout | 35 | Medium |
| mass_file_rename | 35 | Medium |
| suspicious_process | 30 | Medium |
| bulk_file_modification | 30 | Medium |
| usb_scan_suspicious | 30 | Medium |
| anomaly | 25 | Medium |
| usb_device / unknown_usb | 20 | Medium |
| failed_login | 10 | Low |
| high_cpu_usage / high_memory | 5 | Low |

---

## 11. HOW TO RUN

### Prerequisites
- Windows 10/11
- Python 3.10+
- Node.js 18+

### Setup
```bash
# Install backend dependencies
pip install -r requirements.txt

# Install frontend dependencies
cd frontend && npm install && npm run build && cd ..

# Run the application
python -m backend
```

### Access
- Open browser at `http://127.0.0.1:8000`
- Dashboard loads from built frontend (`frontend/dist/`)
- WebSocket connects automatically for real-time updates

### Commands
```bash
# Development mode (frontend hot-reload)
cd frontend && npm run dev

# Production build
cd frontend && npm run build

# Download incident report
# Visit: http://127.0.0.1:8000/api/report.csv

# Reset all alerts
# POST to: http://127.0.0.1:8000/api/reset
```

---

## 12. KEY FEATURES SUMMARY

1. **9 Detection Engines** running concurrently
2. **Real-time WebSocket updates** every ~3 seconds
3. **4 Windows Event Log sources** (Security, System, Application, Setup, PowerShell)
4. **USB Security Scanning** — autorun, executables, scripts, hidden files, double extensions
5. **AI Coding Tool Detection** — Cursor, Claude, Copilot, Cline, Roo Code, Windsurf, Aider
6. **Code Protection** — mass deletion, rename, and modification detection
7. **ML Anomaly Detection** — Isolation Forest trained on local resource patterns
8. **Cross-Category Correlation** — intrusion pattern detection across 3+ categories
9. **Risk Scoring** with time-decay (0-100 scale)
10. **Local AI Analysis** — algorithm-based findings, recommendations, and interactive Q&A
11. **Process Activity Tracking** — name-based grouping (no sub-process noise)
12. **Time-based Dedup** — prevents duplicate alerts across all layers
13. **CSV Incident Report** export
14. **Collector Health Dashboard** — shows status of all monitoring components
15. **Desktop Notifications** for high/critical alerts
16. **Dark theme dashboard** with responsive grid layout
