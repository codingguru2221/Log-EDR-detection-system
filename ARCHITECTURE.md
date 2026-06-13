# AI-Aware EDR Platform Structure

This project is organized as a Python FastAPI endpoint monitor with a React dashboard.

## Backend

- `backend/main.py` exposes the API, WebSocket stream, module inventory, report export, and static dashboard.
- `backend/monitor.py` runs the live endpoint loop for snapshots, process scans, process lifecycle activity, and alert publishing.
- `backend/telemetry.py` collects Windows event logs, USB inventory, registry startup changes, and file activity.
- `backend/detection.py` is the central threat engine used by collectors.
- `backend/engines/risk.py` maps events to the 0-100 Safe / Warning / High Risk / Critical scoring model.
- `backend/engines/ai_attribution.py` identifies AI-tool process chains and dangerous commands.
- `backend/engines/resource_analyzer.py` ranks active processes by CPU, RAM, and disk I/O.
- `backend/engines/system_activity.py` tracks app/process open and close activity.
- `backend/engines/usb_security.py` scans USB mount points for executables, scripts, autorun files, and hidden files.
- `backend/engines/code_protection.py` detects mass deletion, renaming, and bulk modification.
- `backend/engines/ai_analysis.py` creates read-only summaries and recommendations. It does not execute commands, edit files, or control the system.

## Frontend

- `frontend/src/App.jsx` composes the live EDR dashboard.
- `frontend/src/hooks/useDashboard.js` fetches overview, alerts, processes, modules, activity, logs, and AI analysis.
- `frontend/src/components/ModuleMatrix.jsx` shows the nine core EDR modules.
- `frontend/src/components/AIAnalysis.jsx` shows the read-only AI summary.
- `frontend/src/components/SystemActivity.jsx` shows process open/close activity.
- `frontend/src/components/ActiveProcesses.jsx` shows CPU, RAM, disk read/write, and status per process.

## Main API

- `GET /api/overview`
- `GET /api/alerts`
- `GET /api/processes`
- `GET /api/activity`
- `GET /api/modules`
- `GET /api/ai-analysis`
- `GET /api/logs/recent`
- `GET /api/report.csv`
- `POST /api/reset`
- `WS /ws`

