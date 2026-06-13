# TRINETRA SENTINEL — Windows Desktop Notifications & Popups Report

**All notifications appear as WPF popup windows in the bottom-right corner of the screen, even when the browser is closed.**

---

## POPUP DESIGN

```
┌─────────────────────────────────────────┐
│ ● TRINETRA SENTINEL — [SEVERITY LABEL]  │  ← Colored dot + label
│                                          │
│ Alert Title (white, bold)               │  ← Main alert title
│ Alert summary message text here...      │  ← Brief description
└─────────────────────────────────────────┘
   Dark background (#1A1A2E)
   Colored border matching severity
   Auto-closes after 6-8 seconds
```

### Severity Colors & Sounds

| Severity | Border Color | Sound | Auto-Close | Cooldown |
|----------|-------------|-------|------------|----------|
| **CRITICAL** | Red (#FF4444) | Error beep (stop) | 8 seconds | 15 seconds |
| **HIGH** | Orange (#FF8800) | Warning beep (exclamation) | 6 seconds | 30 seconds |
| **MEDIUM** | Yellow (#FFD700) | No sound | 6 seconds | 60 seconds |
| **LOW** | Blue (#4488FF) | No sound | 6 seconds | 120 seconds |

---

## COMPLETE NOTIFICATION LIST

### 1. CRITICAL SEVERITY POPUPS 🔴

| # | Event Type | Popup Title | When It Fires | Score |
|---|-----------|-------------|---------------|-------|
| 1 | `ransomware_activity` | Ransomware-like file activity detected | 100+ file writes, 25+ renames, or 15+ extension changes in 10 seconds | 80 |

**Popup shows:** Rapid file activity details (write count, rename count, extension changes)  
**Sound:** Critical error beep  
**Stays:** 8 seconds  

---

### 2. HIGH SEVERITY POPUPS 🟠

| # | Event Type | Popup Title | When It Fires | Score |
|---|-----------|-------------|---------------|-------|
| 2 | `threat_detected` | Potential threat detected in logs | Threat keywords (malware, trojan, ransom, etc.) found in Windows event logs | 75 |
| 3 | `intrusion_correlation` | Correlated intrusion pattern | 3+ different alert categories within 5 minutes | 70 |
| 4 | `system_error` | Critical system error: [source] | Error-level events from Windows System log | 55 |
| 5 | `usb_threat_detected` | USB threat-like content detected | High-risk files found on USB (autorun.inf, suspicious executables, double extensions) | 55 |
| 6 | `registry_persistence` | Startup registry entry modified | New or changed entry in `HKCU\...\Run` autorun key | 50 |
| 7 | `malware_signature` | *(from threat engine)* | Known malware pattern matched | 50 |

**Popup shows:** Specific threat details and source  
**Sound:** Warning beep  
**Stays:** 6 seconds  

---

### 3. MEDIUM SEVERITY POPUPS 🟡

| # | Event Type | Popup Title | When It Fires | Score |
|---|-----------|-------------|---------------|-------|
| 8 | `application_crash` | Application crash detected: [app name] | Application crash events (Event IDs 1000-1008) in Windows log | 45 |
| 9 | `mass_file_deletion` | Mass file deletion detected | 20+ files deleted in 12 seconds | 45 |
| 10 | `suspicious_chain` | AI-origin shell process detected | Shell process (cmd, PowerShell, bash) traced to AI coding tool parent | 45 |
| 11 | `powershell_encoded` | Encoded PowerShell execution | PowerShell with `-enc`, `-encodedcommand`, `frombase64`, `-windowstyle hidden` | 40 |
| 12 | `dangerous_command` | Dangerous command observed | `rm -rf`, `del /s`, `diskpart`, `format`, `shutdown`, `bcdedit`, etc. | 40 |
| 13 | `service_failure` | Service failure: [service name] | Windows service failure events (Event IDs 7000-7036) | 40 |
| 14 | `ai_assisted_command` | Dangerous command observed | Dangerous command traced to AI tool (Cursor, Claude, Copilot, etc.) | 35 |
| 15 | `ai_bulk_file_change` | *(from AI attribution)* | AI tool triggered bulk file changes | 35 |
| 16 | `mass_file_rename` | Mass file rename detected | 30+ files renamed in 12 seconds | 35 |
| 17 | `account_lockout` | Windows account lockout detected | Event ID 4740 — account locked after repeated failures | 35 |
| 18 | `usb_scan_suspicious` | USB scan found risky files | Medium-risk files on USB (scripts, executables) | 30 |
| 19 | `bulk_file_modification` | Bulk file modification detected | 50+ files modified/created in 12 seconds | 30 |
| 20 | `usb_device` | USB storage device inserted | Any USB storage device connected to the system | 20 |
| 21 | `failed_login` | Repeated login failures detected | 5+ failed Windows logins within 60 seconds (Event ID 4625) | 10 |

**Popup shows:** Event-specific details and context  
**Sound:** None  
**Stays:** 6 seconds  

---

### 4. ALL CRITICAL/HIGH EVENTS (Automatic) 🔴🟠

**Any event** with severity `critical` or `high` automatically triggers a popup, even if not in the list above. This includes:

- Anomaly detection alerts (Isolation Forest ML model)
- High CPU usage (> 90%)
- High memory usage (> 80%)
- Suspicious process resource usage
- Any custom or future event types with high/critical severity

---

## TRIGGER SOURCES (Which Engine Fires Each)

| Engine | Notifications It Triggers |
|--------|--------------------------|
| **System Activity Engine** | Process open/close (web only, no popup) |
| **Resource Analyzer** | High CPU/RAM → popup if severity is high |
| **AI Attribution Engine** | `ai_assisted_command`, `dangerous_command`, `suspicious_chain` |
| **Code Protection Engine** | `mass_file_deletion`, `mass_file_rename`, `bulk_file_modification` |
| **USB Security Engine** | `usb_device`, `usb_scan_suspicious`, `usb_threat_detected` |
| **Threat Detection Engine** | `powershell_encoded`, `suspicious_process`, `high_cpu_usage`, `high_memory_usage`, `anomaly` |
| **Log Correlation Engine** | `intrusion_correlation` |
| **Windows Log Collectors** | `system_error`, `application_crash`, `service_failure`, `threat_detected`, `failed_login`, `account_lockout` |
| **Registry Monitor** | `registry_persistence` |
| **File Watcher** | `ransomware_activity`, `ai_bulk_file_change` |

---

## COOLDOWN SUMMARY (How Often Popups Can Fire)

| Severity | Cooldown | Max Popups Per Hour |
|----------|----------|-------------------|
| Critical | 15 seconds | ~240/hour |
| High | 30 seconds | ~120/hour |
| Medium | 60 seconds | ~60/hour |
| Low | 120 seconds | ~30/hour |

**Note:** Cooldown is per (event_type + title) pair. So different alert types can fire independently without waiting.

---

## EXAMPLE SCENARIOS

### Scenario 1: USB Inserted
```
[POPUP] 🟡 WARNING (Yellow border)
TRINETRA SENTINEL — WARNING
USB storage device inserted
External USB device connected: USB Device (E:). Review the device before opening files.
→ Auto-closes in 6 seconds
```

### Scenario 2: Ransomware-Like Activity
```
[POPUP] 🔴 CRITICAL (Red border) + ERROR SOUND
TRINETRA SENTINEL — CRITICAL
Ransomware-like file activity detected
Rapid file activity crossed the local threshold: 150 writes, 30 renames, 20 extension changes in 10 seconds.
→ Auto-closes in 8 seconds
→ Same popup won't fire again for 15 seconds
```

### Scenario 3: Correlated Intrusion Pattern
```
[POPUP] 🟠 HIGH (Orange border) + WARNING SOUND
TRINETRA SENTINEL — HIGH
Correlated intrusion pattern
Multiple suspicious behaviors were correlated across ai-attribution, process, resource. Review the incident chain immediately.
→ Auto-closes in 6 seconds
```

### Scenario 4: Application Crash
```
[POPUP] 🟡 WARNING (Yellow border)
TRINETRA SENTINEL — WARNING
Application crash detected: chrome.exe
chrome.exe crashed unexpectedly
→ Auto-closes in 6 seconds
```

### Scenario 5: Encoded PowerShell
```
[POPUP] 🟡 WARNING (Yellow border)
TRINETRA SENTINEL — WARNING
Encoded PowerShell execution
An encoded PowerShell command was observed. This technique can hide malicious script behavior.
→ Auto-closes in 6 seconds
```

---

## NOTIFICATION LOG

All notifications are also logged to `notifications.log` in the project root:
```
2026-06-09 12:55:48 - INFO - [CRITICAL] USB Threat Detected | Risky executable found on USB drive E:. Do not open files.
2026-06-09 12:55:48 - INFO - WPF popup sent: [CRITICAL] USB Threat Detected
```

This log persists across restarts and can be used for audit/review.
