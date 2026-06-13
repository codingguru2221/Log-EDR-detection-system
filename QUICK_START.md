# 🚀 Quick Start Guide - Real Log Detection

## What You Get

✨ **Real-time suspicious activity detection** with automatic notifications!

Your system will now detect and alert you about:
- 🔴 System crashes and critical errors
- 💥 Application crashes  
- ⚠️ Service failures
- 🛡️ Threat patterns (malware, trojans)
- 🔗 Correlated attack patterns

## Getting Started (2 Steps)

### Step 1: Start the Tool
```powershell
cd "c:\Users\hp5cd\Desktop\hydrabad\Project"
.\run_trinetra.bat
```

Or manually:
```powershell
python -m backend
```

**Expected Output:**
```
INFO:     Uvicorn running on http://127.0.0.1:8000
```

### Step 2: Open Dashboard
```
http://127.0.0.1:8000
```

## What to Look For

### 🎯 Dashboard Sections

1. **Alerts Timeline**
   - Real-time alerts from logs
   - Color-coded by severity
   - Click for details

2. **Collector Health**
   - ✅ `application_logs` → Monitoring System/Application logs
   - ✅ `windows_security` → Monitoring Security log
   - ✅ `file_activity` → Monitoring ransomware patterns
   - ✅ `usb_devices` → Monitoring USB insertions
   - ✅ `startup_registry` → Monitoring persistence

3. **Overall Score**
   - Green: Low threat
   - Yellow: Medium threat
   - Red: High/Critical threat

### 🔔 Notifications

**You'll see 3 types of alerts:**

1. **Windows Toast Popup** (top-right corner)
   - Appears for HIGH/CRITICAL severity events
   - Auto-dismisses after 3-5 seconds
   - Click to dismiss

2. **Dashboard Alert** 
   - Shows in alerts timeline
   - Full details available
   - Exportable to CSV

3. **Notification Log**
   - File: `notifications.log`
   - Permanent record of all alerts
   - Useful for audit trails

## 📊 Alert Examples

### Low Severity (Green)
```
System warning from kernel
Score: 15 points
Action: Informational
```

### Medium Severity (Yellow)  
```
Application crashed: explorer.exe
Score: 45 points
Action: Review in dashboard
```

### High Severity (Red) 🚨
```
Threat detected: Malware pattern found
Score: 75 points
Action: WINDOWS NOTIFICATION + Dashboard alert
```

### Critical Severity (Red) 🚨🚨
```
Correlated intrusion pattern detected
Multiple suspicious behaviors identified
Score: 70+ points
Action: IMMEDIATE NOTIFICATION + Dashboard alert
```

## 💻 Command Reference

### Monitor Notifications in Real-time
```powershell
Get-Content -Path notifications.log -Tail 20 -Wait
```

### Check Recent Events in Event Viewer
```powershell
# System Log
Get-EventLog System -Newest 10 | Select-Object EventID,Source,Message

# Application Log  
Get-EventLog Application -Newest 10 | Select-Object EventID,Source,Message
```

### Test the Tool (Optional)
```powershell
python test_real_log_detection.py
```

## 🔍 Troubleshooting

### No notifications appearing?

**Check 1:** Collector is running
```
Dashboard → Collector Health → application_logs should show "active"
```

**Check 2:** Events are being generated
```
Dashboard → Alerts section should have recent entries
```

**Check 3:** Check notification log
```powershell
Get-Content notifications.log -Tail 5
```

### Collector shows "Limited"?

**Solution:** Run as Administrator
```powershell
# Right-click PowerShell → Run as Administrator
.\run_trinetra.bat
```

### Too many alerts?

**That's normal!** Windows logs can be verbose. The tool is:
- ✅ Filtering only Important events (Error, Warning, Crash)
- ✅ De-duplicating repeated events
- ✅ Suppressing spam with alert cooldowns

## 📈 What Happens When Threats Are Detected

### Single Event
```
User sees: Alert in dashboard + possible notification
System creates: Event with threat score
Database stores: Complete event record
```

### Multiple Events (Correlation)
```
Event 1: Failed login attempts (authentication)
Event 2: Registry modification (persistence)
Event 3: Disk error (system)

System detects: 3+ different threat categories within 5 minutes
Result: ⚠️ CORRELATED INTRUSION PATTERN ALERT
```

## 📝 Log Files

### notifications.log
```
Location: c:\Users\hp5cd\Desktop\hydrabad\Project\notifications.log

Format:
2026-06-07 15:20:35 - CRITICAL - Threat detected in logs | Malware pattern found
2026-06-07 15:18:12 - HIGH - Critical system error | Disk failure detected
2026-06-07 15:15:45 - MEDIUM - Application crash | explorer.exe crashed
```

### trinetra.db
```
Location: c:\Users\hp5cd\Desktop\hydrabad\Project\backend\trinetra.db

Contains:
- All detected events (with full details)
- System snapshots (CPU, memory, processes)
- Event metadata and correlation info
```

### Event Viewer
```
Windows Event Viewer → Windows Logs → System/Application
See the actual events that triggered alerts
```

## 🎯 Real-World Scenarios

### Scenario 1: Ransomware Attack
```
Detected:
  ✓ Rapid file activity (file system monitor)
  ✓ Process using high resources (process monitor)
  ✓ Service failure (log monitor)
  ✓ System errors (log monitor)

Result:
  → Correlation triggered
  → CRITICAL notification sent
  → Dashboard shows full attack chain
```

### Scenario 2: Malware Infection
```
Detected:
  ✓ Application crashes repeatedly (log monitor)
  ✓ Registry persistence attempt (registry monitor)
  ✓ Threat pattern in logs (log monitor)

Result:
  → Multiple alerts generated
  → HIGH severity notifications
  → Incident chain visible in dashboard
```

### Scenario 3: System Maintenance
```
Detected:
  ✓ Service restart (normal)
  ✓ Windows update restart
  ✓ Some application crash (unrelated)

Result:
  → Individual alerts created
  → No correlation (different categories)
  → Dashboard shows as routine maintenance
```

## ✨ Features at a Glance

| Feature | Status | Details |
|---------|--------|---------|
| System Error Detection | ✅ Active | Monitors System Event Log |
| App Crash Detection | ✅ Active | Monitors Application Event Log |
| Threat Pattern Detection | ✅ Active | Keyword matching for malware |
| Windows Notifications | ✅ Active | Toast popups on High/Critical |
| Persistent Logging | ✅ Active | notifications.log file |
| Dashboard Integration | ✅ Active | Real-time WebSocket updates |
| Event Correlation | ✅ Active | Multi-category pattern detection |
| Threat Scoring | ✅ Active | Automatic severity calculation |

## 🚀 Next Steps

1. ✅ **Start the tool** → `.\run_trinetra.bat`
2. ✅ **Open dashboard** → `http://127.0.0.1:8000`
3. ✅ **Monitor alerts** → Watch for new detections
4. ✅ **Check logs** → `notifications.log` for history
5. ✅ **Test system** → Run `python test_real_log_detection.py`

## 📞 Tips

- 💡 Keep dashboard open while working to see alerts live
- 💡 Check notifications.log regularly for audit trail
- 💡 Windows Admin rights recommended for full log access
- 💡 Alert volume depends on system activity level

---

**✨ Your system is now protected with real log detection!**

Real suspicious activity will be immediately detected and reported.
