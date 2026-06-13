# Real Log Detection Feature

## 🎯 What's New

Your Trinetra Sentinel tool now has **Real Log Detection** capabilities! It continuously monitors Windows Event Logs to detect suspicious system behavior and alert you immediately.

## ✨ Features Added

### 1. Application & System Event Log Monitoring
The tool now monitors **three key event logs** in real-time:

- **System Log** - Detects system errors, crashes, service failures
- **Application Log** - Detects application crashes and unusual behavior
- **Security Log** - Already monitoring authentication events (brute force, lockouts)

**Monitored Events:**
```
✓ Critical System Errors (Event Type 1)
✓ System Warnings (Event Type 2)
✓ Application Crashes (Event ID 1000)
✓ Service Failures (Event IDs 7034, 7035, 7036)
✓ Threat Patterns (malware/trojan keywords detected)
```

### 2. New Event Types

| Event Type | Severity | Score | Meaning |
|-----------|----------|-------|---------|
| `system_error` | Medium | 55 | Critical system errors detected |
| `system_warning` | Low | 15 | Non-critical system warnings |
| `application_crash` | Medium | 45 | Application crashed unexpectedly |
| `service_failure` | Medium | 40 | Windows service failed |
| `threat_detected` | **High** | 75 | Malware/threat patterns detected |

### 3. Smart Notifications

**Automatic alerts on HIGH & CRITICAL severity events:**

- 🔔 **Windows Toast Notifications** - System-level alerts (non-blocking)
- 📝 **Persistent Log** - `notifications.log` records all alerts
- ⚡ **Real-time Dashboard Updates** - WebSocket live streaming

**Alert Examples:**
```
Critical system error from kernel driver
Application crash: explorer.exe
Service failure: Windows Update service
Threat detected: Potential malware pattern in logs
```

### 4. Threat Scoring & Severity Levels

The tool automatically calculates threat severity:

```
Score > 100  → CRITICAL (immediate action needed)
Score > 60   → HIGH (review immediately)
Score > 30   → MEDIUM (investigate)
Score ≤ 30   → LOW (informational)
```

Multiple suspicious events are **correlated** to identify intrusion patterns.

## 📊 Dashboard Integration

All new log detection events appear in the dashboard:

- **Timeline View** - All alerts sorted by time
- **Alert Summary** - Count by category and severity
- **Collector Health** - Shows which log sources are active
- **Live Updates** - Real-time WebSocket streaming

### Collector Status
```
✓ windows_security → Active (authentication monitoring)
✓ application_logs → Active (system & app log monitoring)
✓ file_activity    → Active (ransomware detection)
✓ usb_devices      → Active (USB tracking)
✓ startup_registry → Active (persistence detection)
```

## 🔧 How It Works

### Real-time Log Polling
```
Every 5 seconds:
  1. Check System Event Log for new events
  2. Check Application Event Log for new events
  3. Parse and analyze each event
  4. Create threat scores
  5. Send notifications if severity > threshold
  6. Update dashboard
```

### Detection Logic
```
IF event is critical error/crash/service failure/threat:
  ├─ Create event with threat score
  ├─ Set severity level
  ├─ Log to notifications.log
  ├─ Send notification (if High/Critical)
  ├─ Broadcast to dashboard
  └─ Correlate with other recent events
```

### Correlation Detection
When **3+ different threat categories** occur within **5 minutes**:
- 🚨 Creates "Intrusion Pattern" alert
- 📊 Score boost (70 points)
- 🔔 Critical notification sent

## 📝 Notification Log

Persistent record of all notifications in `notifications.log`:

```
2026-06-07 20:15:33 - CRITICAL - Threat detected in logs | Malware pattern found
2026-06-07 20:14:12 - HIGH - Critical system error: kernel driver | Disk failure
2026-06-07 20:12:45 - MEDIUM - Application crash: explorer.exe | Unexpected exit
```

## 🎯 Common Use Cases

### Case 1: Ransomware Detection
```
Detects rapid file writes + service failures + system errors
→ Triggers correlation alert
→ Sends CRITICAL notification
→ Escalates severity to RED
```

### Case 2: Malware Infection
```
Application crashes + threat patterns in logs
+ Registry persistence attempts
→ Multiple alerts correlated
→ HIGH severity notification
→ Dashboard shows incident chain
```

### Case 3: System Issues
```
Disk errors + service failures (but no suspicious activity)
→ MEDIUM severity alerts
→ Informational notifications
→ No correlation (only system health)
```

## 📦 Installation

No additional installation needed! The feature uses:
- ✅ `pywin32` (already in requirements.txt)
- ✅ Python standard library

Just run as usual:
```powershell
python -m backend
# or
.\run_trinetra.bat
```

## 🔍 Verification

Check that logs are being monitored:

1. **Dashboard** - Go to http://127.0.0.1:8000
2. **Collector Health** - Look for "application_logs" status
3. **Notifications** - Check for recent alerts
4. **Log File** - Look for `notifications.log`

## 💡 Tips

### High Alert Volume?
System logs can be verbose. To reduce noise:
- Alerts are only created for **Error** and **Warning** events
- Service failures trigger only on specific event IDs
- Threat detection uses keyword matching

### Windows Log Permissions?
If you see "Limited" status on application_logs:
- Run tool as Administrator
- Or configure Windows Event Log permissions

### Check Logs Manually?
```powershell
# PowerShell
Get-EventLog System -Newest 10 -EntryType Error
Get-EventLog Application -Newest 10 -EntryType Error
```

## 🚀 Future Enhancements

Planned features for next release:
- [ ] Network anomaly detection (port scanning, DoS)
- [ ] Process genealogy tracking
- [ ] Custom rule engine
- [ ] Email/SMS alerts
- [ ] SIEM integration

## 📞 Support

For issues or questions:
1. Check `notifications.log` for error details
2. Verify Event Log permissions
3. Review dashboard "Collector Health" panel

---

**✨ Your system is now under real-time log surveillance!**
