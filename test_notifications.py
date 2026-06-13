"""
Trinetra Sentinel — Popup Notification Tester
Run this to test all 21 notification types on your Windows desktop.

Usage:
    python test_notifications.py          # Test all popups (one by one)
    python test_notifications.py critical # Test only critical popups
    python test_notifications.py high     # Test only high severity popups
    python test_notifications.py medium   # Test only medium severity popups
"""

import sys
import time

from backend.notifications import notify

ALL_NOTIFICATIONS = [
    # ── CRITICAL ──────────────────────────────────────────
    {
        "group": "critical",
        "event": {
            "severity": "critical",
            "event_type": "ransomware_activity",
            "title": "Ransomware-like file activity detected",
            "summary": "Rapid file activity crossed the local threshold: 150 writes, 30 renames, 20 extension changes in 10 seconds.",
            "score": 80,
        },
    },

    # ── HIGH ──────────────────────────────────────────────
    {
        "group": "high",
        "event": {
            "severity": "high",
            "event_type": "threat_detected",
            "title": "Potential threat detected in logs",
            "summary": "Threat pattern 'malware' found in Windows Defender log source.",
            "score": 75,
        },
    },
    {
        "group": "high",
        "event": {
            "severity": "high",
            "event_type": "intrusion_correlation",
            "title": "Correlated intrusion pattern",
            "summary": "Multiple suspicious behaviors were correlated across ai-attribution, process, resource. Review the incident chain immediately.",
            "score": 70,
        },
    },
    {
        "group": "high",
        "event": {
            "severity": "high",
            "event_type": "system_error",
            "title": "Critical system error: Microsoft-Windows-Kernel-Power",
            "summary": "The system has rebooted without cleanly shutting down first. This could be caused by the system not responding or crashing.",
            "score": 55,
        },
    },
    {
        "group": "high",
        "event": {
            "severity": "high",
            "event_type": "usb_threat_detected",
            "title": "USB threat-like content detected",
            "summary": "Auto scan found 4 risky file(s) on Kingston USB: 2 high, 2 medium. Do not open files until reviewed.",
            "score": 55,
        },
    },
    {
        "group": "high",
        "event": {
            "severity": "high",
            "event_type": "registry_persistence",
            "title": "Startup registry entry modified",
            "summary": "A startup entry named 'UpdaterService' was created or changed in the current user autorun registry.",
            "score": 50,
        },
    },
    {
        "group": "high",
        "event": {
            "severity": "high",
            "event_type": "malware_signature",
            "title": "Malware signature detected",
            "summary": "Known malware pattern matched in process chain analysis. Immediate action recommended.",
            "score": 50,
        },
    },

    # ── MEDIUM ────────────────────────────────────────────
    {
        "group": "medium",
        "event": {
            "severity": "medium",
            "event_type": "application_crash",
            "title": "Application crash detected: chrome.exe",
            "summary": "Application chrome.exe crashed unexpectedly. Check Windows Application log for details.",
            "score": 45,
        },
    },
    {
        "group": "medium",
        "event": {
            "severity": "medium",
            "event_type": "mass_file_deletion",
            "title": "Mass file deletion detected",
            "summary": "Code protection threshold crossed in 12 seconds: 5 writes, 25 deletions, 0 renames.",
            "score": 45,
        },
    },
    {
        "group": "medium",
        "event": {
            "severity": "medium",
            "event_type": "suspicious_chain",
            "title": "AI-origin shell process detected",
            "summary": "powershell.exe appears to originate from Cursor AI with 87% confidence.",
            "score": 45,
        },
    },
    {
        "group": "medium",
        "event": {
            "severity": "medium",
            "event_type": "powershell_encoded",
            "title": "Encoded PowerShell execution",
            "summary": "An encoded PowerShell command was observed. This technique can hide malicious script behavior.",
            "score": 40,
        },
    },
    {
        "group": "medium",
        "event": {
            "severity": "medium",
            "event_type": "dangerous_command",
            "title": "Dangerous command observed",
            "summary": "rm -rf / was seen from Unknown user or process with 40% confidence.",
            "score": 40,
        },
    },
    {
        "group": "medium",
        "event": {
            "severity": "medium",
            "event_type": "service_failure",
            "title": "Service failure: Windows Update",
            "summary": "Service Windows Update encountered a failure. Check system logs for recovery attempts.",
            "score": 40,
        },
    },
    {
        "group": "medium",
        "event": {
            "severity": "medium",
            "event_type": "ai_assisted_command",
            "title": "Dangerous command observed",
            "summary": "git clean -fd was seen from Cursor AI with 82% confidence.",
            "score": 35,
        },
    },
    {
        "group": "medium",
        "event": {
            "severity": "medium",
            "event_type": "mass_file_rename",
            "title": "Mass file rename detected",
            "summary": "Code protection threshold crossed in 12 seconds: 2 writes, 0 deletions, 35 renames.",
            "score": 35,
        },
    },
    {
        "group": "medium",
        "event": {
            "severity": "medium",
            "event_type": "account_lockout",
            "title": "Windows account lockout detected",
            "summary": "A local or domain account was locked after repeated authentication failures.",
            "score": 35,
        },
    },
    {
        "group": "medium",
        "event": {
            "severity": "medium",
            "event_type": "usb_scan_suspicious",
            "title": "USB scan found risky files",
            "summary": "Auto scan found 3 risky file(s) on SanDisk USB: 0 high, 3 medium. Do not open files until reviewed.",
            "score": 30,
        },
    },
    {
        "group": "medium",
        "event": {
            "severity": "medium",
            "event_type": "bulk_file_modification",
            "title": "Bulk file modification detected",
            "summary": "Code protection threshold crossed in 12 seconds: 55 writes, 0 deletions, 0 renames.",
            "score": 30,
        },
    },
    {
        "group": "medium",
        "event": {
            "severity": "medium",
            "event_type": "usb_device",
            "title": "USB storage device inserted",
            "summary": "External USB device connected: Kingston DataTraveler (E:). Review the device before opening files.",
            "score": 20,
        },
    },
    {
        "group": "medium",
        "event": {
            "severity": "medium",
            "event_type": "failed_login",
            "title": "Repeated login failures detected",
            "summary": "Possible brute force behavior: 8 failed Windows logins observed within 60 seconds.",
            "score": 10,
        },
    },
]


def main():
    # Filter by group if argument provided
    group_filter = sys.argv[1].lower() if len(sys.argv) > 1 else "all"
    
    if group_filter == "all":
        items = ALL_NOTIFICATIONS
    else:
        items = [n for n in ALL_NOTIFICATIONS if n["group"] == group_filter]

    if not items:
        print(f"No notifications found for group '{group_filter}'.")
        print("Available groups: all, critical, high, medium")
        return

    total = len(items)
    print(f"\n{'='*60}")
    print(f"  TRINETRA SENTINEL — Popup Notification Tester")
    print(f"  Testing {total} notification(s) | Filter: {group_filter}")
    print(f"{'='*60}\n")

    for i, item in enumerate(items, 1):
        event = item["event"]
        severity = event["severity"].upper()
        title = event["title"]
        group = item["group"]

        print(f"[{i}/{total}] {severity:8s} | {title}")
        print(f"          Summary: {event['summary'][:80]}...")

        notify(event)

        # Wait between notifications so user can see each popup
        if i < total:
            wait = 4 if group == "critical" else 3
            print(f"          Waiting {wait}s for next popup...\n")
            time.sleep(wait)

    print(f"\n{'='*60}")
    print(f"  All {total} notifications sent!")
    print(f"  Check bottom-right corner of your screen.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
