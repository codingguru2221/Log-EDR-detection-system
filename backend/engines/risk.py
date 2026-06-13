from datetime import datetime, timedelta, timezone


EVENT_SCORES = {
    "normal_activity": 0,
    "process_started": 0,
    "process_stopped": 0,
    "high_cpu_usage": 5,
    "high_memory_usage": 5,
    "usb_device": 20,
    "usb_removed": 0,
    "usb_scan_started": 0,
    "usb_scan_clean": 0,
    "usb_scan_suspicious": 30,
    "usb_threat_detected": 55,
    "unknown_usb": 20,
    "suspicious_process": 30,
    "suspicious_chain": 45,
    "powershell_encoded": 40,
    "dangerous_command": 40,
    "ai_assisted_command": 35,
    "ai_bulk_file_change": 35,
    "mass_file_deletion": 45,
    "mass_file_rename": 35,
    "bulk_file_modification": 30,
    "registry_persistence": 50,
    "malware_signature": 50,
    "ransomware_activity": 80,
    "anomaly": 25,
    "failed_login": 10,
    "account_lockout": 35,
    "intrusion_correlation": 70,
    "system_error": 55,
    "system_warning": 0,
    "application_crash": 45,
    "service_failure": 40,
    "threat_detected": 75,
}


def severity_for(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def posture_for(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 50:
        return "High Risk"
    if score >= 20:
        return "Warning"
    return "Safe"


# ──────────────────────────────────────────────────────────────
# Remediation engine — actionable fix steps per threat type
# Each threat has 3 phases: immediate / investigate / prevent
# ──────────────────────────────────────────────────────────────
REMEDIATION_MAP: dict[str, dict] = {
    "ransomware_activity": {
        "priority": 1,
        "threat": "Ransomware activity detected",
        "immediate": [
            "Disconnect the system from ALL networks immediately (unplug Ethernet, disable Wi-Fi, disable Bluetooth).",
            "Do NOT restart or shut down — ransomware may encrypt more files or destroy decryption keys on reboot.",
            "Open Task Manager (Ctrl+Shift+Esc), find the ransomware process, right-click > End Task.",
            "If files are actively being encrypted, pull the power cable as a last resort.",
        ],
        "investigate": [
            "Note the ransom note file name and extension appended to encrypted files (e.g., .locked, .encrypted, .crypt).",
            "Search the file name online to identify the ransomware family and check for free decryptors at NoMoreRansom.org.",
            "Check Event Viewer > Security logs for the initial entry point (failed logins, RDP access, suspicious process).",
            "Check if the ransomware spread to network shares or other connected systems.",
            "Collect the ransomware binary path from the alert metadata for forensic analysis.",
        ],
        "prevent": [
            "Restore all affected files from a known-clean, offline backup (not a network backup that may also be encrypted).",
            "Run a full offline antivirus scan with Windows Defender and a second-opinion scanner (Malwarebytes).",
            "Patch all software, especially RDP, browsers, and Office — most ransomware enters through unpatched exploits.",
            "Enable Controlled Folder Access in Windows Defender: Settings > Virus & threat protection > Ransomware protection.",
            "Disable RDP if not needed, or restrict it to a VPN with MFA.",
            "Implement the 3-2-1 backup rule: 3 copies, 2 media types, 1 offsite/offline.",
        ],
    },
    "intrusion_correlation": {
        "priority": 1,
        "threat": "Correlated intrusion pattern",
        "immediate": [
            "Isolate this endpoint from the network — unplug Ethernet and disable Wi-Fi.",
            "Do NOT log out or lock the screen — preserve the current session for forensic analysis.",
            "Note the timestamp of the first alert in the incident chain.",
        ],
        "investigate": [
            "Open the Live Threat Feed and review the full incident chain — note all correlated event categories.",
            "Check all recently started processes (Task Manager > Details tab) for unknown binaries.",
            "Run `wmic startup list full` in an admin command prompt to find unauthorized auto-start entries.",
            "Open Scheduled Tasks (taskschd.msc) and check for tasks created in the last 24 hours.",
            "Review Security event logs (eventvwr.msc > Windows Logs > Security) for logon type 10 (RDP) or 3 (network) from unknown IPs.",
            "Check the alert metadata for the source process path — trace back to the initial infection vector.",
        ],
        "prevent": [
            "Reset ALL passwords used on this system (local accounts, email, VPN, cloud services).",
            "Revoke all active sessions/tokens for accounts used on this machine.",
            "Enable Windows Defender Attack Surface Reduction (ASR) rules via Group Policy.",
            "Enable Credential Guard and HVCI if hardware supports it.",
            "Consider a full system reimage if the intrusion depth is unclear.",
            "File an incident report with your security team documenting the timeline and affected systems.",
        ],
    },
    "threat_detected": {
        "priority": 2,
        "threat": "General threat detected",
        "immediate": [
            "Open the alert details in the Live Threat Feed — identify the source process name and path.",
            "If the process is unknown, right-click > Open file location in Task Manager to find its origin.",
            "Terminate the flagged process if it is not a recognized system or application process.",
        ],
        "investigate": [
            "Search the process name online to verify if it is legitimate or known malware.",
            "Run Windows Defender full scan: Settings > Privacy & Security > Virus & threat protection > Scan options > Full scan.",
            "Check `msconfig` (System Configuration) > Startup tab for any unauthorized startup entries.",
            "Review recent downloads in your browser history and check the Downloads folder.",
            "Check if any new services were installed: `sc query type= service state= all` in admin CMD.",
        ],
        "prevent": [
            "Ensure Windows Defender real-time protection is ON and cloud-delivered protection is enabled.",
            "Enable SmartScreen for apps and files in Windows Security > App & browser control.",
            "Keep all software updated — enable automatic updates in Windows Update.",
            "Avoid downloading executables from untrusted sources.",
        ],
    },
    "malware_signature": {
        "priority": 1,
        "threat": "Malware signature match",
        "immediate": [
            "Do NOT open, execute, or double-click the flagged file.",
            "Note the exact file path from the alert metadata.",
            "Right-click the file > Scan with Microsoft Defender.",
        ],
        "investigate": [
            "Check the file hash on VirusTotal.com to see detection rates across 70+ antivirus engines.",
            "Check the file's digital signature: right-click > Properties > Digital Signatures tab.",
            "Look at the file creation date — was it created during a suspicious download or USB insertion?",
            "Check if the malware has already executed: look for child processes in Task Manager.",
            "Review the parent process in the alert metadata to trace how the file arrived on the system.",
        ],
        "prevent": [
            "If confirmed malicious, delete the file and empty the Recycle Bin.",
            "Run a full system scan to check for additional infections or persistence mechanisms.",
            "Check registry Run keys and Scheduled Tasks for any entries created by the malware.",
            "Enable Windows Defender PUA (Potentially Unwanted Application) blocking: `Set-MpPreference -PUAProtection Enabled` in admin PowerShell.",
            "If the file came from a USB, scan all other USB drives that were recently connected.",
        ],
    },
    "registry_persistence": {
        "priority": 2,
        "threat": "Registry persistence mechanism",
        "immediate": [
            "Open Registry Editor (regedit.exe) as Administrator.",
            "Navigate to the flagged registry key from the alert metadata.",
            "Take a screenshot of the suspicious entry before deleting it (for forensic records).",
        ],
        "investigate": [
            "Check ALL Run keys: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run and HKLM\\...\\Run.",
            "Check RunOnce keys: same path but \\RunOnce — used for one-time execution on next boot.",
            "Check Services: HKLM\\SYSTEM\\CurrentControlSet\\Services for unauthorized service entries.",
            "Compare the suspicious value's data (executable path) against known-good system files.",
            "Use Autoruns (Sysinternals) for a comprehensive view of all auto-start locations.",
            "Check if the referenced executable actually exists and scan it with Defender.",
        ],
        "prevent": [
            "Delete the suspicious registry entry after documenting it.",
            "Restart the system and verify the suspicious process no longer auto-starts.",
            "Enable Windows Defender ASR rule: Block Office applications from creating child processes.",
            "Monitor registry changes with Process Monitor (Sysinternals) during software installations.",
        ],
    },
    "usb_threat_detected": {
        "priority": 1,
        "threat": "USB threat detected",
        "immediate": [
            "Safely eject the USB drive: right-click the drive in File Explorer > Eject.",
            "Do NOT open any files from the USB on this system.",
            "Disable AutoPlay: Settings > Bluetooth & devices > AutoPlay > turn OFF for all media.",
        ],
        "investigate": [
            "Check the USB Security panel — review the specific threat type (autorun, executable, script, virus).",
            "Note the USB device name and mount point from the alert for tracking.",
            "If possible, scan the USB on an isolated/sandboxed system that is not on the production network.",
            "Check if any files from this USB were already opened or copied to this system.",
            "Review the scan findings list — note all flagged executables, scripts, and autorun files.",
        ],
        "prevent": [
            "Delete all suspicious executables and autorun.inf files from the USB.",
            "Format the USB drive if it is heavily infected (back up only documents/images first).",
            "Re-scan the USB with Windows Defender after cleanup before reconnecting to any system.",
            "Implement USB device control policy: only allow whitelisted USB devices via Group Policy.",
            "Enable Windows Defender's USB scanning on insertion via Group Policy.",
        ],
    },
    "usb_scan_suspicious": {
        "priority": 3,
        "threat": "USB suspicious files found",
        "immediate": [
            "Do not execute any .exe, .bat, .ps1, .vbs, or .js files from the USB.",
            "Do not double-click any file with a double extension (e.g., report.pdf.exe).",
        ],
        "investigate": [
            "Review each flagged file in the USB Security panel — check the risk level and file type.",
            "Check if .exe files have valid digital signatures (right-click > Properties > Digital Signatures).",
            "Look for hidden files: in File Explorer, enable View > Hidden items.",
        ],
        "prevent": [
            "Copy only needed documents and images from the USB — avoid executables entirely.",
            "Scan the entire USB with Windows Defender before transferring any files.",
            "Enable real-time protection to catch any threats if files are accidentally opened.",
        ],
    },
    "suspicious_chain": {
        "priority": 2,
        "threat": "Suspicious process chain",
        "immediate": [
            "Open Task Manager > Details tab and identify both the parent and child processes in the chain.",
            "If the child process is a shell (cmd, powershell, bash), check its command line arguments.",
            "Terminate unrecognized child processes immediately.",
        ],
        "investigate": [
            "Check if the chain was initiated by an AI coding tool (Cursor, Copilot, Claude Code, Cline).",
            "Review the AI tool's recent actions/commands in its terminal or output panel.",
            "Trace the full process tree: parent -> child -> grandchild to understand the execution depth.",
            "Check the process command line from the alert metadata for encoded or obfuscated arguments.",
            "Search the child process name online to determine if it is a known attack tool.",
        ],
        "prevent": [
            "Configure AI coding tools to require explicit approval before executing shell commands.",
            "Restrict PowerShell execution policy: `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`.",
            "Enable PowerShell Constrained Language Mode for non-admin users.",
            "Monitor process creation events with Sysmon (System Monitor from Sysinternals).",
        ],
    },
    "powershell_encoded": {
        "priority": 2,
        "threat": "Encoded PowerShell execution",
        "immediate": [
            "Check the PowerShell process command line in Task Manager > Details > right-click > Select columns > Command line.",
            "If the command is actively running, terminate the PowerShell process.",
        ],
        "investigate": [
            "Decode the Base64 command: copy the encoded string and run `[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ENCODED_STRING'))` in a safe PowerShell session.",
            "Check if the execution was from a trusted admin script, deployment tool, or monitoring agent.",
            "Review PowerShell logs: Event Viewer > Applications and Services Logs > Microsoft > Windows > PowerShell > Operational.",
            "Look for downloaded files in the user's temp directory that match the execution timestamp.",
        ],
        "prevent": [
            "Block encoded PowerShell via Group Policy: enable 'Turn on Module Logging' and 'Turn on Script Block Logging'.",
            "Set PowerShell execution policy to RemoteSigned or AllSigned: `Set-ExecutionPolicy AllSigned`.",
            "Enable AMSI (Antimalware Scan Interface) integration — already on by default in Windows 10/11.",
            "Deploy AppLocker or WDAC to restrict which scripts can run on the system.",
        ],
    },
    "dangerous_command": {
        "priority": 2,
        "threat": "Dangerous command execution",
        "immediate": [
            "Review the full command line from the alert details immediately.",
            "If the command is still running, open Task Manager and terminate the process.",
            "Check if the command modified any files: look at the command's target path.",
        ],
        "investigate": [
            "Determine the command's origin: was it from an AI tool, admin script, or manual input?",
            "Check the process tree to see what launched this command (parent process).",
            "Review the command's effect: did it delete files, modify registry, download content, or change permissions?",
            "Search the command string online to understand its full impact.",
        ],
        "prevent": [
            "Restrict shell access for AI coding tools to approval/ask mode.",
            "Implement command-line auditing: enable 'Include command line in process creation events' in Group Policy.",
            "Create an AppLocker rule to block dangerous commands like `net user /add`, `reg add ...\\Run`, etc.",
            "Educate users to review AI-generated commands before approving execution.",
        ],
    },
    "mass_file_deletion": {
        "priority": 1,
        "threat": "Mass file deletion",
        "immediate": [
            "STOP all write operations to the affected drive — do NOT save new files or install anything.",
            "Check the Recycle Bin immediately — deleted files may still be recoverable.",
            "If using git: run `git status` and `git checkout -- .` to restore tracked files.",
        ],
        "investigate": [
            "Identify the process that triggered the deletion from the alert metadata.",
            "Check the deletion pattern: was it targeted (specific folders) or random (possible ransomware)?",
            "Look for a ransom note or new files with instructions in the affected directories.",
            "Check if the deletion was from an AI coding tool — review its recent actions.",
            "Use Windows File Recovery: `winfr source_drive: destination_drive: /regular` in admin CMD.",
        ],
        "prevent": [
            "Restore deleted files from backup (OneDrive version history, File History, or external backup).",
            "If no backup exists, use Recuva or similar recovery tool BEFORE writing new data to the drive.",
            "Enable File History: Settings > Update & Security > Backup > Add a drive.",
            "Set up regular git commits for project directories to enable easy rollback.",
            "Enable Controlled Folder Access to prevent unauthorized apps from modifying protected folders.",
        ],
    },
    "mass_file_rename": {
        "priority": 2,
        "threat": "Mass file renaming",
        "immediate": [
            "Check if files were renamed with a suspicious extension (e.g., .locked, .encrypted) — this indicates ransomware.",
            "Terminate the renaming process immediately if identified in the alert metadata.",
        ],
        "investigate": [
            "Check if an AI tool or script triggered the rename — review its command history.",
            "Use git to see renamed files: `git status` shows untracked/renamed files.",
            "Compare original and new names — ransomware typically appends an extension or changes the name entirely.",
            "Check if the rename affected system files, user documents, or project files.",
        ],
        "prevent": [
            "Use `git checkout -- .` or restore from backup to fix renamed files.",
            "If ransomware is suspected, follow the ransomware remediation steps.",
            "Enable File History or OneDrive versioning for automatic file version tracking.",
        ],
    },
    "bulk_file_modification": {
        "priority": 2,
        "threat": "Bulk file modification",
        "immediate": [
            "Identify the modifying process from the alert metadata and terminate if unauthorized.",
            "Check `git diff` to see exactly what changed in version-controlled files.",
        ],
        "investigate": [
            "Determine the scope: how many files were modified and in which directories?",
            "Check if modifications were from an AI coding tool performing a refactoring operation.",
            "Look for patterns: were all files of a specific type modified (e.g., all .js files)?",
            "Compare file timestamps to identify the modification window.",
        ],
        "prevent": [
            "Restore from git: `git stash` or `git checkout -- .` to undo modifications.",
            "Restore from backup if git is not available.",
            "Set up git pre-commit hooks to review bulk changes before they are committed.",
            "Configure AI tools to request approval for bulk file operations.",
        ],
    },
    "high_cpu_usage": {
        "priority": 3,
        "threat": "Abnormal CPU usage",
        "immediate": [
            "Open Task Manager (Ctrl+Shift+Esc) > sort by CPU column.",
            "Identify the process consuming >90% CPU from the alert metadata.",
        ],
        "investigate": [
            "Check if the high-CPU process is a known application or a suspicious unknown binary.",
            "Right-click the process > Open file location to find its origin.",
            "Check if the process is a crypto miner: search the process name + 'miner' online.",
            "Look at the CPU history in Task Manager > Performance tab — is it sustained or a spike?",
            "Check if an AI coding tool is running a heavy build/indexing operation.",
        ],
        "prevent": [
            "End Task if the process is not essential and is confirmed suspicious.",
            "Set process priority to Low for known resource-heavy background tasks.",
            "Update or reinstall the application if it consistently uses excessive CPU.",
            "Run a malware scan — persistent high CPU from unknown processes can indicate cryptojacking malware.",
        ],
    },
    "high_memory_usage": {
        "priority": 3,
        "threat": "Abnormal memory usage",
        "immediate": [
            "Open Task Manager > sort by Memory column.",
            "Close unnecessary browser tabs and applications to free memory immediately.",
        ],
        "investigate": [
            "Identify memory-hungry processes from the alert metadata.",
            "Check if a process has a memory leak: sustained high memory that never decreases.",
            "Check Resource Monitor (resmon) > Memory tab for detailed per-process breakdown.",
            "Look for unknown processes using large amounts of RAM.",
        ],
        "prevent": [
            "Restart the leaking process periodically or update it to a newer version.",
            "Add more RAM if the system consistently runs above 85% memory.",
            "Disable unnecessary startup programs that consume memory in the background.",
            "Run a malware scan if unknown processes are consuming significant memory.",
        ],
    },
    "anomaly": {
        "priority": 3,
        "threat": "Behavioral anomaly",
        "immediate": [
            "Review the Endpoint Status panel — check CPU, RAM, disk, and network for unusual values.",
            "Check if a new application was installed or started recently.",
        ],
        "investigate": [
            "Compare current resource usage with your normal usage pattern.",
            "Check the Live Threat Feed for any correlated alerts around the same timestamp.",
            "Review recently started processes for anything unfamiliar.",
            "Check network connections: `netstat -ano` in admin CMD for unexpected outbound connections.",
        ],
        "prevent": [
            "Run a quick scan with Windows Defender to rule out malware.",
            "Uninstall any recently added software that you don't recognize.",
            "Create a system restore point after confirming the system is clean.",
            "Monitor the system for the next 30 minutes — if the anomaly recurs, escalate to a full scan.",
        ],
    },
    "account_lockout": {
        "priority": 2,
        "threat": "Account lockout",
        "immediate": [
            "Verify if you or a known service/application triggered the lockout.",
            "If the lockout was unexpected, do NOT unlock the account yet — investigate first.",
        ],
        "investigate": [
            "Open Event Viewer > Security log > filter for Event ID 4740 (account lockout).",
            "Note the Caller Computer Name and source IP in the event details.",
            "Check if a service or scheduled task is using old credentials and causing repeated failures.",
            "Review the lockout threshold: `net accounts` in admin CMD to see the lockout policy.",
        ],
        "prevent": [
            "Reset the account password if unauthorized access is suspected.",
            "Enable multi-factor authentication (MFA) on all accounts.",
            "Update stored credentials in any services or apps that use this account.",
            "Consider implementing account lockout notifications to get real-time alerts.",
        ],
    },
    "failed_login": {
        "priority": 3,
        "threat": "Failed login attempts",
        "immediate": [
            "Check if the failed logins are from your own mistyped password or a service.",
        ],
        "investigate": [
            "Open Security event log > filter for Event ID 4625 (failed logon).",
            "Note the source IP address and logon type (10=RDP, 3=network, 2=interactive).",
            "Check if the source IP is internal or external — external is more concerning.",
            "Count the number of failed attempts — a high count from one IP suggests brute force.",
        ],
        "prevent": [
            "Block the source IP in Windows Firewall if it's from an unknown external address.",
            "Ensure all accounts have strong passwords (16+ characters, unique).",
            "Enable MFA on all remote access methods (RDP, VPN, web portals).",
            "Consider implementing IP allowlisting for RDP and admin access.",
        ],
    },
    "service_failure": {
        "priority": 3,
        "threat": "Service failure",
        "immediate": [
            "Open services.msc and locate the failed service.",
            "Right-click > Properties > check the Recovery tab — set to 'Restart the Service' on first failure.",
            "Try restarting the service manually: right-click > Start.",
        ],
        "investigate": [
            "Check Application and System event logs for the root cause error code.",
            "Check if the service binary was modified or replaced recently.",
            "Verify the service account has the correct permissions and password.",
            "Check if a Windows Update broke the service — review recently installed updates.",
        ],
        "prevent": [
            "Configure service recovery options: automatic restart on first and second failure.",
            "Set up service monitoring alerts for critical services.",
            "Keep service software updated and test after Windows Updates.",
        ],
    },
    "application_crash": {
        "priority": 4,
        "threat": "Application crash",
        "immediate": [
            "Note the application name and any error dialog that appeared.",
            "Restart the application to see if the crash is reproducible.",
        ],
        "investigate": [
            "Check Application event log for crash details and exception codes.",
            "Check for crash dump files in the application's directory or %LOCALAPPDATA%\\CrashDumps.",
            "Search the error code online to find the specific cause.",
        ],
        "prevent": [
            "Update the application to the latest version.",
            "If recurring, run `sfc /scannow` to check system file integrity.",
            "Reinstall the application if crashes persist after updating.",
        ],
    },
    "system_error": {
        "priority": 3,
        "threat": "System error",
        "immediate": [
            "Open Event Viewer > Windows Logs > System for full error details.",
            "Note the error code and source for further research.",
        ],
        "investigate": [
            "Search the specific error code in Microsoft documentation.",
            "Check if the error correlates with a recent Windows Update or driver installation.",
            "Run `DISM /Online /Cleanup-Image /CheckHealth` to check for component store corruption.",
        ],
        "prevent": [
            "Run `sfc /scannow` and `DISM /Online /Cleanup-Image /RestoreHealth` to repair system files.",
            "Update all device drivers via Device Manager or the manufacturer's website.",
            "Create a system restore point after resolving the issue.",
        ],
    },
}

# Emergency escalation for critical scenarios
EMERGENCY_ESCALATION = {
    "event_type": "emergency_escalation",
    "priority": 0,
    "threat": "EMERGENCY — System compromised",
    "severity": "critical",
    "immediate": [
        "ISOLATE: Disconnect from ALL networks (Ethernet, Wi-Fi, Bluetooth, VPN).",
        "PRESERVE: Do NOT reboot, shut down, or log out — preserve evidence for forensics.",
        "DOCUMENT: Take screenshots of all active alerts, open windows, and suspicious processes.",
        "NOTIFY: Contact your security team or IT department immediately.",
    ],
    "investigate": [
        "Record the timeline: when was the first alert, what was the system doing at that time?",
        "List ALL active alerts in the Live Threat Feed — note event types and severity.",
        "Check network connections: `netstat -ano` for unexpected outbound connections.",
        "Check for data exfiltration: large outbound transfers in Resource Monitor > Network.",
        "Identify the attack vector: USB, phishing email, downloaded file, or RDP brute force?",
    ],
    "prevent": [
        "Reset ALL passwords (local accounts, email, cloud services, banking) FROM A DIFFERENT CLEAN DEVICE.",
        "Revoke all active sessions and tokens from cloud services (Google, Microsoft, AWS, etc.).",
        "Consider a full system reimage/wipe if the compromise depth is unclear.",
        "File a detailed incident report: timeline, affected systems, data at risk, actions taken.",
        "Enable enhanced logging and monitoring after recovery.",
        "Review and harden network segmentation to prevent lateral movement.",
    ],
}


def _extract_context_steps(event: dict) -> list[str]:
    """Generate dynamic context-aware steps from event metadata."""
    steps = []
    meta = event.get("metadata", {})
    process_name = meta.get("name") or meta.get("process_name") or ""
    process_path = meta.get("path") or meta.get("exe") or ""
    cmdline = meta.get("cmdline") or meta.get("command_line") or ""
    pid = meta.get("pid")
    device_name = meta.get("device_id") or meta.get("name") or meta.get("label") or ""
    mountpoint = meta.get("mountpoint") or meta.get("path") or ""
    event_title = event.get("title", "")
    event_summary = event.get("summary", "")

    if process_name and process_name != "Unknown":
        steps.append(f"Target process: **{process_name}** — open Task Manager and locate this process to verify its legitimacy.")
    if process_path:
        steps.append(f"File location: `{process_path}` — right-click this path in File Explorer and scan with Defender.")
    if pid:
        steps.append(f"Process ID: **{pid}** — use `taskkill /PID {pid} /F` in admin CMD to force-terminate if needed.")
    if cmdline and len(str(cmdline)) > 10:
        truncated = str(cmdline)[:120] + ("..." if len(str(cmdline)) > 120 else "")
        steps.append(f"Command executed: `{truncated}` — decode/analyze this command to understand its intent.")
    if device_name and event.get("source") in {"usb-monitor", "usb-security-engine"}:
        steps.append(f"USB device: **{device_name}** — this specific device was involved in the alert.")
    if mountpoint and event.get("source") in {"usb-monitor", "usb-security-engine"}:
        steps.append(f"Drive path: `{mountpoint}` — navigate here to inspect flagged files.")

    return steps[:4]  # Max 4 context steps per event


def build_remediations(events: list[dict], score: int) -> list[dict]:
    """Build prioritized, context-aware remediation steps from active events."""
    seen_types: set[str] = set()
    type_counts: dict[str, int] = {}
    remediations: list[dict] = []
    all_context_steps: list[str] = []

    for event in events:
        etype = event.get("event_type", "")
        type_counts[etype] = type_counts.get(etype, 0) + 1

        if etype in seen_types or etype not in REMEDIATION_MAP:
            continue
        seen_types.add(etype)
        info = REMEDIATION_MAP[etype]

        # Collect context steps from first event of each type
        context = _extract_context_steps(event)
        all_context_steps.extend(context)

        remediations.append({
            "event_type": etype,
            "priority": info["priority"],
            "threat": info["threat"],
            "severity": event.get("severity", "low"),
            "event_count": type_counts.get(etype, 1),
            "immediate": info.get("immediate", []),
            "investigate": info.get("investigate", []),
            "prevent": info.get("prevent", []),
            "context": context,
        })

    # Update event counts for types that appeared multiple times
    for rem in remediations:
        rem["event_count"] = type_counts.get(rem["event_type"], 1)

    # Sort by priority (1=highest)
    remediations.sort(key=lambda r: r["priority"])

    # Emergency escalation for critical risk scores
    if score >= 70:
        emergency = {
            **EMERGENCY_ESCALATION,
            "event_count": 0,
            "context": [
                f"Current risk score is **{score}/100** — this is a critical security situation.",
                f"Total active threats: **{len(remediations)}** different threat types detected.",
                f"Multiple threat categories are active simultaneously — this suggests an ongoing attack.",
            ],
        }
        remediations.insert(0, emergency)

    # General high-risk fallback if score is elevated but no specific matches
    if score >= 50 and len(remediations) <= 1:
        remediations.append({
            "event_type": "general_high_risk",
            "priority": 2,
            "threat": "Elevated risk score — general hardening",
            "severity": "high" if score >= 50 else "medium",
            "event_count": 0,
            "immediate": [
                "Review ALL recent alerts in the Live Threat Feed — click each alert for details.",
                "Run a full Windows Defender scan right now.",
            ],
            "investigate": [
                "Check for unauthorized software installations in Settings > Apps.",
                "Review all startup programs: Task Manager > Startup tab.",
                "Check network connections: `netstat -ano` for unexpected outbound traffic.",
            ],
            "prevent": [
                "Consider isolating this endpoint until the risk score decreases below 30.",
                "Enable all Windows Defender protection features (real-time, cloud, ASR rules).",
                "Ensure all Windows Updates are installed.",
                "Create a system restore point after confirming the system is clean.",
            ],
            "context": [f"Risk score is {score}/100 — elevated threat indicators require a comprehensive security review."],
        })

    return remediations


def compute_risk_score(events: list[dict], window_minutes: int = 20) -> int:
    """Score recent meaningful alerts and decay stale medium-level noise."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=window_minutes)
    skip_types = {"system_warning", "usb_removed", "process_started", "process_stopped", "normal_activity"}
    total = 0.0
    seen_events = set()

    for event in events:
        try:
            ts = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, KeyError):
            continue
        if ts < cutoff:
            continue

        event_type = event.get("event_type")
        metadata = event.get("metadata", {})
        key = (event_type, event.get("source"), metadata.get("record"), metadata.get("pid"), event.get("title"))
        if key in seen_events:
            continue
        seen_events.add(key)

        if event_type in skip_types:
            continue

        score = max(0, min(int(event.get("score", 0)), 100))
        severity = str(event.get("severity", "low")).lower()
        if severity == "low" and score < 20:
            continue

        age_minutes = max((now - ts).total_seconds() / 60.0, 0.0)
        decay = max(0.25, 1.0 - age_minutes / window_minutes)
        if severity == "critical":
            adjusted = max(score, 85) * 1.1
        elif severity == "high":
            adjusted = max(score, 60)
        else:
            adjusted = score * decay
        total += adjusted

    return min(int(total), 100)
