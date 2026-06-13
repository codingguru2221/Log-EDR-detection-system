"""
MITRE ATT&CK Mapper
-------------------
Maps Trinetra Sentinel event types to MITRE ATT&CK techniques.
This is a rule-based mapper that infers relevant TTPs from detected behaviors.
"""

# Mapping of Trinetra event_types to MITRE ATT&CK techniques
MITRE_ATTACK_MAP: dict[str, list[dict]] = {
    "powershell_encoded": [
        {
            "technique_id": "T1059.001",
            "name": "PowerShell",
            "tactic": "Execution",
            "description": "Adversaries abuse PowerShell commands and scripts for execution, often using encoded commands to hide malicious intent.",
            "reference": "https://attack.mitre.org/techniques/T1059/001/",
        },
        {
            "technique_id": "T1027",
            "name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
            "description": "Adversaries attempt to make executables or commands difficult to analyze through encoding (e.g., Base64).",
            "reference": "https://attack.mitre.org/techniques/T1027/",
        },
    ],
    "suspicious_chain": [
        {
            "technique_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "description": "AI-originated shell process chains indicate command execution potentially initiated by automated tools.",
            "reference": "https://attack.mitre.org/techniques/T1059/",
        },
        {
            "technique_id": "T1204",
            "name": "User Execution",
            "tactic": "Execution",
            "description": "An adversary may rely upon specific actions by a user to gain execution through AI-assisted or user-approved commands.",
            "reference": "https://attack.mitre.org/techniques/T1204/",
        },
    ],
    "registry_persistence": [
        {
            "technique_id": "T1547.001",
            "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
            "tactic": "Persistence",
            "description": "Adversaries establish persistence by adding programs to Registry Run keys or the Startup folder so they execute on logon.",
            "reference": "https://attack.mitre.org/techniques/T1547/001/",
        },
        {
            "technique_id": "T1547",
            "name": "Boot or Logon Autostart Execution",
            "tactic": "Persistence",
            "description": "Adversaries configure system settings to automatically execute a program during system boot or logon.",
            "reference": "https://attack.mitre.org/techniques/T1547/",
        },
    ],
    "failed_login": [
        {
            "technique_id": "T1110.001",
            "name": "Brute Force: Password Guessing",
            "tactic": "Credential Access",
            "description": "Adversaries with no prior knowledge of legitimate credentials attempt to gain access by guessing passwords.",
            "reference": "https://attack.mitre.org/techniques/T1110/001/",
        },
    ],
    "account_lockout": [
        {
            "technique_id": "T1110",
            "name": "Brute Force",
            "tactic": "Credential Access",
            "description": "Repeated failed login attempts leading to account lockout indicate brute-force password attacks.",
            "reference": "https://attack.mitre.org/techniques/T1110/",
        },
    ],
    "ransomware_activity": [
        {
            "technique_id": "T1486",
            "name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "description": "Adversaries encrypt data on target systems to interrupt availability to system and network resources.",
            "reference": "https://attack.mitre.org/techniques/T1486/",
        },
        {
            "technique_id": "T1490",
            "name": "Inhibit System Recovery",
            "tactic": "Impact",
            "description": "Adversaries delete or remove built-in operating system data and turn off services to inhibit system recovery.",
            "reference": "https://attack.mitre.org/techniques/T1490/",
        },
    ],
    "mass_file_deletion": [
        {
            "technique_id": "T1485",
            "name": "Data Destruction",
            "tactic": "Impact",
            "description": "Adversaries destroy data to disrupt availability to system and network resources.",
            "reference": "https://attack.mitre.org/techniques/T1485/",
        },
        {
            "technique_id": "T1070.004",
            "name": "Indicator Removal on Host: File Deletion",
            "tactic": "Defense Evasion",
            "description": "Adversaries delete files left behind by their operations to minimize their footprint.",
            "reference": "https://attack.mitre.org/techniques/T1070/004/",
        },
    ],
    "mass_file_rename": [
        {
            "technique_id": "T1486",
            "name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "description": "Mass file renaming with suspicious extensions is characteristic of ransomware encryption.",
            "reference": "https://attack.mitre.org/techniques/T1486/",
        },
    ],
    "bulk_file_modification": [
        {
            "technique_id": "T1565.001",
            "name": "Data Manipulation: Stored Data Manipulation",
            "tactic": "Impact",
            "description": "Adversaries insert, delete, or manipulate data at rest to influence outcomes or cover tracks.",
            "reference": "https://attack.mitre.org/techniques/T1565/001/",
        },
    ],
    "intrusion_correlation": [
        {
            "technique_id": "T1078",
            "name": "Valid Accounts",
            "tactic": "Persistence / Privilege Escalation",
            "description": "Correlated multi-vector intrusion patterns often indicate use of compromised credentials across multiple system areas.",
            "reference": "https://attack.mitre.org/techniques/T1078/",
        },
        {
            "technique_id": "T1053",
            "name": "Scheduled Task/Job",
            "tactic": "Persistence / Execution",
            "description": "Multi-stage attacks often use scheduled tasks to maintain persistence and execute payloads.",
            "reference": "https://attack.mitre.org/techniques/T1053/",
        },
    ],
    "dangerous_command": [
        {
            "technique_id": "T1059.003",
            "name": "Command and Scripting Interpreter: Windows Command Shell",
            "tactic": "Execution",
            "description": "Dangerous system-level commands executed through cmd.exe or similar interpreters.",
            "reference": "https://attack.mitre.org/techniques/T1059/003/",
        },
    ],
    "ai_assisted_command": [
        {
            "technique_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "description": "Commands generated or assisted by AI coding tools, potentially with elevated privilege.",
            "reference": "https://attack.mitre.org/techniques/T1059/",
        },
    ],
    "usb_threat_detected": [
        {
            "technique_id": "T1091",
            "name": "Replication Through Removable Media",
            "tactic": "Lateral Movement",
            "description": "Adversaries move onto systems by copying malware to removable media and taking advantage of Autorun features.",
            "reference": "https://attack.mitre.org/techniques/T1091/",
        },
        {
            "technique_id": "T1052",
            "name": "Exfiltration Over Physical Medium",
            "tactic": "Exfiltration",
            "description": "Adversaries exfiltrate data via physical media such as USB drives.",
            "reference": "https://attack.mitre.org/techniques/T1052/",
        },
    ],
    "usb_scan_suspicious": [
        {
            "technique_id": "T1091",
            "name": "Replication Through Removable Media",
            "tactic": "Lateral Movement",
            "description": "Suspicious files on USB media indicate potential for lateral movement via removable media.",
            "reference": "https://attack.mitre.org/techniques/T1091/",
        },
    ],
    "malware_signature": [
        {
            "technique_id": "T1204.002",
            "name": "User Execution: Malicious File",
            "tactic": "Execution",
            "description": "Known malware signatures detected indicate malicious files that may execute upon user interaction.",
            "reference": "https://attack.mitre.org/techniques/T1204/002/",
        },
    ],
    "suspicious_process": [
        {
            "technique_id": "T1055",
            "name": "Process Injection",
            "tactic": "Defense Evasion / Privilege Escalation",
            "description": "Abnormal resource usage by processes may indicate process injection or hollowing techniques.",
            "reference": "https://attack.mitre.org/techniques/T1055/",
        },
    ],
    "threat_detected": [
        {
            "technique_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "description": "General threat detection often correlates with command execution techniques.",
            "reference": "https://attack.mitre.org/techniques/T1059/",
        },
    ],
}

# Aggregate MITRE tactics that may be active based on current events
TACTIC_SUMMARY = {
    "Reconnaissance": ["T1592", "T1595"],
    "Resource Development": ["T1583", "T1587"],
    "Initial Access": ["T1190", "T1133", "T1091"],
    "Execution": ["T1059", "T1204", "T1053"],
    "Persistence": ["T1547", "T1053", "T1078"],
    "Privilege Escalation": ["T1055", "T1548"],
    "Defense Evasion": ["T1027", "T1070", "T1055"],
    "Credential Access": ["T1110"],
    "Discovery": ["T1082", "T1083"],
    "Lateral Movement": ["T1091", "T1021"],
    "Collection": ["T1005", "T1113"],
    "Command and Control": ["T1071", "T1105"],
    "Exfiltration": ["T1052", "T1048"],
    "Impact": ["T1486", "T1485", "T1490", "T1565"],
}


def map_events_to_mitre(events: list[dict]) -> list[dict]:
    """Map a list of Trinetra events to MITRE ATT&CK techniques.

    Returns a deduplicated list of matched techniques with counts.
    """
    seen_ids: set[str] = set()
    techniques: list[dict] = []

    for event in events:
        event_type = event.get("event_type", "")
        if event_type not in MITRE_ATTACK_MAP:
            continue
        for technique in MITRE_ATTACK_MAP[event_type]:
            tid = technique["technique_id"]
            if tid not in seen_ids:
                seen_ids.add(tid)
                techniques.append({
                    **technique,
                    "matched_events": [event_type],
                    "event_count": 1,
                })
            else:
                # Update count for already-seen technique
                for t in techniques:
                    if t["technique_id"] == tid and event_type not in t["matched_events"]:
                        t["matched_events"].append(event_type)
                        t["event_count"] += 1

    return techniques


def get_active_tactics(techniques: list[dict]) -> list[str]:
    """From matched techniques, return a list of active MITRE tactics."""
    tactics: set[str] = set()
    for t in techniques:
        tactic = t.get("tactic", "")
        for part in tactic.split("/"):
            tactics.add(part.strip())
    return sorted(tactics)


def build_mitre_summary(events: list[dict]) -> dict:
    """Full MITRE ATT&CK summary for current event stream."""
    techniques = map_events_to_mitre(events)
    tactics = get_active_tactics(techniques)
    total_matches = sum(t["event_count"] for t in techniques)
    return {
        "techniques": techniques,
        "active_tactics": tactics,
        "total_matches": total_matches,
        "framework": "MITRE ATT&CK v14",
    }
