import hashlib
import re
from pathlib import Path


DANGEROUS_EXTENSIONS = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
HIGH_RISK_NAMES = {
    "autorun.inf",
    "setup.exe",
    "install.exe",
    "update.exe",
    "crack.exe",
    "keygen.exe",
    "payload.exe",
    "loader.exe",
}
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".vbs", ".js"}
EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".com", ".msi"}
DOUBLE_EXTENSION_HINTS = (".pdf.exe", ".doc.exe", ".docx.exe", ".xls.exe", ".xlsx.exe", ".jpg.exe", ".png.exe", ".txt.exe")
BENIGN_HIDDEN_NAMES = {
    ".nomedia",
    ".spotlight-v100",
    ".trashes",
    ".fseventsd",
    "system volume information",
}

# Known malicious file hashes (SHA-256) — curated sample of common malware
# In production, this would be a much larger database or an API call to VirusTotal
KNOWN_MALWARE_HASHES: set[str] = {
    # EICAR test file (standard antivirus test)
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    # Common ransomware / trojan samples (educational reference hashes)
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # empty file (placeholder)
}

# Heuristic patterns that indicate malicious content in scripts/text files
MALICIOUS_PATTERNS = [
    (re.compile(r"Invoke-Mimikatz", re.I), "Mimikatz credential theft tool reference"),
    (re.compile(r"Invoke-Expression\s*\(.*FromBase64", re.I), "Base64-decoded PowerShell execution"),
    (re.compile(r"\$client\s*=\s*New-Object\s+System\.Net\.WebClient", re.I), "WebClient download pattern"),
    (re.compile(r"DownloadFile\s*\(", re.I), "File download call detected"),
    (re.compile(r"\[System\.Reflection\.Assembly\]::Load", re.I), "In-memory assembly loading"),
    (re.compile(r"cmd\.exe\s*/c\s*del\s+/f\s+/q", re.I), "Self-deletion command pattern"),
    (re.compile(r"reg\s+add\s+.*\\CurrentVersion\\Run", re.I), "Registry persistence via Run key"),
    (re.compile(r"schtasks\s+/create", re.I), "Scheduled task creation (persistence)"),
    (re.compile(r"certutil\s+-decode", re.I), "certutil decoding (obfuscation bypass)"),
    (re.compile(r"mshta\s+", re.I), "mshta execution (LOLBins technique)"),
    (re.compile(r"powershell\s+.*-enc\b", re.I), "Encoded PowerShell command"),
    (re.compile(r"WScript\.Shell", re.I), "WScript shell execution in script"),
    (re.compile(r"CreateObject\s*\(\s*\"WScript", re.I), "WScript object creation in VBS"),
    (re.compile(r"net\s+user\s+.*\s+/add", re.I), "User account creation command"),
    (re.compile(r"net\s+localgroup\s+administrators", re.I), "Privilege escalation command"),
]

# PE (Portable Executable) magic bytes
PE_MAGIC = b"MZ"


class USBSecurityEngine:
    def scan_device(self, device: dict, max_files: int = 1000) -> dict:
        root = device.get("mountpoint") or device.get("path")
        if not root:
            return {"scanned": False, "reason": "No mount point available", "findings": [], "virus_scan": {"status": "skipped"}}

        path = Path(root)
        if not path.exists():
            return {"scanned": False, "reason": "Mount point not accessible", "findings": [], "virus_scan": {"status": "skipped"}}

        findings = []
        virus_hits: list[dict] = []
        scanned = 0
        heuristic_hits = 0
        hash_checked = 0
        try:
            for item in path.rglob("*"):
                if scanned >= max_files:
                    break
                if not item.is_file():
                    continue
                scanned += 1
                lower_name = item.name.lower()
                suffix = item.suffix.lower()
                if lower_name in BENIGN_HIDDEN_NAMES:
                    continue
                hidden = lower_name.startswith(".") or self._is_hidden(item)

                # ── Deep virus scan on executables and scripts ──
                if suffix in EXECUTABLE_EXTENSIONS or suffix in SCRIPT_EXTENSIONS or lower_name.endswith(DOUBLE_EXTENSION_HINTS):
                    hash_checked += 1
                    virus_result = self._deep_scan_file(item)
                    if virus_result:
                        virus_hits.append(virus_result)

                # ── Heuristic scan on script/text files ──
                if suffix in SCRIPT_EXTENSIONS or suffix in {".txt", ".inf", ".cfg", ".ini", ".xml", ".html", ".hta"}:
                    heuristic_hits += self._heuristic_scan(item, findings)

                # ── Original rule-based checks ──
                if lower_name == "autorun.inf":
                    findings.append(self._finding(item, "autorun_file", "high", "USB autorun file can launch content automatically on older or misconfigured systems."))
                elif lower_name in HIGH_RISK_NAMES and suffix in EXECUTABLE_EXTENSIONS:
                    findings.append(self._finding(item, "suspicious_executable_name", "high", "Executable has a common malware/social-engineering name."))
                elif any(lower_name.endswith(pattern) for pattern in DOUBLE_EXTENSION_HINTS):
                    findings.append(self._finding(item, "double_extension_executable", "high", "File uses a document/image-looking double extension ending in executable code."))
                elif suffix in SCRIPT_EXTENSIONS:
                    findings.append(self._finding(item, "script_file", "medium", "Script file can execute commands on the endpoint."))
                elif suffix in EXECUTABLE_EXTENSIONS:
                    findings.append(self._finding(item, "executable_file", "medium", "Portable executable or installer found on removable media."))
                elif hidden:
                    findings.append(self._finding(item, "hidden_file", "low", "Hidden file found on removable media."))
        except (OSError, PermissionError) as exc:
            return {
                "scanned": False,
                "reason": type(exc).__name__,
                "findings": findings,
                "files_scanned": scanned,
                "threat_level": self._threat_level(findings, virus_hits),
                "virus_scan": {"status": "partial", "checked": hash_checked, "hits": len(virus_hits), "details": virus_hits},
            }

        return {
            "scanned": True,
            "findings": findings,
            "files_scanned": scanned,
            "threat_level": self._threat_level(findings, virus_hits),
            "virus_scan": {
                "status": "complete",
                "checked": hash_checked,
                "hits": len(virus_hits),
                "heuristic_hits": heuristic_hits,
                "details": virus_hits,
            },
        }

    # ──────────────────────────────────────────────────────────────
    # Deep virus scan — hash + PE header analysis
    # ──────────────────────────────────────────────────────────────
    def _deep_scan_file(self, path: Path) -> dict | None:
        """Scan a single file using hash matching + PE header heuristics."""
        try:
            file_size = path.stat().st_size
            if file_size > 50 * 1024 * 1024:  # skip files > 50 MB
                return None

            # Hash check
            sha256 = hashlib.sha256()
            with open(path, "rb") as f:
                # Read first 1 MB for hash (sufficient for most executables)
                chunk = f.read(1_048_576)
                sha256.update(chunk)
                # If file is larger, read remainder
                while True:
                    more = f.read(1_048_576)
                    if not more:
                        break
                    sha256.update(more)
            file_hash = sha256.hexdigest()

            if file_hash in KNOWN_MALWARE_HASHES:
                return {
                    "path": str(path),
                    "name": path.name,
                    "detection": "known_malware_hash",
                    "severity": "critical",
                    "detail": f"File hash matches known malware signature ({file_hash[:16]}...).",
                    "action": "DELETE immediately — do not execute.",
                }

            # PE header heuristic check for executables
            if path.suffix.lower() in EXECUTABLE_EXTENSIONS and file_size > 512:
                with open(path, "rb") as f:
                    header = f.read(512)
                if header[:2] == PE_MAGIC:
                    # Check for packed/suspicious PE characteristics
                    suspicious_strings = [b"UPX0", b"UPX1", b".themida", b".vmp0"]
                    for sig in suspicious_strings:
                        if sig in header:
                            return {
                                "path": str(path),
                                "name": path.name,
                                "detection": "packed_executable",
                                "severity": "high",
                                "detail": f"Executable appears to be packed with {sig.decode()} packer — commonly used to hide malware.",
                                "action": "Scan with a full antivirus before executing.",
                            }

        except (OSError, PermissionError):
            return None
        return None

    # ──────────────────────────────────────────────────────────────
    # Heuristic scan — pattern matching in script/text files
    # ──────────────────────────────────────────────────────────────
    def _heuristic_scan(self, path: Path, findings: list) -> int:
        """Scan script/text files for malicious command patterns."""
        hits = 0
        try:
            file_size = path.stat().st_size
            if file_size > 2 * 1024 * 1024:  # skip > 2 MB text files
                return 0
            with open(path, "r", errors="ignore", encoding="utf-8") as f:
                content = f.read(min(file_size, 512_000))  # read up to 500 KB

            matched_patterns = []
            for pattern, description in MALICIOUS_PATTERNS:
                if pattern.search(content):
                    matched_patterns.append(description)
                    hits += 1

            if matched_patterns:
                findings.append({
                    "path": str(path),
                    "name": path.name,
                    "extension": path.suffix.lower(),
                    "type": "malicious_pattern",
                    "risk": "high" if len(matched_patterns) >= 2 else "medium",
                    "reason": f"Malicious pattern(s) detected: {'; '.join(matched_patterns[:3])}",
                    "patterns_found": matched_patterns[:5],
                })
        except (OSError, PermissionError, UnicodeDecodeError):
            pass
        return hits

    @staticmethod
    def _finding(path: Path, finding_type: str, risk: str, reason: str) -> dict:
        return {
            "path": str(path),
            "name": path.name,
            "extension": path.suffix.lower(),
            "type": finding_type,
            "risk": risk,
            "reason": reason,
        }

    @staticmethod
    def _threat_level(findings: list[dict], virus_hits: list[dict] | None = None) -> str:
        # Virus hits always critical/high
        if virus_hits:
            if any(v.get("severity") == "critical" for v in virus_hits):
                return "critical"
            return "high"
        if any(item.get("risk") == "high" for item in findings):
            return "high"
        if sum(item.get("risk") == "medium" for item in findings) >= 3:
            return "high"
        if any(item.get("risk") == "medium" for item in findings):
            return "medium"
        if findings:
            return "low"
        return "clean"

    @staticmethod
    def _is_hidden(path: Path) -> bool:
        try:
            return bool(path.stat().st_file_attributes & 2)
        except (AttributeError, OSError):
            return False
