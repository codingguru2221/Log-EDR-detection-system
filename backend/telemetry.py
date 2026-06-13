from __future__ import annotations

import ctypes
import os
import platform
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psutil

from .detection import ThreatEngine
from .engines.code_protection import CodeProtectionEngine
from .engines.usb_security import USBSecurityEngine

try:
    import win32evtlog
except ImportError:
    win32evtlog = None

try:
    import winreg
except ImportError:
    winreg = None

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    FileSystemEventHandler = object
    Observer = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


EVENT_TYPE_NAMES = {
    1: "error",
    2: "warning",
    4: "information",
    8: "audit_success",
    16: "audit_failure",
}

BOOTSTRAP_LOG_COUNT = 150  # seed dashboard with recent real records
BOOTSTRAP_MAX_AGE_MINUTES = 720  # 12 hours for richer initial view


def event_timestamp(item) -> str:
    """Windows Event Log TimeGenerated — return local time ISO string."""
    try:
        ts = item.TimeGenerated
        if ts.tzinfo is None:
            # pywin32 returns local naive datetime
            return ts.isoformat()
        return ts.astimezone().replace(tzinfo=None).isoformat()
    except Exception:
        return datetime.now().isoformat()


def is_recent_event(item, max_age_minutes: int = 2) -> bool:
    try:
        ts = item.TimeGenerated
        if ts.tzinfo is not None:
            ts = ts.astimezone().replace(tzinfo=None)
        age = (datetime.now() - ts).total_seconds()
        return age <= max_age_minutes * 60
    except Exception:
        return False


THREAT_KEYWORDS = (
    "threat",
    "malware",
    "trojan",
    "virus",
    "ransom",
    "encrypt",
    "crypto",
    "payload",
    "backdoor",
    "exploit",
    "unauthorized",
    "credential",
    "rootkit",
    "spyware",
)

SERVICE_FAILURE_IDS = {7000, 7001, 7009, 7011, 7031, 7032, 7034, 7035, 7036}
APPLICATION_CRASH_IDS = {1000, 1001, 1002, 1008}


def normalize_event_message(item) -> str:
    inserts = list(item.StringInserts or [])
    message = " ".join(str(value) for value in inserts if value)
    if not message:
        return getattr(item, "SourceName", "").strip()
    return message


def message_contains_threat(message: str) -> bool:
    normalized = message.lower()
    return any(keyword in normalized for keyword in THREAT_KEYWORDS)


class LogStreamBuffer:
    """Ring buffer of recent Windows event log entries for the live dashboard."""

    def __init__(self, maxlen: int = 300):
        self.entries: deque[dict] = deque(maxlen=maxlen)
        self.total_scanned = 0
        self._seq = 0  # monotonic sequence counter for incremental reads
        self.lock = threading.Lock()

    def add(self, entry: dict):
        with self.lock:
            self.total_scanned += 1
            self._seq += 1
            entry["_seq"] = self._seq
            self.entries.appendleft(entry)

    def list(self, limit: int = 50) -> list[dict]:
        with self.lock:
            return [{k: v for k, v in e.items() if k != "_seq"} for e in list(self.entries)[:limit]]

    def entries_since(self, seq: int, limit: int = 100) -> tuple[list[dict], int]:
        """Return entries added after the given sequence number + latest seq."""
        with self.lock:
            new = [e for e in self.entries if e.get("_seq", 0) > seq][:limit]
            return new, self._seq

    def stats(self) -> dict:
        with self.lock:
            return {"total_scanned": self.total_scanned, "buffered": len(self.entries), "seq": self._seq}


def log_entry_from_item(item, log_name: str, suspicious: bool = False) -> dict:
    event_id = item.EventID & 0xFFFF
    inserts = list(item.StringInserts or [])
    message = " ".join(inserts) if inserts else f"Event ID {event_id}"
    return {
        "timestamp": event_timestamp(item),
        "log_name": log_name,
        "event_id": event_id,
        "source": item.SourceName or "Unknown",
        "level": EVENT_TYPE_NAMES.get(item.EventType, "information"),
        "message": message[:300],
        "suspicious": suspicious,
        "record": item.RecordNumber,
    }


def bootstrap_log_records(handle, last_record: int, oldest: int, count: int) -> list:
    if BOOTSTRAP_LOG_COUNT <= 0 or count <= 0:
        return []
    start = max(oldest, last_record - BOOTSTRAP_LOG_COUNT + 1)
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
    try:
        items = list(win32evtlog.ReadEventLog(handle, flags, start))
        return [item for item in items if is_recent_event(item, BOOTSTRAP_MAX_AGE_MINUTES)]
    except Exception:
        return []


class AlertThrottle:
    def __init__(self, cooldown_seconds: float = 180.0):
        self.cooldown = cooldown_seconds
        self.last_seen: dict[str, float] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        if now - self.last_seen.get(key, 0) < self.cooldown:
            return False
        self.last_seen[key] = now
        return True


class SecurityEventCollector:
    def __init__(self, engine: ThreatEngine, emit, set_status, log_stream: LogStreamBuffer):
        self.engine = engine
        self.emit = emit
        self.set_status = set_status
        self.log_stream = log_stream
        self.last_record = None
        self.failures = deque()
        self.last_brute_force_alert = 0.0

    def poll(self):
        if platform.system() != "Windows":
            self.set_status("windows_security", "unavailable", "Windows only")
            return
        if not win32evtlog:
            self.set_status("windows_security", "unavailable", "Install pywin32")
            return
        handle = None
        try:
            handle = win32evtlog.OpenEventLog(None, "Security")
            if self.last_record is None:
                oldest = win32evtlog.GetOldestEventLogRecord(handle)
                count = win32evtlog.GetNumberOfEventLogRecords(handle)
                self.last_record = oldest + count - 1
                for item in bootstrap_log_records(handle, self.last_record, oldest, count):
                    self._capture(item, emit_alert=False)
                self.set_status("windows_security", "active", "Security log connected (live stream)")
                return
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
            events = win32evtlog.ReadEventLog(handle, flags, self.last_record + 1)
            while events:
                for item in events:
                    self.last_record = max(self.last_record, item.RecordNumber)
                    self._capture(item)
                events = win32evtlog.ReadEventLog(handle, flags, self.last_record + 1)
            self.set_status("windows_security", "active", "Monitoring authentication events")
        except Exception as exc:
            self.set_status("windows_security", "limited", f"Security log access unavailable: {type(exc).__name__}")
        finally:
            if handle:
                win32evtlog.CloseEventLog(handle)

    def _capture(self, item, emit_alert: bool = True):
        event_id = item.EventID & 0xFFFF
        suspicious = event_id in (4625, 4740, 4648, 4672)
        self.log_stream.add(log_entry_from_item(item, "Security", suspicious))
        if emit_alert:
            self._inspect(item, event_id)

    def _inspect(self, item, event_id: int | None = None):
        if event_id is None:
            event_id = item.EventID & 0xFFFF
        inserts = list(item.StringInserts or [])
        metadata = {"event_id": event_id, "record": item.RecordNumber}
        if inserts:
            metadata["account"] = inserts[5] if len(inserts) > 5 else inserts[0]
        if event_id == 4625:
            now = time.monotonic()
            self.failures.append(now)
            while self.failures and now - self.failures[0] > 60:
                self.failures.popleft()
            count = len(self.failures)
            if count >= 5 and now - self.last_brute_force_alert > 60:
                self.last_brute_force_alert = now
                severity_text = "High-confidence" if count >= 20 else "Possible"
                event = self.engine.create_event(
                    "failed_login",
                    "Repeated login failures detected",
                    f"{severity_text} brute force behavior: {count} failed Windows logins observed within 60 seconds.",
                    "authentication",
                    source="windows-security-log",
                    metadata={**metadata, "failures_in_60s": count},
                )
                if count >= 20:
                    event["score"], event["severity"] = 70, "high"
                self.emit(event)
        elif event_id == 4740:
            self.emit(self.engine.create_event(
                "account_lockout",
                "Windows account lockout detected",
                "A local or domain account was locked after repeated authentication failures.",
                "authentication",
                source="windows-security-log",
                metadata=metadata,
            ))


class USBCollector:
    def __init__(self, engine: ThreatEngine, emit, set_status, log_stream):
        self.engine = engine
        self.emit = emit
        self.set_status = set_status
        self.log_stream = log_stream
        self.devices = None
        self.scanner = USBSecurityEngine()

    def poll(self):
        try:
            devices = self._inventory()
            if self.devices is None:
                self.devices = devices
                self.set_status("usb_devices", "active", f"Tracking {len(devices)} USB storage device(s)")
                for device in devices.values():
                    self._scan_and_emit(device, action="present")
                return
            for key, device in devices.items():
                if key not in self.devices:
                    event = self.engine.create_event(
                        "usb_device",
                        "USB storage device inserted",
                        f"External USB device connected: {device['name']}. Review the device before opening files.",
                        "device",
                        source="usb-monitor",
                        metadata=device,
                    )
                    self.emit(event)
                    self.log_stream.add(self._make_usb_log_entry(event, "Inserted"))
                    self._scan_and_emit(device, action="inserted")
            for key, device in self.devices.items():
                if key not in devices:
                    event = self.engine.create_event(
                        "usb_removed",
                        "USB storage device removed",
                        f"External USB device disconnected: {device['name']}.",
                        "device",
                        source="usb-monitor",
                        metadata=device,
                    )
                    self.emit(event)
                    self.log_stream.add(self._make_usb_log_entry(event, "Removed"))
            self.devices = devices
            self.set_status("usb_devices", "active", f"Tracking {len(devices)} USB storage device(s)")
        except Exception as exc:
            self.set_status("usb_devices", "limited", f"USB inventory unavailable: {type(exc).__name__}")

    def _scan_and_emit(self, device: dict, action: str = "inserted"):
        self.emit(self.engine.create_event(
            "usb_scan_started",
            "USB scan started",
            f"External device {action}: scanning {device.get('name', 'USB device')} for risky executables, scripts, autorun files, and hidden files.",
            "usb-security",
            source="usb-security-engine",
            metadata={"device": device, "action": action},
        ))
        result = self.scanner.scan_device(device)
        findings = result.get("findings", [])
        if findings:
            threat_level = result.get("threat_level", "medium")
            high_count = sum(item.get("risk") == "high" for item in findings)
            medium_count = sum(item.get("risk") == "medium" for item in findings)
            event_type = "usb_threat_detected" if threat_level == "high" else "usb_scan_suspicious"
            event = self.engine.create_event(
                event_type,
                "USB threat-like content detected" if threat_level == "high" else "USB scan found risky files",
                (
                    f"Auto scan found {len(findings)} risky file(s) on {device.get('name', 'USB device')}: "
                    f"{high_count} high, {medium_count} medium. Do not open files until reviewed."
                ),
                "usb-security",
                source="usb-security-engine",
                metadata={"device": device, "scan": result},
            )
            if threat_level == "high":
                event["severity"] = "high"
        else:
            event = self.engine.create_event(
                "usb_scan_clean",
                "USB scan completed",
                f"Auto scan completed for {device.get('name', 'USB device')} with no risky files found.",
                "usb-security",
                source="usb-security-engine",
                metadata={"device": device, "scan": result},
            )
        self.emit(event)

    @staticmethod
    def _inventory() -> dict:
        devices = {}
        if platform.system() == "Windows":
            try:
                import pythoncom
                import wmi
                pythoncom.CoInitialize()
                try:
                    client = wmi.WMI()
                    for disk in client.Win32_DiskDrive(InterfaceType="USB"):
                        key = str(disk.PNPDeviceID or disk.DeviceID)
                        base_device = {
                            "name": str(disk.Model or "USB storage device"),
                            "device_id": str(disk.DeviceID or ""),
                            "serial": str(disk.SerialNumber or ""),
                            "pnp_id": str(disk.PNPDeviceID or ""),
                            "timestamp": utc_now(),
                        }
                        devices[key] = base_device
                        try:
                            for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
                                for logical in partition.associators("Win32_LogicalDiskToPartition"):
                                    mountpoint = f"{logical.DeviceID}\\"
                                    devices[f"{key}:{mountpoint}"] = {
                                        **base_device,
                                        "name": f"{base_device['name']} ({mountpoint})",
                                        "mountpoint": mountpoint,
                                        "path": mountpoint,
                                        "volume_name": str(getattr(logical, "VolumeName", "") or ""),
                                        "filesystem": str(getattr(logical, "FileSystem", "") or ""),
                                    }
                        except Exception:
                            pass

                    for logical in client.Win32_LogicalDisk(DriveType=2):
                        mountpoint = f"{logical.DeviceID}\\"
                        devices.setdefault(
                            mountpoint,
                            {
                                "name": f"{getattr(logical, 'VolumeName', '') or 'Removable USB'} ({mountpoint})",
                                "mountpoint": mountpoint,
                                "path": mountpoint,
                                "device_id": str(logical.DeviceID or ""),
                                "filesystem": str(getattr(logical, "FileSystem", "") or ""),
                                "timestamp": utc_now(),
                            },
                        )
                finally:
                    pythoncom.CoUninitialize()
            except ImportError:
                pass

            for drive in USBCollector._windows_removable_drives():
                key = drive["path"]
                devices.setdefault(key, drive)

        for item in psutil.disk_partitions(all=False):
            if "removable" in (item.opts or "").lower():
                devices[item.device] = {"name": item.device, "mountpoint": item.mountpoint, "timestamp": utc_now()}
        return USBCollector._dedupe_devices(devices)

    @staticmethod
    def _dedupe_devices(devices: dict) -> dict:
        mountpoint_rows = {}
        hardware_rows = {}
        for key, device in devices.items():
            mountpoint = device.get("mountpoint") or device.get("path")
            if mountpoint:
                normalized = str(mountpoint).upper()
                current = mountpoint_rows.get(normalized)
                if not current or (device.get("pnp_id") and not current.get("pnp_id")):
                    mountpoint_rows[normalized] = device
            else:
                hardware_rows[key] = device

        rows = {}
        for key, device in hardware_rows.items():
            pnp_id = device.get("pnp_id")
            has_mounted_match = pnp_id and any(item.get("pnp_id") == pnp_id for item in mountpoint_rows.values())
            if not has_mounted_match:
                rows[key] = device
        for mountpoint, device in mountpoint_rows.items():
            rows[mountpoint] = device
        return rows

    @staticmethod
    def _make_usb_log_entry(event: dict, action: str) -> dict:
        return {
            "timestamp": event["timestamp"],
            "log_name": "USB",
            "event_id": "USB",
            "source": event["source"],
            "level": "information",
            "message": f"{action}: {event['summary']}",
            "suspicious": True,
            "record": event["metadata"].get("device_id") or event["metadata"].get("path") or event["metadata"].get("pnp_id") or "usb",
        }

    @staticmethod
    def _windows_removable_drives() -> list[dict]:
        drives = []
        DRIVE_REMOVABLE = 2
        GetDriveTypeW = ctypes.windll.kernel32.GetDriveTypeW
        for letter in range(ord("A"), ord("Z") + 1):
            path = f"{chr(letter)}:\\"
            try:
                drive_type = GetDriveTypeW(path)
                if drive_type == DRIVE_REMOVABLE:
                    drives.append({"name": path, "mountpoint": path, "path": path, "timestamp": utc_now()})
            except OSError:
                continue
        return drives


class RegistryCollector:
    RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

    def __init__(self, engine: ThreatEngine, emit, set_status):
        self.engine = engine
        self.emit = emit
        self.set_status = set_status
        self.entries = None

    def poll(self):
        if platform.system() != "Windows" or not winreg:
            self.set_status("startup_registry", "unavailable", "Windows registry only")
            return
        try:
            entries = self._read()
            if self.entries is not None:
                for name, value in entries.items():
                    if self.entries.get(name) != value:
                        self.emit(self.engine.create_event(
                            "registry_persistence",
                            "Startup registry entry modified",
                            f"A startup entry named {name} was created or changed in the current user autorun registry.",
                            "persistence",
                            source="registry-monitor",
                            metadata={"name": name, "value": value, "path": self.RUN_KEY},
                        ))
            self.entries = entries
            self.set_status("startup_registry", "active", f"Tracking {len(entries)} startup entry(s)")
        except OSError as exc:
            self.set_status("startup_registry", "limited", f"Registry unavailable: {type(exc).__name__}")

    def _read(self) -> dict:
        values = {}
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.RUN_KEY) as key:
            index = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, index)
                    values[name] = str(value)
                    index += 1
                except OSError:
                    break
        return values


class RansomwareEventHandler(FileSystemEventHandler):
    def __init__(self, engine: ThreatEngine, emit, set_status):
        self.engine = engine
        self.emit = emit
        self.set_status = set_status
        self.activity = deque()
        self.last_alert = 0.0
        self.lock = threading.Lock()
        self.code_protection = CodeProtectionEngine()

    def on_any_event(self, event):
        if event.is_directory:
            return
        code_event = self.code_protection.inspect_file_event(
            event.event_type,
            event.src_path,
            getattr(event, "dest_path", None),
        )
        if code_event:
            self.emit(self.engine.create_event(**code_event))
        now = time.monotonic()
        extension_changed = False
        if event.event_type == "moved":
            extension_changed = Path(event.src_path).suffix.lower() != Path(event.dest_path).suffix.lower()
        with self.lock:
            self.activity.append((now, event.event_type, extension_changed))
            while self.activity and now - self.activity[0][0] > 10:
                self.activity.popleft()
            writes = sum(kind in {"modified", "created"} for _, kind, _ in self.activity)
            moves = sum(kind == "moved" for _, kind, _ in self.activity)
            changed_extensions = sum(changed for _, _, changed in self.activity)
            suspicious = writes >= 100 or moves >= 25 or changed_extensions >= 15
            if suspicious and now - self.last_alert > 60:
                self.last_alert = now
                self.emit(self.engine.create_event(
                    "ransomware_activity",
                    "Ransomware-like file activity detected",
                    f"Rapid file activity crossed the local threshold: {writes} writes, {moves} renames, {changed_extensions} extension changes in 10 seconds.",
                    "file",
                    source="file-system-monitor",
                    metadata={"writes": writes, "renames": moves, "extension_changes": changed_extensions},
                ))


class ApplicationLogCollector:
    def __init__(self, engine: ThreatEngine, emit, set_status, log_stream: LogStreamBuffer):
        self.engine = engine
        self.emit = emit
        self.set_status = set_status
        self.log_stream = log_stream
        self.log_names = ["System", "Application", "Setup", "Windows PowerShell"]
        self.last_record: dict[str, int | None] = {name: None for name in self.log_names}
        self.alert_throttle = AlertThrottle()

    def poll(self):
        if platform.system() != "Windows":
            self.set_status("application_logs", "unavailable", "Windows only")
            return
        if not win32evtlog:
            self.set_status("application_logs", "unavailable", "Install pywin32")
            return
        for name in self.log_names:
            self._check_log(name)
        active_count = sum(1 for v in self.last_record.values() if v is not None and v >= 0)
        self.set_status(
            "application_logs",
            "active",
            f"Monitoring {active_count} log source(s): {', '.join(self.log_names)}",
        )

    def _check_log(self, log_name: str):
        handle = None
        try:
            handle = win32evtlog.OpenEventLog(None, log_name)
            if self.last_record.get(log_name) in (None, -1):
                if self.last_record.get(log_name) == -1:
                    # Previously failed — retry after a delay
                    self.last_record[log_name] = None
                oldest = win32evtlog.GetOldestEventLogRecord(handle)
                count = win32evtlog.GetNumberOfEventLogRecords(handle)
                self.last_record[log_name] = oldest + count - 1
                for item in bootstrap_log_records(handle, self.last_record[log_name], oldest, count):
                    self._capture_event(item, log_name, emit_alert=False)
                return
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
            events = win32evtlog.ReadEventLog(handle, flags, self.last_record[log_name] + 1)
            while events:
                for item in events:
                    self.last_record[log_name] = max(self.last_record[log_name], item.RecordNumber)
                    self._capture_event(item, log_name)
                events = win32evtlog.ReadEventLog(handle, flags, self.last_record[log_name] + 1)
        except Exception:
            # Log source may not exist on this system — mark unavailable and continue
            if self.last_record[log_name] is None:
                self.last_record[log_name] = -1  # mark as tried-but-failed
        finally:
            if handle:
                win32evtlog.CloseEventLog(handle)

    def _capture_event(self, item, log_name: str, emit_alert: bool = True):
        suspicious = self._is_suspicious(item, log_name)
        self.log_stream.add(log_entry_from_item(item, log_name, suspicious))
        if emit_alert and suspicious:
            self._emit_suspicious(item, log_name)

    def _is_suspicious(self, item, log_name: str) -> bool:
        event_id = item.EventID & 0xFFFF
        event_type_val = item.EventType
        message = normalize_event_message(item)

        if event_type_val == 1:
            return True
        if event_id in SERVICE_FAILURE_IDS:
            return True
        if event_id in APPLICATION_CRASH_IDS and "Application" in log_name:
            return True
        if event_type_val == 2 and (event_id in SERVICE_FAILURE_IDS or event_id in APPLICATION_CRASH_IDS):
            return True
        if message_contains_threat(message):
            return True
        return False

    def _emit_suspicious(self, item, log_name: str):
        event_id = item.EventID & 0xFFFF
        source = item.SourceName or "Unknown"
        throttle_key = f"{log_name}:{event_id}:{source}"
        if not self.alert_throttle.allow(throttle_key):
            return
        ts = event_timestamp(item)
        message = normalize_event_message(item)
        event_type_val = item.EventType
        metadata = {
            "event_id": event_id,
            "source": source,
            "log_name": log_name,
            "record": item.RecordNumber,
        }

        if event_id in APPLICATION_CRASH_IDS and "Application" in log_name:
            self.emit(self.engine.create_event(
                "application_crash",
                f"Application crash detected: {source}",
                message[:200] if message else f"Application {source} crashed unexpectedly",
                "application",
                source="application-log-monitor",
                metadata=metadata,
                timestamp=ts,
            ))
        elif event_id in SERVICE_FAILURE_IDS:
            self.emit(self.engine.create_event(
                "service_failure",
                f"Service failure: {source}",
                message[:200] if message else f"Service {source} encountered a failure",
                "system",
                source="application-log-monitor",
                metadata=metadata,
                timestamp=ts,
            ))
        elif message_contains_threat(message):
            self.emit(self.engine.create_event(
                "threat_detected",
                "Potential threat detected in logs",
                message[:200] if message else f"Threat pattern found in {source}",
                "security",
                source="application-log-monitor",
                metadata=metadata,
                timestamp=ts,
            ))
        elif event_type_val == 1:
            self.emit(self.engine.create_event(
                "system_error",
                f"Critical system error: {source}",
                message[:200] if message else f"Event ID {event_id} from {source}",
                "system",
                source="application-log-monitor",
                metadata=metadata,
                timestamp=ts,
            ))
        else:
            self.emit(self.engine.create_event(
                "threat_detected",
                "Suspicious log event detected",
                message[:200] if message else f"Suspicious event {event_id} from {source}",
                "security",
                source="application-log-monitor",
                metadata=metadata,
                timestamp=ts,
            ))


class TelemetryManager:
    def __init__(self, engine: ThreatEngine, emit):
        self.engine = engine
        self.emit = emit
        self.status = {}
        self.log_stream = LogStreamBuffer()
        self.security = SecurityEventCollector(engine, emit, self.set_status, self.log_stream)
        self.usb = USBCollector(engine, emit, self.set_status, self.log_stream)
        self.registry = RegistryCollector(engine, emit, self.set_status)
        self.application_logs = ApplicationLogCollector(engine, emit, self.set_status, self.log_stream)
        self.observer = None

    def set_status(self, name: str, state: str, detail: str):
        self.status[name] = {"state": state, "detail": detail, "updated": utc_now()}

    def start(self):
        self._start_file_monitor()

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=3)

    def poll(self):
        self.security.poll()
        self.usb.poll()
        self.registry.poll()
        self.application_logs.poll()

    def _start_file_monitor(self):
        if not Observer:
            self.set_status("file_activity", "unavailable", "Install watchdog")
            return
        configured = os.getenv("TRINETRA_WATCH_PATHS", "")
        paths = [Path(item.strip()).expanduser() for item in configured.split(os.pathsep) if item.strip()]
        if not paths:
            home = Path.home()
            paths = [home / name for name in ("Desktop", "Documents", "Downloads")]
        paths = [path for path in paths if path.exists()]
        if not paths:
            self.set_status("file_activity", "unavailable", "No monitored folders found")
            return
        handler = RansomwareEventHandler(self.engine, self.emit, self.set_status)
        self.observer = Observer()
        for path in paths:
            self.observer.schedule(handler, str(path), recursive=True)
        self.observer.start()
        self.set_status("file_activity", "active", f"Watching {len(paths)} local folder(s)")
