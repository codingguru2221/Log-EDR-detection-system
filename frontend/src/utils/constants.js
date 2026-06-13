export const SOURCE_LABELS = {
  "application-log-monitor": "LOG MONITOR",
  "windows-security-log": "SECURITY LOG",
  "file-system-monitor": "FILE WATCHER",
  "registry-monitor": "REGISTRY",
  "usb-monitor": "USB",
  "usb-security-engine": "USB SCAN",
  "ai-attribution-engine": "AI ATTRIBUTION",
  "code-protection-engine": "CODE PROTECT",
  "command-auditor": "COMMAND AUDIT",
  "correlation-engine": "CORRELATION",
  "local-monitor": "SYSTEM",
};

export const LOG_SOURCES = new Set([
  "application-log-monitor",
  "windows-security-log",
  "usb-monitor",
  "usb-security-engine",
]);

export const COLLECTOR_LABELS = {
  application_logs: "Windows System & Application Logs",
  windows_security: "Windows Security Log",
  usb_devices: "USB Device Monitor",
  startup_registry: "Startup Registry",
  file_activity: "File Activity Watcher",
};
