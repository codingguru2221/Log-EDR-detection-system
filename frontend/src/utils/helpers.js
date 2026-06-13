import { SOURCE_LABELS } from "./constants.js";

export function fmtTime(timestamp) {
  return new Date(timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function sourceLabel(source) {
  return SOURCE_LABELS[source] || (source || "unknown").replace(/-/g, " ").toUpperCase();
}

export function posture(score) {
  if (score >= 80) {
    return [
      "Critical threats detected",
      "Immediate review is required. Multiple high-confidence malicious behaviors are active.",
    ];
  }
  if (score >= 50) {
    return [
      "Elevated endpoint risk",
      "High-risk behavior was detected. Investigate the latest alerts and affected processes.",
    ];
  }
  if (score >= 20) {
    return [
      "Suspicious activity observed",
      "Local monitoring identified activity outside the expected behavioral baseline.",
    ];
  }
  return [
    "Endpoint is protected",
    "Local behavioral monitoring is active. No urgent action is required.",
  ];
}

export function logTypeLabel(alert) {
  const logName = alert.metadata?.log_name;
  if (logName) return logName.toUpperCase();
  if (alert.source === "windows-security-log") return "SECURITY";
  return "EVENT LOG";
}

export function severityColor(severity) {
  if (severity === "critical" || severity === "high") return "red";
  if (severity === "medium") return "amber";
  return "mint";
}
