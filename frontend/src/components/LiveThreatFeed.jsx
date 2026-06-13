import SourceBadge from "./SourceBadge.jsx";
import { fmtTime } from "../utils/helpers.js";

function isUsbActivity(item) {
  return item.pid === "USB" || item.source === "usb-monitor" || item.source === "usb-security-engine";
}

function usbStatusText(item) {
  if (item.event_type === "usb_scan_clean") return "";
  if (item.event_type === "usb_scan_started") return "SCANNING";
  if (item.event_type === "usb_threat_detected" || item.event_type === "usb_scan_suspicious") return "REVIEW REQUIRED";
  if (item.event_type === "usb_device") return "CONNECTED";
  if (item.event_type === "usb_removed") return "REMOVED";
  return "USB ACTIVITY";
}

export default function LiveThreatFeed({ alerts, activity, processes, onReset, onExplainAlert }) {
  const dedupedActivity = [];
  const seenActivity = new Set();

  (activity || []).forEach((item) => {
    const key = `${item.kind || "activity"}-${item.event_type || item.title}-${item.title || item.name || ""}-${item.pid || ""}-${item.summary || ""}`;
    if (!seenActivity.has(key)) {
      seenActivity.add(key);
      dedupedActivity.push({ ...item, kind: "activity" });
    }
  });

  const liveItems = [
    ...dedupedActivity,
    ...(alerts || []).slice(0, 8).map((item) => ({ ...item, kind: "alert" })),
  ].filter((item, index, array) => {
    const key = `${item.kind}-${item.title || item.name}-${item.summary || item.category || ""}-${item.pid || ""}`;
    return array.findIndex((other) => {
      return `${other.kind}-${other.title || other.name}-${other.summary || other.category || ""}-${other.pid || ""}` === key;
    }) === index;
  }).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  const topProcesses = [...new Map(
    [...(processes || [])]
      .sort((a, b) => (b.cpu || 0) - (a.cpu || 0))
      .map((proc) => [proc.name || proc.pid, proc])
  ).values()].slice(0, 5);

  return (
    <article className="panel panel-feed">
      <div className="panel-header">
        <div>
          <span className="eyebrow">Real-Time Endpoint Telemetry</span>
          <h2>Live Activity Feed</h2>
        </div>
        <div className="btn-group">
          <button type="button" className="btn-ghost" onClick={onReset}>
            Clear
          </button>
          <a className="btn-ghost" href="/api/report.csv">
            Export Report
          </a>
        </div>
      </div>

      <div className="mini-process-strip">
        {topProcesses.map((proc) => (
          <div className="mini-process" key={proc.pid}>
            <strong>{proc.name}</strong>
            <span>RAM {proc.ram_mb ?? 0} MB</span>
            <span>CPU {proc.cpu}%</span>
            <span>Disk R/W {proc.disk_read_mb ?? 0}/{proc.disk_write_mb ?? 0} MB</span>
          </div>
        ))}
      </div>

      <div className="scroll-area feed-list">
        {!liveItems.length ? (
          <EmptyState
            icon="OK"
            title="Monitoring active — no alerts yet"
            text="Trinetra is watching processes, USB devices, registry, file system, and Windows logs. Connect a USB drive or open/close an app and events will stream here live."
          />
        ) : (
          <>
            {liveItems.slice(0, 35).map((item, i) =>
              item.kind === "alert" ? (
                <div key={`${item.timestamp}-${i}`} className={`alert-item severity-${item.severity}`}>
                  <span className="alert-marker" />
                  <div className="alert-body">
                    <h3>
                      <SourceBadge source={item.source} />
                      {item.title}
                      <em>+{item.score}</em>
                    </h3>
                    <p>{item.category.toUpperCase()} - {item.summary}</p>
                    <button
                      className="explain-alert-btn"
                      onClick={() => onExplainAlert && onExplainAlert(item)}
                      title="Explain this alert with AI"
                    >
                      Why this alert?
                    </button>
                  </div>
                  <time>{fmtTime(item.timestamp)}</time>
                </div>
              ) : (
                <ActivityRow item={item} index={i} />
              )
            )}
            {liveItems.length < 6 && (
              <div className="feed-monitoring-hint">
                <span className="pulse-dot-live" />
                Monitoring active — {liveItems.length} event(s) captured. New activity will appear here live.
              </div>
            )}
          </>
        )}
      </div>
    </article>
  );
}

function ActivityRow({ item, index }) {
  const usb = isUsbActivity(item);
  const usbStatus = usb ? usbStatusText(item) : "";
  return (
    <div
      key={`${item.timestamp}-${item.pid}-${index}`}
      className={`alert-item severity-${item.severity || "low"} ${usb ? "usb-activity-item" : ""}`}
    >
      <span className="alert-marker" />
      <div className="alert-body">
        <h3>
          <span className="source-badge">{usb ? "USB" : "PROCESS"}</span>
          {usb ? item.title : item.name}
          {usbStatus && <em>{usbStatus}</em>}
        </h3>
        <p>
          {usb
            ? `${item.name} - ${item.summary}`
            : `${item.title.toUpperCase()} - PID ${item.pid} - User ${item.username}`}
        </p>
      </div>
      <time>{fmtTime(item.timestamp)}</time>
    </div>
  );
}

function EmptyState({ icon, title, text }) {
  return (
    <div className="empty-state">
      <span className="empty-icon">{icon}</span>
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  );
}
