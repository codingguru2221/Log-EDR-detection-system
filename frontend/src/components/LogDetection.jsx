import { fmtTime } from "../utils/helpers.js";

const LEVEL_CLASS = {
  error: "level-error",
  warning: "level-warn",
  information: "level-info",
  audit_success: "level-info",
  audit_failure: "level-warn",
};

export default function LogDetection({ logStream, logAlerts }) {
  const entries = logStream?.entries ?? [];
  const stats = logStream?.stats ?? { total_scanned: 0, buffered: 0 };
  const suspiciousAlerts = logAlerts ?? [];

  return (
    <article className="panel panel-log">
      <div className="panel-header">
        <div>
          <span className="eyebrow">Real-Time Logs</span>
          <h2>Windows Event Log Stream</h2>
        </div>
        <div className="log-stats">
          <span className="live-tag">Live</span>
          <span className="log-counter">{stats.total_scanned} scanned</span>
        </div>
      </div>
      <p className="muted panel-desc">
        Recent real Windows System, Application, and Security records plus new live events captured after monitoring starts.
      </p>

      <div className="log-section-label">Live Log Stream</div>
      <div className="scroll-area log-stream-wrap">
        {!entries.length ? (
          <div className="empty-state compact">
            <span className="empty-icon">LOG</span>
            <h3>No readable Windows log records yet</h3>
            <p>Start the app with normal user permissions or administrator rights if Windows blocks a log source.</p>
          </div>
        ) : (
          <table className="log-stream-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Log</th>
                <th>Level</th>
                <th>ID</th>
                <th>Source</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry, i) => (
                <tr
                  key={`${entry.record}-${entry.log_name}-${i}`}
                  className={entry.suspicious ? "log-suspicious" : ""}
                >
                  <td className="mono dim">{fmtTime(entry.timestamp)}</td>
                  <td>
                    <span className={`tag tag-${entry.log_name === "Security" ? "warn" : "mint"}`}>
                      {entry.log_name}
                    </span>
                  </td>
                  <td>
                    <span className={`level-pill ${LEVEL_CLASS[entry.level] || "level-info"}`}>
                      {entry.level}
                    </span>
                  </td>
                  <td className="mono">{entry.event_id}</td>
                  <td className="mono dim source-cell">{entry.source}</td>
                  <td className="message-cell">
                    {entry.suspicious && <span className="flag-pill">FLAGGED</span>}
                    {entry.message}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {suspiciousAlerts.length > 0 && (
        <>
          <div className="log-section-label">Suspicious Detections</div>
          <div className="scroll-area log-list">
            {suspiciousAlerts.slice(0, 10).map((alert, i) => (
              <div key={`${alert.timestamp}-sus-${i}`} className={`log-item severity-${alert.severity}`}>
                <span className="alert-marker" />
                <div className="log-body">
                  <div className="log-tags">
                    <span className="tag tag-warn">{alert.metadata?.log_name?.toUpperCase() || "LOG"}</span>
                    <span className="tag">ID {alert.metadata?.event_id ?? "-"}</span>
                    <span className={`tag tag-sev-${alert.severity}`}>{alert.severity.toUpperCase()}</span>
                  </div>
                  <h4>{alert.title}</h4>
                  <p>{alert.summary}</p>
                </div>
                <time>{fmtTime(alert.timestamp)}</time>
              </div>
            ))}
          </div>
        </>
      )}
    </article>
  );
}
