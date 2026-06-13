import { fmtTime } from "../utils/helpers.js";

const BACKGROUND_PROCESS_NAMES = new Set([
  "memcompression",
  "msmpeng.exe",
  "registry",
  "runtimebroker.exe",
  "searchfilterhost.exe",
  "searchindexer.exe",
  "searchprotocolhost.exe",
  "services.exe",
  "svchost.exe",
  "system",
  "system idle process",
]);

export default function SystemActivity({ activity, processes, snapshot }) {
  const processActivity = activity.filter((item) =>
    item.event_type === "process_started" || item.event_type === "process_stopped"
  );
  const runningApps = (processes || [])
    .filter((proc) => proc.name && !BACKGROUND_PROCESS_NAMES.has(proc.name.toLowerCase()))
    .sort((a, b) => (b.latest_start ?? 0) - (a.latest_start ?? 0))
    .slice(0, 8);

  return (
    <article className="panel">
      <div className="panel-header">
        <div>
          <span className="eyebrow">System Activity</span>
          <h2>Running Apps</h2>
        </div>
        <span className="live-tag muted-tag">Live</span>
      </div>

      <div className="system-usage-grid">
        <UsageStat
          label="Total RAM"
          value={`${snapshot?.memory_used_gb ?? "--"} / ${snapshot?.memory_total_gb ?? "--"} GB`}
          sub={`${snapshot?.memory ?? "--"}% used`}
        />
        <UsageStat
          label="Storage"
          value={`${snapshot?.storage_used_gb ?? "--"} / ${snapshot?.storage_total_gb ?? "--"} GB`}
          sub={`${snapshot?.storage_percent ?? "--"}% used`}
        />
      </div>

      <div className="running-app-list">
        {runningApps.length === 0 ? (
          <div className="empty-state compact">
            <p>Running applications will appear here.</p>
          </div>
        ) : (
          runningApps.map((proc) => (
            <div className="running-app-row" key={`${proc.name}-${proc.pid}`}>
              <div>
                <strong>
                  {proc.name}
                  {proc.instances > 1 ? <span className="dim"> x{proc.instances}</span> : null}
                </strong>
                <span>PID {proc.pid}{proc.instances > 1 ? ` +${proc.instances - 1}` : ""}</span>
              </div>
              <div className="running-app-metrics">
                <span>RAM {proc.ram_mb ?? 0} MB</span>
                <span>CPU {proc.cpu ?? 0}%</span>
                <span>Disk {proc.disk_read_mb ?? 0}/{proc.disk_write_mb ?? 0} MB</span>
              </div>
            </div>
          ))
        )}
      </div>

      <div className="log-section-label">Open / Close History</div>
      <div className="activity-list scroll-area">
        {processActivity.length === 0 ? (
          <div className="empty-state compact">
            <p>Process lifecycle events will appear here.</p>
          </div>
        ) : (
          processActivity.map((item, index) => (
            <div className="activity-row" key={`${item.timestamp}-${item.pid}-${index}`}>
              <span className={`activity-dot ${item.event_type}`} />
              <div>
                <strong>{item.title}</strong>
                <p>{item.summary}</p>
              </div>
              <time>{fmtTime(item.timestamp)}</time>
            </div>
          ))
        )}
      </div>
    </article>
  );
}

function UsageStat({ label, value, sub }) {
  return (
    <div className="usage-stat">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{sub}</small>
    </div>
  );
}
