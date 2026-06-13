import { COLLECTOR_LABELS } from "../utils/constants.js";

export default function CollectorHealth({ telemetry = {} }) {
  return (
    <article className="panel">
      <div className="panel-header">
        <div>
          <span className="eyebrow">Real Telemetry</span>
          <h2>Collector Health</h2>
        </div>
      </div>
      <p className="muted panel-desc">Live OS-level monitoring status for this endpoint.</p>
      <div className="collector-list">
        {Object.entries(COLLECTOR_LABELS).map(([key, label]) => {
          const item = telemetry[key] || { state: "pending", detail: "Starting collector..." };
          return (
            <div key={key} className="collector-row">
              <div>
                <span className="collector-name">{label}</span>
                <small>{item.detail}</small>
              </div>
              <span className={`state state-${item.state}`}>{item.state}</span>
            </div>
          );
        })}
      </div>
    </article>
  );
}
