export default function StatCards({ overview }) {
  const previews = overview?.previews || {};

  return (
    <div className="stat-card-group">
      <article className="panel panel-stat">
        <span className="eyebrow">Total Alerts</span>
        <strong className="stat-value">{overview?.alerts ?? 0}</strong>
        <p className="muted">Recorded locally</p>
        <StatPreview items={previews.alerts} empty="No alerts recorded yet" />
      </article>
      <article className="panel panel-stat">
        <span className="eyebrow">AI Attributed</span>
        <strong className="stat-value">{overview?.ai_attributed ?? 0}</strong>
        <p className="muted">Commands and chains</p>
        <StatPreview items={previews.ai_attributed} empty="No AI-attributed chains" />
      </article>
      <article className="panel panel-stat panel-online">
        <span className="eyebrow">USB Events</span>
        <strong className="stat-online">
          <span className="pulse-dot" /> {overview?.usb_events ?? 0}
        </strong>
        <p className="muted">Detected and scanned</p>
        <StatPreview items={previews.usb_events} empty="No USB activity" />
      </article>
    </div>
  );
}

function StatPreview({ items = [], empty }) {
  const rows = items.slice(0, 3);
  return (
    <div className="stat-preview-list">
      {rows.length === 0 ? (
        <span className="stat-preview-empty">{empty}</span>
      ) : (
        rows.map((item, index) => (
          <div className={`stat-preview-item severity-${item.severity || "low"}`} key={`${item.title}-${index}`}>
            <span className="stat-preview-dot" />
            <div>
              <strong>{item.title}</strong>
              <small>{item.detail}</small>
            </div>
          </div>
        ))
      )}
    </div>
  );
}
