export default function AlertTimeline({ alerts }) {
  return (
    <article className="panel">
      <div className="panel-header">
        <div>
          <span className="eyebrow">Activity History</span>
          <h2>Alert Timeline</h2>
        </div>
      </div>
      <div className="timeline-chart">
        {!alerts.length ? (
          <p className="muted timeline-empty">Waiting for local events...</p>
        ) : (
          alerts
            .slice(0, 24)
            .reverse()
            .map((alert, i) => (
              <span
                key={`${alert.timestamp}-tl-${i}`}
                className={`timeline-bar severity-${alert.severity}`}
                title={alert.title}
                style={{ height: `${Math.min(62, 8 + alert.score / 1.5)}px` }}
              />
            ))
        )}
      </div>
    </article>
  );
}
