export default function ActiveProcesses({ processes }) {
  return (
    <article className="panel">
      <div className="panel-header">
        <div>
          <span className="eyebrow">Live Telemetry</span>
          <h2>Active Processes</h2>
        </div>
        <span className="live-tag muted-tag">Auto Refresh</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Process Name</th>
              <th>PID</th>
              <th>CPU</th>
              <th>RAM</th>
              <th>Disk Read</th>
              <th>Disk Write</th>
              <th>Net</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {processes.map((proc) => (
              <tr key={`${proc.name}-${proc.pid}`}>
                <td className="mono">
                  {proc.name}
                  {proc.instances > 1 ? <span className="dim"> x{proc.instances}</span> : null}
                </td>
                <td className="mono dim">
                  {proc.pid}
                  {proc.instances > 1 ? ` +${proc.instances - 1}` : ""}
                </td>
                <td className="mono">{proc.cpu}%</td>
                <td className="mono">{proc.memory}% / {proc.ram_mb ?? 0} MB</td>
                <td className="mono">{proc.disk_read_mb ?? 0} MB</td>
                <td className="mono">{proc.disk_write_mb ?? 0} MB</td>
                <td className="mono">{proc.connections ?? 0} conn</td>
                <td><span className={`tag ${proc.status === "High" ? "tag-warn" : "tag-mint"}`}>{proc.status}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </article>
  );
}
