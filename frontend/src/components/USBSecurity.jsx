import { useState } from "react";

export default function USBSecurity({ usbStatus }) {
  const devices = usbStatus?.devices || [];
  const hasDevices = devices.length > 0;
  const [expandedDevice, setExpandedDevice] = useState(null);

  function toggleDevice(deviceId) {
    setExpandedDevice((prev) => (prev === deviceId ? null : deviceId));
  }

  const threatBadgeColor = (level) => {
    if (level === "critical") return "badge-critical";
    if (level === "high") return "badge-high";
    if (level === "medium") return "badge-medium";
    return "badge-low";
  };

  return (
    <article className="panel panel-usb">
      <div className="panel-header">
        <div>
          <span className="eyebrow">USB Security</span>
          <h2>External Devices</h2>
        </div>
        <span className={`badge ${hasDevices ? "badge-low" : "badge-medium"}`}>
          {hasDevices ? `${devices.length} CONNECTED` : "NO USB"}
        </span>
      </div>

      {usbStatus?.error && <p className="muted">USB inventory error: {usbStatus.error}</p>}

      {!hasDevices ? (
        <div className="usb-empty">
          <strong>No external USB storage detected</strong>
          <span>Connect a pendrive and scan status will appear here automatically.</span>
        </div>
      ) : (
        <div className="usb-device-list">
          {devices.map((device) => {
            const vs = device.virus_scan || {};
            const hasVirusHits = vs.virus_hits > 0;
            const hasHeuristicHits = vs.heuristic_hits > 0;
            const isExpanded = expandedDevice === device.id;

            return (
              <section className={`usb-device usb-${device.threat_level}`} key={device.id}>
                <div className="usb-device-top">
                  <div>
                    <strong>{device.volume_name || device.name}</strong>
                    <span>{device.mountpoint || device.name}</span>
                  </div>
                  <b>{device.status}</b>
                </div>
                <div className="usb-meta">
                  <span>{device.files_scanned} files scanned</span>
                  <span>{device.findings} finding(s)</span>
                  <span>{device.filesystem || "unknown fs"}</span>
                </div>

                {/* ── Deep Virus Scan Summary ── */}
                {vs.status && vs.status !== "skipped" && (
                  <div className="usb-virus-scan-summary">
                    <div className="usb-vs-row">
                      <span className="usb-vs-label">Deep Scan</span>
                      <span className={`usb-vs-status usb-vs-${vs.status}`}>
                        {vs.status === "complete" ? "✓ Complete" : vs.status === "partial" ? "⚠ Partial" : "⏳ Scanning"}
                      </span>
                    </div>
                    <div className="usb-vs-stats">
                      <span>{vs.files_checked || 0} executables checked</span>
                      {hasVirusHits && (
                        <span className="usb-vs-virus-hit">
                          ⚠ {vs.virus_hits} virus signature{vs.virus_hits > 1 ? "s" : ""} matched
                        </span>
                      )}
                      {hasHeuristicHits && (
                        <span className="usb-vs-heuristic-hit">
                          ⚡ {vs.heuristic_hits} malicious pattern{vs.heuristicHits > 1 ? "s" : ""} found
                        </span>
                      )}
                      {!hasVirusHits && !hasHeuristicHits && vs.files_checked > 0 && (
                        <span className="usb-vs-clean">✓ No viruses detected</span>
                      )}
                    </div>

                    {/* ── Virus Hit Details (expandable) ── */}
                    {(hasVirusHits || hasHeuristicHits) && (
                      <>
                        <button
                          className="usb-vs-expand-btn"
                          onClick={() => toggleDevice(device.id)}
                        >
                          {isExpanded ? "Hide threat details ▾" : `Show ${vs.details?.length || 0} threat detail(s) ▸`}
                        </button>
                        {isExpanded && vs.details?.length > 0 && (
                          <div className="usb-vs-details">
                            {vs.details.map((hit, idx) => (
                              <div key={idx} className={`usb-vs-threat usb-vs-threat-${hit.severity || "high"}`}>
                                <div className="usb-vs-threat-header">
                                  <span className="usb-vs-severity-badge">{(hit.severity || "high").toUpperCase()}</span>
                                  <strong>{hit.name}</strong>
                                </div>
                                <p className="usb-vs-detail-text">{hit.detail || hit.reason}</p>
                                <p className="usb-vs-action">
                                  <span>Recommended: </span>
                                  {hit.action || "Scan with full antivirus before opening."}
                                </p>
                                <code className="usb-vs-path">{hit.path}</code>
                              </div>
                            ))}
                          </div>
                        )}
                      </>
                    )}
                  </div>
                )}

                {/* ── Risky files from rule-based scan ── */}
                {device.risky_files?.length > 0 && (
                  <div className="usb-findings">
                    {device.risky_files.slice(0, 4).map((file) => (
                      <span key={file.path} title={file.reason || ""}>
                        {file.risk}: {file.name}
                      </span>
                    ))}
                  </div>
                )}

                {/* ── Threat level badge ── */}
                {device.threat_level !== "clean" && (
                  <div className="usb-threat-banner">
                    <span className={`badge ${threatBadgeColor(device.threat_level)}`}>
                      {device.threat_level.toUpperCase()} RISK
                    </span>
                    <span className="usb-threat-hint">
                      {device.threat_level === "critical"
                        ? "Virus/malware detected — eject and scan on isolated system."
                        : device.threat_level === "high"
                        ? "Threat-like files found — do not execute any files."
                        : "Review flagged files before using this device."}
                    </span>
                  </div>
                )}
              </section>
            );
          })}
        </div>
      )}
    </article>
  );
}
