import { useState } from "react";
import MarkdownText from "./MarkdownText.jsx";

export default function AIThreatSummary({ geminiAnalysis, mitreMapping, onSpeak }) {
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [showMitre, setShowMitre] = useState(false);

  async function fetchAnalysis() {
    setRefreshing(true);
    try {
      await fetch("/api/gemini/analyze").then((r) => r.json());
    } catch {
      /* ignore */
    } finally {
      setTimeout(() => setRefreshing(false), 1200);
    }
  }

  const analysis = geminiAnalysis?.analysis || "";
  const provider = geminiAnalysis?.provider || "unknown";
  const model = geminiAnalysis?.model || "";
  const error = geminiAnalysis?.error;
  const techniques = mitreMapping?.techniques || [];
  const tactics = mitreMapping?.active_tactics || [];

  const providerColor =
    provider === "gemini" ? "var(--mint)" : "var(--amber)";

  return (
    <article className="panel panel-gemini">
      <div className="panel-header">
        <div>
          <span className="eyebrow">Gemini Threat Intelligence</span>
          <h2>AI Threat Analysis</h2>
        </div>
        <div className="ai-header-right">
          <span className="ai-chip" style={{ color: providerColor, borderColor: providerColor }}>
            {provider === "gemini" ? "Gemini Active" : "Local Fallback"}
          </span>
          <button
            className="ai-refresh-btn"
            onClick={fetchAnalysis}
            disabled={refreshing}
            title="Re-analyze with Gemini"
          >
            {refreshing ? "⟳" : "↻"}
          </button>
        </div>
      </div>

      {error && (
        <p className="gemini-notice">{error}</p>
      )}

      {model && (
        <p className="gemini-model">Model: {model}</p>
      )}

      {/* ── Analysis Text ── */}
      <div className="gemini-analysis">
        {analysis ? (
          <MarkdownText text={analysis} />
        ) : (
          <p className="muted">Waiting for Gemini analysis...</p>
        )}
      </div>

      {/* ── MITRE ATT&CK Toggle ── */}
      {techniques.length > 0 && (
        <>
          <button
            className="mitre-toggle-btn"
            onClick={() => setShowMitre(!showMitre)}
          >
            <span>MITRE ATT&CK Mapping</span>
            <span className="mitre-count">{techniques.length} technique(s)</span>
            <span className="mitre-chevron">{showMitre ? "▲" : "▼"}</span>
          </button>

          {showMitre && (
            <div className="mitre-panel">
              {/* Active Tactics */}
              {tactics.length > 0 && (
                <div className="mitre-tactics">
                  {tactics.map((t) => (
                    <span key={t} className="mitre-tactic-tag">{t}</span>
                  ))}
                </div>
              )}

              {/* Techniques Table */}
              <div className="mitre-table-wrap">
                <table className="mitre-table">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Technique</th>
                      <th>Tactic</th>
                    </tr>
                  </thead>
                  <tbody>
                    {techniques.map((t) => (
                      <tr key={t.technique_id}>
                        <td className="mono">{t.technique_id}</td>
                        <td>
                          <strong>{t.name}</strong>
                          <br />
                          <small className="dim">{t.description?.slice(0, 90)}...</small>
                        </td>
                        <td>{t.tactic}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}

      {/* ── Voice Button ── */}
      {onSpeak && analysis && (
        <div className="gemini-actions">
          <button className="voice-btn" onClick={() => onSpeak(analysis)}>
            🔊 Voice Summary
          </button>
        </div>
      )}
    </article>
  );
}
