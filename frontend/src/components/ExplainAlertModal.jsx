import { useState } from "react";
import MarkdownText from "./MarkdownText.jsx";

export default function ExplainAlertModal({ alert, onClose }) {
  const [explanation, setExplanation] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useState(() => {
    if (!alert) return;
    setLoading(true);
    setError(null);
    fetch("/api/gemini/explain", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert }),
    })
      .then((r) => r.json())
      .then((data) => {
        setExplanation(data);
        setLoading(false);
      })
      .catch(() => {
        setError("Failed to fetch explanation from Gemini.");
        setLoading(false);
      });
  }, []);

  if (!alert) return null;

  const provider = explanation?.provider || "";
  const mitre = explanation?.mitre || [];
  const text = explanation?.explanation || "";

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="modal-header">
          <div>
            <span className="eyebrow">Explainable Alert</span>
            <h2>Why was this alert generated?</h2>
          </div>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>

        {/* Alert Info */}
        <div className="modal-alert-info">
          <span className={`badge badge-${alert.severity || "low"}`}>
            {alert.severity || "unknown"}
          </span>
          <strong>{alert.title || "Unknown alert"}</strong>
          <span className="dim">{alert.event_type || ""}</span>
          <span className="mono dim">Score: {alert.score ?? 0}</span>
        </div>

        {/* Loading */}
        {loading && (
          <div className="modal-loading">
            <span className="pulse-dot" />
            <span>Generating explanation with Gemini AI...</span>
          </div>
        )}

        {/* Error */}
        {error && <p className="gemini-notice">{error}</p>}

        {/* Explanation */}
        {text && !loading && (
          <div className="modal-explanation">
            <MarkdownText text={text} />
          </div>
        )}

        {/* MITRE Mapping */}
        {mitre.length > 0 && (
          <div className="modal-mitre">
            <h4>MITRE ATT&CK Techniques</h4>
            <div className="mitre-chips">
              {mitre.map((t) => (
                <span key={t.technique_id} className="mitre-chip">
                  <strong>{t.technique_id}</strong> {t.name}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Provider Badge */}
        {provider && (
          <div className="modal-footer">
            <span className="gemini-provider-tag">
              {provider === "gemini" ? "🤖 Gemini AI" : "🖥️ Local Analysis"}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
