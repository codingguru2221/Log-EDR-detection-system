import MarkdownText from "./MarkdownText.jsx";

export default function ThreatSummary({ alerts, analysis }) {
  const summary =
    analysis?.threat_summary ||
    (alerts.length === 0
      ? "No suspicious patterns are active. Trinetra is learning this endpoint's local behavioral baseline."
      : alerts[0].summary +
        (alerts.length > 1
          ? ` Correlated with ${alerts.length - 1} additional local alert${alerts.length > 2 ? "s" : ""}.`
          : ""));

  return (
    <article className="panel panel-ai">
      <div className="panel-header">
        <div>
          <span className="eyebrow">AI Analyst</span>
          <h2>Threat Summary</h2>
        </div>
        <span className="ai-chip">AI</span>
      </div>
      <MarkdownText className="ai-text" text={summary} />
      <div className="ai-footer">
        <span>{analysis?.provider === "gemini" ? analysis.model : "Local Analysis"}</span>
        <strong>
          {analysis?.provider === "gemini" && !analysis?.error ? "Gemini" : "Offline"} <span className="pulse-dot small" />
        </strong>
      </div>
    </article>
  );
}
