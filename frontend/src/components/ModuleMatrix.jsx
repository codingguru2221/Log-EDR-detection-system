export default function ModuleMatrix({ modules }) {
  return (
    <article className="panel">
      <div className="panel-header">
        <div>
          <span className="eyebrow">Platform Structure</span>
          <h2>EDR Modules</h2>
        </div>
        <span className="live-tag muted-tag">{modules.length} Engines</span>
      </div>
      <div className="module-grid">
        {modules.map((item) => (
          <section className="module-tile" key={item.name}>
            <div className="module-title-row">
              <strong>{item.name}</strong>
              <span className={`state state-${item.status}`}>{item.status.replace("_", " ")}</span>
            </div>
            <p>{item.detail}</p>
          </section>
        ))}
      </div>
    </article>
  );
}

