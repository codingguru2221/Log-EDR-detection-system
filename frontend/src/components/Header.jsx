import { useEffect, useState } from "react";

export default function Header() {
  const [clock, setClock] = useState("--:--:--");

  useEffect(() => {
    const tick = () => setClock(new Date().toLocaleTimeString());
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <header className="topbar">
      <div className="brand">
        <div className="brand-icon" aria-hidden="true">
          <svg viewBox="0 0 32 32" fill="none">
            <circle cx="16" cy="16" r="14" stroke="currentColor" strokeWidth="1.5" />
            <circle cx="16" cy="16" r="4" fill="currentColor" />
            <path d="M16 4v6M16 22v6M4 16h6M22 16h6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
        </div>
        <div>
          <h1>
            TRINETRA <span>SENTINEL</span>
          </h1>
          <p>Local Threat Intelligence Platform</p>
        </div>
      </div>
      <div className="topbar-actions">
        <div className="clock-block">
          <span>Local Time</span>
          <strong>{clock}</strong>
        </div>
        <div className="status-pill">
          <span className="pulse-dot" />
          Monitoring Active
        </div>
      </div>
    </header>
  );
}
