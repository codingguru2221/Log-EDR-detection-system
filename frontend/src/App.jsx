import Header from "./components/Header.jsx";
import SecurityIndex from "./components/SecurityIndex.jsx";
import EndpointStatus from "./components/EndpointStatus.jsx";
import StatCards from "./components/StatCards.jsx";
import LiveThreatFeed from "./components/LiveThreatFeed.jsx";
import ThreatSummary from "./components/ThreatSummary.jsx";
import AlertTimeline from "./components/AlertTimeline.jsx";
import LogDetection from "./components/LogDetection.jsx";
import ActiveProcesses from "./components/ActiveProcesses.jsx";
import ModuleMatrix from "./components/ModuleMatrix.jsx";
import AIAnalysis from "./components/AIAnalysis.jsx";
import SystemActivity from "./components/SystemActivity.jsx";
import USBSecurity from "./components/USBSecurity.jsx";
import CollectorHealth from "./components/CollectorHealth.jsx";
import Toast from "./components/Toast.jsx";
import { useDashboard } from "./hooks/useDashboard.js";

export default function App() {
  const { overview, alerts, processes, snapshot, logStream, logAlerts, modules, activity, usbStatus, aiAnalysis, toast, resetAlerts } = useDashboard();

  return (
    <>
      <Header />
      <main className="dashboard">
        <section className="grid-hero">
          <SecurityIndex overview={overview} />
          <EndpointStatus snapshot={snapshot} />
          <StatCards overview={overview} />
        </section>

        <section className="grid-main">
          <LiveThreatFeed alerts={alerts} activity={activity} processes={processes} onReset={resetAlerts} />
          <aside className="sidebar">
            <USBSecurity usbStatus={usbStatus} />
            <AIAnalysis analysis={aiAnalysis} />
            <ThreatSummary alerts={alerts} analysis={aiAnalysis} />
            <AlertTimeline alerts={alerts} />
          </aside>
        </section>

        <section className="grid-full">
          <ModuleMatrix modules={modules} />
        </section>

        <section className="grid-full">
          <LogDetection logStream={logStream} logAlerts={logAlerts} />
        </section>

        <section className="grid-full">
          <CollectorHealth telemetry={overview?.telemetry} />
        </section>

        <section className="grid-bottom">
          <ActiveProcesses processes={processes} />
          <SystemActivity activity={activity} processes={processes} snapshot={snapshot} />
        </section>

      </main>
      <Toast toast={toast} />
    </>
  );
}
