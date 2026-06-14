import { useCallback, useEffect, useRef, useState } from "react";
import { LOG_SOURCES } from "../utils/constants.js";

export function useDashboard() {
  const [overview, setOverview] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [processes, setProcesses] = useState([]);
  const [snapshot, setSnapshot] = useState({});
  const [logStream, setLogStream] = useState({ entries: [], stats: {} });
  const [modules, setModules] = useState([]);
  const [activity, setActivity] = useState([]);
  const [usbStatus, setUsbStatus] = useState({ connected: 0, devices: [] });
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [geminiAnalysis, setGeminiAnalysis] = useState(null);
  const [mitreMapping, setMitreMapping] = useState(null);
  const [voiceLanguages, setVoiceLanguages] = useState([]);
  const [voiceAvailable, setVoiceAvailable] = useState(false);
  const [toast, setToast] = useState(null);
  const [startupSummary, setStartupSummary] = useState(null);
  const [localReport, setLocalReport] = useState(null);
  const socketRef = useRef(null);
  const lastAiFetchRef = useRef(0);
  const geminiFetchedRef = useRef(false);

  const showToast = useCallback((message, danger = false) => {
    setToast({ message, danger });
    setTimeout(() => setToast(null), 2600);
  }, []);

  const fetchLogStream = useCallback(async () => {
    try {
      const data = await fetch("/api/logs/recent?limit=80").then((r) => r.json());
      setLogStream(data);
    } catch {
      /* backend may still be starting */
    }
  }, []);

  const fetchAiAnalysis = useCallback(async (force = false) => {
    const now = Date.now();
    if (!force && now - lastAiFetchRef.current < 15000) return; // 15s minimum gap
    lastAiFetchRef.current = now;
    try {
      const url = force ? "/api/ai-analysis?force=true" : "/api/ai-analysis";
      const data = await fetch(url).then((r) => r.json());
      setAiAnalysis(data);
    } catch {
      /* backend may still be starting */
    }
  }, []);

  const mergeActivity = useCallback((items) => {
    setActivity((prev) => {
      const seen = new Set();
      return [...items, ...prev]
        .filter((item) => {
          const key = `${item.event_type || ""}-${item.title || item.name || ""}-${item.pid || ""}-${item.summary || ""}`;
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        })
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 120);
    });
  }, []);

  const fetchUsbStatus = useCallback(async () => {
    try {
      const data = await fetch("/api/usb/status").then((r) => r.json());
      setUsbStatus(data);
    } catch {
      /* backend may still be starting */
    }
  }, []);

  const fetchVoiceLanguages = useCallback(async () => {
    try {
      const data = await fetch("/api/voice/languages").then((r) => r.json());
      setVoiceLanguages(data.languages || []);
      setVoiceAvailable(data.available || false);
    } catch { /* ignore */ }
  }, []);

  const fetchGeminiAnalysis = useCallback(async () => {
    try {
      const [geminiData, mitreData] = await Promise.all([
        fetch("/api/gemini/analyze").then((r) => r.json()),
        fetch("/api/mitre-mapping").then((r) => r.json()),
      ]);
      setGeminiAnalysis(geminiData);
      setMitreMapping(mitreData);
      geminiFetchedRef.current = true;
    } catch { /* ignore */ }
  }, []);

  const fetchStartupSummary = useCallback(async () => {
    try {
      const data = await fetch("/api/gemini/startup-summary").then((r) => r.json());
      setStartupSummary(data);
    } catch { /* ignore */ }
  }, []);

  const fetchLocalReport = useCallback(async () => {
    try {
      const data = await fetch("/api/analytics/report").then((r) => r.json());
      setLocalReport(data);
    } catch { /* ignore */ }
  }, []);

  const refresh = useCallback(async () => {
    const [overviewData, recentAlerts, processData, moduleData, activityData, usbData] = await Promise.all([
      fetch("/api/overview").then((r) => r.json()),
      fetch("/api/alerts").then((r) => r.json()),
      fetch("/api/processes").then((r) => r.json()),
      fetch("/api/modules").then((r) => r.json()),
      fetch("/api/activity?limit=120").then((r) => r.json()),
      fetch("/api/usb/status").then((r) => r.json()),
    ]);
    setOverview(overviewData);
    setAlerts(recentAlerts);
    setProcesses(processData);
    setModules(moduleData);
    mergeActivity(activityData);
    setUsbStatus(usbData);
    if (overviewData.snapshot) setSnapshot(overviewData.snapshot);
    await fetchLogStream();
  }, [fetchLogStream, mergeActivity]);

  // Fetch startup summary + voice languages on mount (once)
  useEffect(() => {
    fetchStartupSummary();
    fetchVoiceLanguages();
  }, [fetchStartupSummary, fetchVoiceLanguages]);

  // Fetch Gemini + MITRE on mount (once) — no more 60s polling
  useEffect(() => {
    fetchGeminiAnalysis();
  }, [fetchGeminiAnalysis]);

  // Fetch local analytics report on interval (every 30s)
  useEffect(() => {
    fetchLocalReport();
    const interval = setInterval(fetchLocalReport, 30000);
    return () => clearInterval(interval);
  }, [fetchLocalReport]);

  const resetAlerts = useCallback(async () => {
    await fetch("/api/reset", { method: "POST" });
    setActivity([]);
    await refresh();
    await fetchAiAnalysis(true);
    geminiFetchedRef.current = false;
    await fetchGeminiAnalysis();
  }, [refresh, fetchAiAnalysis, fetchGeminiAnalysis]);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 10000);
    return () => clearInterval(interval);
  }, [refresh]);

  // AI analysis: fetch every 30s + re-fetch on risk score changes
  useEffect(() => {
    fetchAiAnalysis(true);
    const interval = setInterval(() => fetchAiAnalysis(true), 30000);

    // Listen for custom event from AIAnalysis force refresh
    const onAiRefresh = () => fetchAiAnalysis(true);
    window.addEventListener("ai-analysis-refreshed", onAiRefresh);

    return () => {
      clearInterval(interval);
      window.removeEventListener("ai-analysis-refreshed", onAiRefresh);
    };
  }, [fetchAiAnalysis]);

  useEffect(() => {
    fetchLogStream();
    const interval = setInterval(fetchLogStream, 4000);
    return () => clearInterval(interval);
  }, [fetchLogStream]);

  useEffect(() => {
    fetchUsbStatus();
    const interval = setInterval(fetchUsbStatus, 2000);
    return () => clearInterval(interval);
  }, [fetchUsbStatus]);

  useEffect(() => {
    let reconnectTimer;

    function connect() {
      const protocol = location.protocol === "https:" ? "wss" : "ws";
      const socket = new WebSocket(`${protocol}://${location.host}/ws`);
      socketRef.current = socket;

      socket.onmessage = ({ data }) => {
        const message = JSON.parse(data);
        if (message.kind === "connected") {
          setOverview(message.data);
          if (message.data.snapshot) setSnapshot(message.data.snapshot);
          fetchLogStream();
        }
        if (message.kind === "snapshot") setSnapshot(message.data);
        if (message.kind === "processes") setProcesses(message.data);
        if (message.kind === "activity") {
          mergeActivity(message.data);
        }
        if (message.kind === "alert") {
          setAlerts((prev) => [message.data, ...prev]);
          showToast(
            message.data.title,
            message.data.severity === "critical" || message.data.severity === "high"
          );
          fetch("/api/overview")
            .then((r) => r.json())
            .then((data) => {
              setOverview(data);
              // Trigger AI re-eval on risk score change
              if (data.score !== undefined) {
                fetchAiAnalysis(true);
              }
              // Fetch Gemini analysis only when a medium+ alert arrives
              const severity = message.data.severity || "low";
              if (
                (severity === "medium" || severity === "high" || severity === "critical") &&
                !geminiFetchedRef.current
              ) {
                fetchGeminiAnalysis();
              }
            });
          fetchAiAnalysis();
        }
        if (message.kind === "logs") {
          const newEntries = (message.data || []).map((e) => {
            const { _seq, ...rest } = e;
            return rest;
          });
          setLogStream((prev) => {
            const existing = prev.entries || [];
            // Deduplicate by record+log_name
            const existingKeys = new Set(existing.map((e) => `${e.record}-${e.log_name}`));
            const fresh = newEntries.filter((e) => !existingKeys.has(`${e.record}-${e.log_name}`));
            return {
              entries: [...fresh, ...existing].slice(0, 120),
              stats: message.stats || prev.stats,
            };
          });
        }
        if (message.kind === "reset") {
          refresh();
          geminiFetchedRef.current = false;
          fetchGeminiAnalysis();
        }
      };

      socket.onclose = () => {
        reconnectTimer = setTimeout(connect, 1500);
      };
    }

    connect();
    return () => {
      clearTimeout(reconnectTimer);
      socketRef.current?.close();
    };
  }, [refresh, showToast, fetchLogStream, fetchAiAnalysis, mergeActivity, fetchGeminiAnalysis]);

  const logAlerts = alerts.filter(
    (a) =>
      LOG_SOURCES.has(a.source) ||
      a.event_type === "usb_device" ||
      a.event_type === "usb_removed"
  );

  return {
    overview, alerts, processes, snapshot, logStream, logAlerts, modules,
    activity, usbStatus, aiAnalysis, geminiAnalysis, mitreMapping,
    voiceLanguages, voiceAvailable, toast, resetAlerts,
    startupSummary, localReport,
  };
}
