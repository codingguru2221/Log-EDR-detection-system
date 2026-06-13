import { useState, useRef, useEffect } from "react";

export default function VoiceAlertPlayer({ languages, voiceAvailable }) {
  const [selectedLang, setSelectedLang] = useState("en");
  const [playing, setPlaying] = useState(false);
  const [audioData, setAudioData] = useState(null);
  const [status, setStatus] = useState("");
  const audioRef = useRef(null);

  // Use browser TTS as fallback when Sarvam is unavailable
  const useBrowserTTS = !voiceAvailable;

  async function speakText() {
    if (playing) {
      stopAudio();
      return;
    }

    setStatus("Generating voice...");
    setPlaying(true);

    if (useBrowserTTS) {
      // Browser-native speech synthesis fallback
      const utterance = new SpeechSynthesisUtterance(getSampleText(selectedLang));
      utterance.lang = selectedLang === "hi" ? "hi-IN" : selectedLang === "te" ? "te-IN" : "en-IN";
      utterance.rate = 0.9;
      utterance.onend = () => {
        setPlaying(false);
        setStatus("");
      };
      utterance.onerror = () => {
        setPlaying(false);
        setStatus("Speech synthesis failed");
      };
      window.speechSynthesis.cancel();
      window.speechSynthesis.speak(utterance);
      return;
    }

    // Try Sarvam API
    try {
      const data = await fetch("/api/voice/speak", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: getSampleText(selectedLang),
          language: selectedLang,
        }),
      }).then((r) => r.json());

      if (data.audio_base64 && data.format !== "browser-fallback") {
        // Play Sarvam audio
        const audio = new Audio(`data:audio/wav;base64,${data.audio_base64}`);
        audioRef.current = audio;
        audio.onended = () => {
          setPlaying(false);
          setStatus("");
        };
        audio.play();
        setStatus(`Playing (${data.provider})`);
      } else {
        // Fallback to browser TTS
        const utterance = new SpeechSynthesisUtterance(data.text || getSampleText(selectedLang));
        utterance.lang = selectedLang === "hi" ? "hi-IN" : selectedLang === "te" ? "te-IN" : "en-IN";
        utterance.rate = 0.9;
        utterance.onend = () => {
          setPlaying(false);
          setStatus("");
        };
        window.speechSynthesis.speak(utterance);
        setStatus("Browser speech (fallback)");
      }
    } catch {
      setStatus("Voice generation failed");
      setPlaying(false);
    }
  }

  function stopAudio() {
    window.speechSynthesis?.cancel();
    if (audioRef.current) {
      audioRef.current.pause();
      audioRef.current = null;
    }
    setPlaying(false);
    setStatus("");
  }

  useEffect(() => {
    return () => {
      window.speechSynthesis?.cancel();
      if (audioRef.current) audioRef.current.pause();
    };
  }, []);

  function getSampleText(lang) {
    if (lang === "hi") return "Trinetra Sentinel security alert. System mein suraksha ghatnaayein detect hui hain. Kripya dashboard ki samiksha karein aur uchch प्राथमिकता alerts par dhyaan dein.";
    if (lang === "te") return "Trinetra Sentinel security alert. System lo bhadratha gathanalu gurthinchabaadayaayi. Dayachesi dashboard ni parishilinchandi mariyu high priority alerts ni gurthinchandi.";
    return "Trinetra Sentinel security alert. Security events have been detected on this system. Please review the dashboard and prioritize high severity alerts.";
  }

  const langList = languages || [
    { code: "en", label: "English", native: "English" },
    { code: "hi", label: "Hindi", native: "हिन्दी" },
    { code: "te", label: "Telugu", native: "తెలుగు" },
  ];

  return (
    <article className="panel panel-voice">
      <div className="panel-header">
        <div>
          <span className="eyebrow">Sarvam AI Voice Assistant</span>
          <h2>Voice Alerts</h2>
        </div>
        <span className={`ai-chip ${useBrowserTTS ? "voice-chip-fallback" : ""}`}>
          {useBrowserTTS ? "Browser TTS" : "Sarvam AI"}
        </span>
      </div>

      <p className="voice-desc">
        Get multilingual voice notifications for security alerts in English, Hindi, or Telugu.
      </p>

      {/* Language selector */}
      <div className="voice-lang-select">
        {langList.map((lang) => (
          <button
            key={lang.code}
            className={`voice-lang-btn ${selectedLang === lang.code ? "voice-lang-active" : ""}`}
            onClick={() => setSelectedLang(lang.code)}
          >
            <span className="voice-lang-native">{lang.native}</span>
            <span className="voice-lang-label">{lang.label}</span>
          </button>
        ))}
      </div>

      {/* Play / Stop button */}
      <div className="voice-controls">
        <button
          className={`voice-play-btn ${playing ? "voice-playing" : ""}`}
          onClick={speakText}
        >
          {playing ? "⏹ Stop" : "🔊 Play Voice Alert"}
        </button>
        {status && <span className="voice-status">{status}</span>}
      </div>

      <div className="voice-footer">
        <span>Sarvam AI TTS</span>
        <strong>3 Languages</strong>
        <span>Read-only</span>
      </div>
    </article>
  );
}
