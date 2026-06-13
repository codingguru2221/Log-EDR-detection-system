from dataclasses import dataclass


AI_TOOLS = {
    "cursor": "Cursor AI",
    "cursor.exe": "Cursor AI",
    "claude": "Claude Code",
    "claude.exe": "Claude Code",
    "code": "VS Code / Copilot",
    "github-copilot": "GitHub Copilot",
    "cline": "Cline",
    "roo": "Roo Code",
    "roo-code": "Roo Code",
    "windsurf": "Windsurf",
    "aider": "Aider",
}

DANGEROUS_COMMANDS = (
    "git reset --hard",
    "git clean",
    "rm -rf",
    "del /s",
    "rmdir /s",
    "diskpart",
    "format ",
    "shutdown",
    "bcdedit",
    "cipher /w",
)


@dataclass
class AttributionResult:
    origin: str
    confidence: int
    reason: str


class AIAttributionEngine:
    def inspect_process(self, process: dict) -> AttributionResult | None:
        chain = [str(item).lower() for item in process.get("parent_chain", [])]
        name = str(process.get("name", "")).lower()
        command = str(process.get("cmdline", "")).lower()
        combined = " ".join([name, command, *chain])

        tool = self._match_tool(combined)
        if not tool:
            return None

        confidence = 70
        if any(shell in name for shell in ("powershell", "cmd.exe", "bash", "pwsh", "git")):
            confidence += 10
        if any(cmd in command for cmd in DANGEROUS_COMMANDS):
            confidence += 12
        if chain:
            confidence += 5

        return AttributionResult(
            origin=tool,
            confidence=min(confidence, 98),
            reason="Process or parent chain contains a known AI coding tool.",
        )

    def inspect_command(self, process: dict) -> dict | None:
        command = str(process.get("cmdline", "")).lower()
        matched = next((item for item in DANGEROUS_COMMANDS if item in command), None)
        if not matched:
            return None
        attribution = self.inspect_process(process)
        return {
            "matched_command": matched,
            "origin": attribution.origin if attribution else "Unknown user or process",
            "confidence": attribution.confidence if attribution else 40,
            "ai_assisted": bool(attribution),
        }

    @staticmethod
    def _match_tool(text: str) -> str | None:
        for needle, label in AI_TOOLS.items():
            if needle in text:
                return label
        return None

