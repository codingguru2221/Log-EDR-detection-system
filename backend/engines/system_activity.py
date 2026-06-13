from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SystemActivityEngine:
    def __init__(self):
        self.previous: dict[int, dict] = {}
        self.previous_names: dict[str, int] = {}  # name -> count of instances
        self.recent: list[dict] = []

    def diff(self, processes: list[dict]) -> list[dict]:
        current = {item["pid"]: item for item in processes}
        if not self.previous:
            self.previous = current
            self.previous_names = self._count_names(current)
            return []

        current_names = self._count_names(current)
        events = []

        # "App opened" only when a process NAME first appears (wasn't running before)
        for name, count in current_names.items():
            if name not in self.previous_names:
                # Find any current process with this name for the event
                proc = next((p for p in current.values() if (p.get("name") or "").lower() == name), None)
                if proc:
                    events.append(self._activity("process_started", "App opened", proc))

        # "App closed" only when a process NAME fully disappears (no instances remain)
        for name in self.previous_names:
            if name not in current_names:
                # Find any previous process with this name for the event
                proc = next((p for p in self.previous.values() if (p.get("name") or "").lower() == name), None)
                if proc:
                    events.append(self._activity("process_stopped", "App closed", proc))

        self.previous = current
        self.previous_names = current_names
        if events:
            self.recent = (events + self.recent)[:200]
        return events

    @staticmethod
    def _count_names(processes: dict[int, dict]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for proc in processes.values():
            name = (proc.get("name") or "unknown").lower()
            counts[name] = counts.get(name, 0) + 1
        return counts

    def list_recent(self, limit: int = 30) -> list[dict]:
        return self.recent[:limit]

    @staticmethod
    def _activity(event_type: str, title: str, proc: dict) -> dict:
        return {
            "timestamp": utc_now(),
            "event_type": event_type,
            "title": title,
            "summary": f"{proc.get('name', 'Unknown')} PID {proc.get('pid')} for user {proc.get('username', 'Unknown')}",
            "pid": proc.get("pid"),
            "name": proc.get("name"),
            "username": proc.get("username") or "Unknown",
        }
