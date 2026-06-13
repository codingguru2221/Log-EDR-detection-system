import time
from collections import deque
from pathlib import Path


class CodeProtectionEngine:
    def __init__(self):
        self.activity = deque()
        self.last_alert = 0.0

    def inspect_file_event(self, event_type: str, src_path: str, dest_path: str | None = None) -> dict | None:
        now = time.monotonic()
        src = Path(src_path)
        dest = Path(dest_path) if dest_path else None
        extension_changed = bool(dest and src.suffix.lower() != dest.suffix.lower())
        self.activity.append((now, event_type, extension_changed, str(src)))
        while self.activity and now - self.activity[0][0] > 12:
            self.activity.popleft()

        deleted = sum(kind == "deleted" for _, kind, _, _ in self.activity)
        renamed = sum(kind == "moved" for _, kind, _, _ in self.activity)
        modified = sum(kind in {"modified", "created"} for _, kind, _, _ in self.activity)

        if now - self.last_alert < 45:
            return None
        if deleted >= 20:
            event_type = "mass_file_deletion"
            title = "Mass file deletion detected"
        elif renamed >= 30:
            event_type = "mass_file_rename"
            title = "Mass file rename detected"
        elif modified >= 50:
            event_type = "bulk_file_modification"
            title = "Bulk file modification detected"
        else:
            return None

        self.last_alert = now
        return {
            "event_type": event_type,
            "title": title,
            "summary": f"Code protection threshold crossed in 12 seconds: {modified} writes, {deleted} deletions, {renamed} renames.",
            "category": "code-protection",
            "source": "code-protection-engine",
            "metadata": {
                "writes": modified,
                "deletions": deleted,
                "renames": renamed,
                "snapshot_recommended": True,
                "backup_mode": "snapshot_or_git_commit_before_large_change",
            },
        }

