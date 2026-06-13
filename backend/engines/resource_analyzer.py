import time

import psutil


class ResourceUsageAnalyzer:
    def collect(self, limit: int = 20) -> list[dict]:
        apps = {}
        connection_counts = self._connection_counts()
        for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "cmdline", "create_time"]):
            try:
                info = proc.info
                pid = info["pid"]
                name = info.get("name") or "Unknown"
                key = name.casefold()
                memory = proc.memory_info()
                io = self._io(proc)
                cpu = info.get("cpu_percent") or 0
                memory_percent = info.get("memory_percent") or 0
                create_time = info.get("create_time") or 0

                if key not in apps:
                    apps[key] = {
                        "pid": pid,
                        "name": name,
                        "username": info.get("username") or "Unknown",
                        "cmdline": " ".join(info.get("cmdline") or []),
                        "cpu": 0.0,
                        "memory": 0.0,
                        "ram_mb": 0.0,
                        "disk_read_mb": 0.0,
                        "disk_write_mb": 0.0,
                        "connections": 0,
                        "instances": 0,
                        "pids": [],
                        "latest_start": create_time,
                        "status": "Normal",
                    }

                app = apps[key]
                app["cpu"] += cpu
                app["memory"] += memory_percent
                app["ram_mb"] += memory.rss / (1024 * 1024)
                app["disk_read_mb"] += io["read_mb"]
                app["disk_write_mb"] += io["write_mb"]
                app["connections"] += connection_counts.get(pid, 0)
                app["instances"] += 1
                app["pids"].append(pid)
                if create_time >= app["latest_start"]:
                    app["pid"] = pid
                    app["latest_start"] = create_time
                    app["username"] = info.get("username") or app["username"]
                    app["cmdline"] = " ".join(info.get("cmdline") or []) or app["cmdline"]
                if cpu > 90 or memory_percent > 80:
                    app["status"] = "High"
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue

        now = time.time()
        rows = []
        for app in apps.values():
            app["cpu"] = round(app["cpu"], 1)
            app["memory"] = round(app["memory"], 1)
            app["ram_mb"] = round(app["ram_mb"], 1)
            app["disk_read_mb"] = round(app["disk_read_mb"], 1)
            app["disk_write_mb"] = round(app["disk_write_mb"], 1)
            app["pids"] = sorted(app["pids"])
            app["rank"] = app["cpu"] + app["memory"]
            if now - app["latest_start"] <= 180:
                app["rank"] += 120
            rows.append(app)
        return sorted(rows, key=lambda item: item["rank"], reverse=True)[:limit]

    @staticmethod
    def _io(proc) -> dict:
        try:
            counters = proc.io_counters()
            return {
                "read_mb": round(counters.read_bytes / (1024 * 1024), 1),
                "write_mb": round(counters.write_bytes / (1024 * 1024), 1),
            }
        except (psutil.AccessDenied, AttributeError, OSError):
            return {"read_mb": 0.0, "write_mb": 0.0}

    @staticmethod
    def _connection_counts() -> dict[int, int]:
        counts = {}
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.pid:
                    counts[conn.pid] = counts.get(conn.pid, 0) + 1
        except (psutil.AccessDenied, OSError):
            pass
        return counts
