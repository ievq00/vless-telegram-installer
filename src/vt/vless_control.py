"""Privileged application of VLESS sources saved by the unprivileged panel."""
import fcntl
import grp
import os
import subprocess
import time
from .common import APP, ETC, PANEL_STATE, STATE, atomic_write, read_json, write_json
from .vless import singbox_config_many
from .vless_sources import resolve_vless_settings, validate_vless_settings


def _status(value):
    write_json(PANEL_STATE / "vless-status.json", value, mode=0o640,
               gid=grp.getgrnam("vt-panel").gr_gid)


def _healthy():
    result = subprocess.run(["curl", "-4", "-fsS", "--proxy", "socks5h://127.0.0.1:1080",
                             "--connect-timeout", "8", "--max-time", "20",
                             "https://www.gstatic.com/generate_204"], capture_output=True, timeout=25)
    return result.returncode == 0


def apply():
    STATE.mkdir(parents=True, exist_ok=True)
    settings = validate_vless_settings(read_json(PANEL_STATE / "vless.json"))
    with open(STATE / "vless-sync.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        old = (ETC / "sing-box.json").read_bytes()
        try:
            outbounds, links = resolve_vless_settings(settings)
            config = singbox_config_many(outbounds, settings["check_interval_minutes"])
            import json
            candidate = (json.dumps(config, ensure_ascii=False, indent=2) + "\n").encode()
            temporary = ETC / ".sing-box.candidate.json"
            try:
                atomic_write(temporary, candidate, mode=0o640, gid=grp.getgrnam("vt-vless").gr_gid)
                subprocess.run([str(APP / "bin/sing-box"), "check", "-c", str(temporary)],
                               check=True, timeout=30, capture_output=True)
                os.replace(temporary, ETC / "sing-box.json")
            finally:
                temporary.unlink(missing_ok=True)
            subprocess.run(["systemctl", "restart", "vt-vless.service"], check=True, timeout=45,
                           capture_output=True)
            deadline = time.monotonic() + 35
            healthy = False
            while time.monotonic() < deadline:
                if _healthy():
                    healthy = True
                    break
                time.sleep(2)
            if not healthy:
                raise RuntimeError("Ни один VLESS-сервер не передаёт трафик.")
            _status({"ok": True, "time": int(time.time()), "nodes": len(links),
                     "check_interval_minutes": settings["check_interval_minutes"]})
        except Exception as exc:
            atomic_write(ETC / "sing-box.json", old, mode=0o640, gid=grp.getgrnam("vt-vless").gr_gid)
            subprocess.run(["systemctl", "restart", "vt-vless.service"], timeout=45, capture_output=True)
            _status({"ok": False, "time": int(time.time()),
                     "error": "Новые настройки не применены; прежний VLESS восстановлен."})
            raise RuntimeError("Failed to apply VLESS settings; previous configuration restored.") from exc


if __name__ == "__main__":
    apply()
