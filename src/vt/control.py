"""Privileged, narrow sync service. The web panel itself is unprivileged."""
import json
import subprocess
import time
from .common import ETC, PANEL_STATE, STATE, read_json, revision, validate_users, write_json


def materialize(document):
    enabled = [u for u in validate_users(document)["users"] if u["enabled"]]
    keys = {u["id"]: u["secret"] for u in enabled}
    profiles = {"profiles": [
        {"name": u["id"], "secret": u["secret"], "backend": "127.0.0.1:2398", "carrier_mode": "https"}
        for u in enabled
    ]}
    return keys, profiles


def apply():
    import fcntl
    import grp
    import pwd
    STATE.mkdir(parents=True, exist_ok=True)
    with open(STATE / "sync.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        document = validate_users(read_json(PANEL_STATE / "users.json"))
        digest = revision(document)
        applied_path = STATE / "applied-users.json"
        if applied_path.exists() and read_json(applied_path) == document:
            return
        before = read_json(applied_path) if applied_path.exists() else None
        backend_gid = grp.getgrnam("vt-backend").gr_gid
        relay_gid = grp.getgrnam("vt-relay").gr_gid
        panel_gid = grp.getgrnam("vt-panel").gr_gid

        def persist(value):
            keys, profiles = materialize(value)
            write_json(ETC / "backend-users.json", keys, mode=0o640, gid=backend_gid)
            write_json(ETC / "profiles.json", profiles, mode=0o600, uid=pwd.getpwnam("vt-relay").pw_uid, gid=relay_gid)

        try:
            persist(document)
            # Restarting also closes active connections belonging to revoked secrets.
            subprocess.run(["systemctl", "restart", "vt-backend.service", "vt-relay.service"],
                           check=True, timeout=40, capture_output=True)
            write_json(applied_path, document)
            write_json(PANEL_STATE / "status.json", {"revision": digest, "ok": True, "time": int(time.time())},
                       mode=0o640, gid=panel_gid)
        except Exception as exc:
            if before:
                persist(before)
                subprocess.run(["systemctl", "restart", "vt-backend.service", "vt-relay.service"],
                               timeout=40, capture_output=True)
            write_json(PANEL_STATE / "status.json", {"revision": digest, "ok": False,
                       "error": "Не удалось применить настройки. Предыдущая конфигурация сохранена."},
                       mode=0o640, gid=panel_gid)
            raise RuntimeError("Failed to apply Telegram users; previous configuration restored.") from exc


if __name__ == "__main__":
    apply()
