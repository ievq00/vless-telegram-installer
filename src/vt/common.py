import hashlib
import json
import os
import re
import secrets
import tempfile
from pathlib import Path

APP = Path("/opt/vless-telegram")
ETC = Path("/etc/vless-telegram")
STATE = Path("/var/lib/vless-telegram")
PANEL_STATE = STATE / "panel"
UNITS = ("vt-vless", "vt-backend", "vt-relay", "vt-panel", "vt-caddy")


def atomic_write(path, data, mode=0o600, uid=None, gid=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not isinstance(data, bytes):
        data = data.encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=".vt-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            if hasattr(os, "fchmod"):
                os.fchmod(stream.fileno(), mode)
            if uid is not None or gid is not None:
                os.fchown(stream.fileno(), -1 if uid is None else uid, -1 if gid is None else gid)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def write_json(path, value, **kwargs):
    atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n", **kwargs)


def read_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    value = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 400000).hex()
    return salt + ":" + value


def password_matches(password, saved):
    try:
        salt, _ = saved.split(":", 1)
        return secrets.compare_digest(password_hash(password, salt), saved)
    except (ValueError, TypeError):
        return False


def validate_users(document):
    if not isinstance(document, dict) or set(document) != {"users"}:
        raise ValueError("Некорректный список подключений.")
    users = document["users"]
    if not isinstance(users, list) or not 1 <= len(users) <= 32:
        raise ValueError("Допустимо от 1 до 32 подключений.")
    ids, keys = set(), set()
    for user in users:
        if not isinstance(user, dict) or set(user) != {"id", "name", "secret", "enabled"}:
            raise ValueError("Некорректная запись подключения.")
        if not isinstance(user["id"], str) or not re.fullmatch(r"[a-f0-9]{16}", user["id"]):
            raise ValueError("Некорректный идентификатор.")
        if not isinstance(user["name"], str) or not 1 <= len(user["name"]) <= 60 or any(ord(c) < 32 for c in user["name"]):
            raise ValueError("Название должно содержать от 1 до 60 печатных символов.")
        if not isinstance(user["secret"], str) or not re.fullmatch(r"[a-f0-9]{32}", user["secret"]):
            raise ValueError("Некорректный секрет.")
        if type(user["enabled"]) is not bool:
            raise ValueError("Некорректный статус подключения.")
        if user["id"] in ids or user["secret"] in keys:
            raise ValueError("Идентификаторы и секреты должны быть уникальны.")
        ids.add(user["id"])
        keys.add(user["secret"])
    if not any(u["enabled"] for u in users):
        raise ValueError("Нужно оставить хотя бы одно включённое подключение.")
    return document


def revision(document):
    return hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()


def proxy_link(domain, secret):
    return "https://t.me/webproxy?server=" + domain + "&secret=" + secret
