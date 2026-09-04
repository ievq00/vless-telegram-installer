import hashlib
import os
import shutil
import subprocess
import tarfile
import time
import urllib.request
from pathlib import Path


PROXY = None


def sha256(path):
    result = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def download(spec, cache):
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / (spec["sha256"] + ".tar.gz")
    if target.is_file() and sha256(target) == spec["sha256"]:
        return target
    partial = target.with_suffix(".partial")
    for attempt in range(3):
        try:
            if PROXY:
                subprocess.run(["curl", "-fsSL", "--proto", "=https", "--proto-redir", "=https", "--proxy", PROXY, "--connect-timeout", "15", "--max-time", "600", "-o", str(partial), spec["url"]], check=True, timeout=610, capture_output=True)
                if sha256(partial) != spec["sha256"]:
                    raise RuntimeError("Контрольная сумма загрузки не совпадает.")
                os.replace(partial, target)
                return target
            request = urllib.request.Request(spec["url"], headers={"User-Agent": "vless-telegram-installer/1.0"})
            start = time.monotonic()
            size = 0
            with urllib.request.urlopen(request, timeout=45) as source, open(partial, "wb") as out:
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    size += len(block)
                    if size > 400 * 1024 * 1024 or time.monotonic() - start > 600:
                        raise RuntimeError("Превышен размер или время загрузки.")
                    out.write(block)
            if sha256(partial) != spec["sha256"]:
                raise RuntimeError("Контрольная сумма загрузки не совпадает.")
            os.replace(partial, target)
            return target
        except Exception:
            partial.unlink(missing_ok=True)
            if attempt == 2:
                raise
            time.sleep(attempt + 1)


def extract(archive, destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    total = 0
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        for member in members:
            path = (destination / member.name).resolve()
            if not path.is_relative_to(destination):
                raise ValueError("Архив содержит небезопасный путь.")
            if not member.isfile() and not member.isdir():
                raise ValueError("Архив содержит неподдерживаемые ссылки или устройства.")
            total += member.size
            if total > 2 * 1024 * 1024 * 1024:
                raise ValueError("Архив слишком большой.")
        for member in members:
            path = destination / member.name
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with bundle.extractfile(member) as source, open(path, "wb") as output:
                    shutil.copyfileobj(source, output)
                path.chmod(0o755 if member.mode & 0o111 else 0o644)
    return destination
