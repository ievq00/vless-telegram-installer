"""Install the complete stack on a dedicated Ubuntu/Debian system."""
import argparse
import contextlib
import getpass
import grp
import ipaddress
import json
import os
import platform
import pwd
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from . import __version__
from .common import APP, ETC, STATE, PANEL_STATE, UNITS, atomic_write, password_hash, proxy_link, read_json, revision, validate_users, write_json
from .downloads import download, extract
from .render import caddyfile, relay_config, service, site, units
from .vless import email_address, hostname, parse_vless, singbox_config

SOURCE = Path(__file__).resolve().parents[2]
CACHE = Path("/var/cache/vless-telegram")
UNIT_DIR = Path("/etc/systemd/system")


def say(text):
    print(text, flush=True)


def run(args, timeout=120, capture=False, env=None):
    return subprocess.run(args, check=True, timeout=timeout, text=True,
                          capture_output=capture, env=env)


def collect(options):
    old = read_json(ETC / "installation.json") if (ETC / "installation.json").is_file() else {}
    if options.config:
        path = Path(options.config)
        if path.stat().st_mode & 0o077:
            raise ValueError("Файл настроек должен быть закрыт от других пользователей: chmod 600 " + str(path))
        if path.stat().st_size > 16384:
            raise ValueError("Файл настроек слишком большой.")
        data = read_json(path)
        if set(data) != {"vless_uri", "domain", "email"}:
            raise ValueError("В JSON нужны ровно три поля: vless_uri, domain, email.")
    elif old and not options.reconfigure:
        data = {key: old[key] for key in ("vless_uri", "domain", "email")}
        say("Использую сохранённые настройки. Для их замены добавьте --reconfigure.")
    else:
        try:
            terminal = open("/dev/tty", "r+")
        except OSError as exc:
            raise ValueError("Нет интерактивного терминала. Передайте --config /путь/настройки.json.") from exc
        with terminal:
            terminal.write("\nVLESS + Telegram WEB Proxy\nТри параметра для установки.\n")
            terminal.flush()
            link = getpass.getpass("VLESS-ссылка (ввод скрыт): ", stream=terminal)
            terminal.write("Домен Telegram-прокси: ")
            terminal.flush()
            domain = terminal.readline().strip()
            terminal.write("Email для HTTPS-сертификата: ")
            terminal.flush()
            email = terminal.readline().strip()
            data = {"vless_uri": link, "domain": domain, "email": email}
    data["vless_uri"] = data["vless_uri"].strip()
    data["domain"] = hostname(data["domain"])
    data["email"] = email_address(data["email"])
    outbound = parse_vless(data["vless_uri"])
    if options.lab and (not data["domain"].endswith(".test") or not Path("/run/vt-installer-lab").is_file()):
        raise ValueError("--lab разрешён только внутри тестового окружения с доменом .test.")
    return data, outbound, old


def preflight(existing, laboratory=False):
    if os.geteuid() != 0:
        raise ValueError("Запустите установщик через sudo.")
    if not Path("/run/systemd/system").is_dir():
        raise ValueError("Нужна система с работающим systemd.")
    release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            release[key] = value.strip('"')
    major = int(release.get("VERSION_ID", "0").split(".")[0])
    if not ((release.get("ID") == "ubuntu" and major >= 22) or (release.get("ID") == "debian" and major >= 12)):
        raise ValueError("Поддерживаются Ubuntu 22.04+ и Debian 12+.")
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if not arch:
        raise ValueError("Поддерживаются amd64 и arm64.")
    if shutil.disk_usage("/").free < 1600 * 1024 * 1024:
        raise ValueError("Нужно не менее 1.6 ГБ свободного места.")
    if not existing:
        for path in (APP, ETC, STATE):
            if path.exists() and any(path.iterdir()):
                raise ValueError(str(path) + " уже существует и не принадлежит этой установке.")
        for port in (80, 443, 1080, 2398, 8080, 8081, 8090, 8888):
            with socket.socket() as probe:
                try:
                    probe.bind(("0.0.0.0", port))
                except OSError as exc:
                    raise ValueError("Порт " + str(port) + " уже занят. Нужен отдельный сервер или ручная интеграция.") from exc
    return arch


def check_dns(domain, laboratory):
    if laboratory:
        return
    addresses = {item[4][0] for item in socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)}
    local = set()
    data = json.loads(run(["ip", "-j", "address", "show"], capture=True).stdout)
    for item in data:
        for address in item.get("addr_info", []):
            if address["family"] == "inet":
                ip = ipaddress.ip_address(address["local"])
                if ip.is_global:
                    local.add(str(ip))
    if not local:
        for endpoint in ("https://api.ipify.org", "https://ipv4.icanhazip.com"):
            try:
                value = run(["curl", "-4", "-fsS", "--max-time", "12", endpoint], capture=True).stdout.strip()
                if ipaddress.ip_address(value).is_global:
                    local.add(value)
                    break
            except Exception:
                continue
    if not addresses or not local or not addresses.issubset(local):
        raise ValueError("DNS домена не указывает на этот сервер. Укажите A-запись на его публичный IPv4 и отключите CDN-проксирование.")
    # An incorrect AAAA can make ACME try an unreachable IPv6 server.
    try:
        ipv6 = {x[4][0] for x in socket.getaddrinfo(domain, 443, socket.AF_INET6, socket.SOCK_STREAM)}
    except socket.gaierror:
        ipv6 = set()
    local6 = {a["local"] for x in data for a in x.get("addr_info", []) if a["family"] == "inet6"}
    if ipv6 and not ipv6.issubset(local6):
        raise ValueError("AAAA-запись домена указывает на посторонний IPv6. Исправьте её или удалите.")


def public_code_tree(path):
    for current, directories, files in os.walk(path, followlinks=False):
        Path(current).chmod(0o755)
        for filename in files:
            file = Path(current) / filename
            if not file.is_symlink():
                file.chmod(0o755 if file.stat().st_mode & 0o111 else 0o644)


def accounts():
    for name in UNITS:
        try:
            pwd.getpwnam(name)
        except KeyError:
            run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
                 "--shell", "/usr/sbin/nologin", name])
    for path in (APP, ETC, STATE, PANEL_STATE, CACHE, STATE / "caddy"):
        path.mkdir(parents=True, exist_ok=True)
    APP.chmod(0o755)
    ETC.chmod(0o755)
    STATE.chmod(0o711)
    for path, user in ((PANEL_STATE, "vt-panel"), (STATE / "caddy", "vt-caddy")):
        account = pwd.getpwnam(user)
        os.chown(path, account.pw_uid, account.pw_gid)
        path.chmod(0o750)


def save_configuration(data, outbound, old, laboratory):
    current = dict(data)
    current["version"] = __version__
    current["panel_path"] = old.get("panel_path") or "/panel-" + secrets.token_hex(16)
    current["admin_password"] = old.get("admin_password") or secrets.token_urlsafe(24)
    current["password_hash"] = old.get("password_hash") or password_hash(current["admin_password"])
    write_json(ETC / "installation.json", current)
    write_json(ETC / "sing-box.json", singbox_config(outbound), mode=0o640, gid=grp.getgrnam("vt-vless").gr_gid)
    write_json(ETC / "panel.json", {k: current[k] for k in ("domain", "panel_path", "password_hash")},
               mode=0o640, gid=grp.getgrnam("vt-panel").gr_gid)
    if not (PANEL_STATE / "users.json").exists():
        document = {"users": [{"id": secrets.token_hex(8), "name": "Основное подключение",
                              "secret": secrets.token_hex(16), "enabled": True}]}
        account = pwd.getpwnam("vt-panel")
        write_json(PANEL_STATE / "users.json", document, mode=0o640, uid=account.pw_uid, gid=account.pw_gid)
    document = validate_users(read_json(PANEL_STATE / "users.json"))
    from .control import materialize
    keys, profiles = materialize(document)
    write_json(ETC / "backend-users.json", keys, mode=0o640, gid=grp.getgrnam("vt-backend").gr_gid)
    write_json(ETC / "profiles.json", profiles, mode=0o600, uid=pwd.getpwnam("vt-relay").pw_uid, gid=grp.getgrnam("vt-relay").gr_gid)
    write_json(ETC / "relay.json", relay_config(current["domain"]), mode=0o644)
    atomic_write(ETC / "Caddyfile", caddyfile(current["domain"], current["email"], current["panel_path"], laboratory), mode=0o644)
    (APP / "site").mkdir(exist_ok=True)
    if not (APP / "site" / "index.html").exists():
        atomic_write(APP / "site" / "index.html", site(current["domain"]), mode=0o644)
    write_json(STATE / "applied-users.json", document)
    write_json(PANEL_STATE / "status.json", {"revision": revision(document), "ok": True},
               mode=0o640, gid=grp.getgrnam("vt-panel").gr_gid)
    return current


def copy_owned_tree(source, target):
    def copy_file(a, b):
        shutil.copy2(a, b, follow_symlinks=False)
        info = os.lstat(a)
        os.chown(b, info.st_uid, info.st_gid, follow_symlinks=False)
        return b
    shutil.copytree(source, target, dirs_exist_ok=True, symlinks=True, copy_function=copy_file)
    for current, directories, _ in os.walk(source, followlinks=False):
        relative = Path(current).relative_to(source)
        info = os.stat(current)
        os.chown(Path(target) / relative, info.st_uid, info.st_gid)
        for directory in directories:
            child = Path(current) / directory
            if child.is_symlink():
                info = child.lstat()
                os.chown(Path(target) / relative / directory, info.st_uid, info.st_gid, follow_symlinks=False)


class Snapshot:
    def __init__(self, existing):
        self.existing = bool(existing)
        self.active, self.enabled = {}, {}
        self.path = Path("/var/backups/vless-telegram") / (time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3))
        self.path.mkdir(parents=True, mode=0o700)
        self.saved = []
        self.unit_names = list(units())
        if self.existing:
            for path in (APP, ETC, STATE):
                if path.exists():
                    destination = self.path / path.name
                    # APP and STATE share their basename, so use their parent component too.
                    destination = self.path / (path.parent.name + "-" + path.name)
                    copy_owned_tree(path, destination)
                    self.saved.append((path, destination))
        for unit in self.unit_names:
            path = UNIT_DIR / unit
            if path.exists():
                shutil.copy2(path, self.path / unit)
            self.active[unit] = subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0
            self.enabled[unit] = subprocess.run(["systemctl", "is-enabled", "--quiet", unit], capture_output=True).returncode == 0

    def restore(self):
        say("Установка не завершена. Восстанавливаю предыдущие службы.")
        subprocess.run(["systemctl", "stop", "vt-sync.path", *[x + ".service" for x in UNITS]], capture_output=True, timeout=60)
        for target, source in self.saved:
            copy_owned_tree(source, target)
        for unit in self.unit_names:
            saved, target = self.path / unit, UNIT_DIR / unit
            if saved.exists():
                shutil.copy2(saved, target)
            elif target.exists():
                subprocess.run(["systemctl", "disable", unit], capture_output=True)
                target.unlink()
        run(["systemctl", "daemon-reload"])
        for unit in self.unit_names:
            if self.enabled[unit]:
                subprocess.run(["systemctl", "enable", unit], capture_output=True)
            if self.active[unit]:
                subprocess.run(["systemctl", "start", unit], capture_output=True, timeout=45)
        say("Резервная копия: " + str(self.path))


def install_binary(spec, executable, name):
    with tempfile.TemporaryDirectory(prefix="vt-extract-", dir=CACHE) as scratch:
        root = extract(download(spec, CACHE), scratch)
        matches = [p for p in root.rglob(executable) if p.is_file()]
        if len(matches) != 1:
            raise RuntimeError("Не удалось найти " + executable + " в архиве.")
        (APP / "bin").mkdir(exist_ok=True)
        (APP / "bin").chmod(0o755)
        atomic_write(APP / "bin" / name, matches[0].read_bytes(), mode=0o755)


def install_source(spec, directory):
    with tempfile.TemporaryDirectory(prefix="vt-source-", dir=CACHE) as scratch:
        root = extract(download(spec, CACHE), scratch)
        children = [p for p in root.iterdir() if p.is_dir()]
        if len(children) != 1:
            raise RuntimeError("Некорректная структура архива исходников.")
        shutil.copytree(children[0], directory, dirs_exist_ok=True)


def check_vless():
    for endpoint in ("https://api.ipify.org", "https://ipv4.icanhazip.com"):
        try:
            result = run(["curl", "-4", "-fsS", "--proxy", "socks5h://127.0.0.1:1080",
                          "--connect-timeout", "8", "--max-time", "20", endpoint], capture=True, timeout=25)
            value = str(ipaddress.ip_address(result.stdout.strip()))
            say("VLESS работает. Адрес выхода: " + value)
            return value
        except Exception:
            continue
    raise RuntimeError("VLESS не передаёт данные. Проверьте ссылку, доступность сервера, SNI и ключ REALITY.")


def install(options):
    data, outbound, old = collect(options)
    if options.check_config:
        say("Настройки корректны: домен " + data["domain"] + ", VLESS " + outbound.get("transport", {}).get("type", "tcp") + ".")
        return
    arch = preflight(old, options.lab)
    say("1/7 · Подготавливаю системные пакеты.")
    env = dict(os.environ, DEBIAN_FRONTEND= "noninteractive")
    run(["apt-get", "-o", "DPkg::Lock::Timeout=120", "update"], timeout=300, env=env)
    run(["apt-get", "-o", "DPkg::Lock::Timeout=120", "install", "-y", "--no-install-recommends",
         "ca-certificates", "curl", "iproute2", "python3", "python3-cryptography", "python3-socks",
         "qrencode", "tar"], timeout=600, env=env)
    check_dns(data["domain"], options.lab)
    snapshot = Snapshot(old)
    try:
        subprocess.run(["systemctl", "stop", "vt-sync.path", "vt-sync.service"], capture_output=True, timeout=90)
        accounts()
        shutil.copytree(SOURCE / "src", APP / "src", dirs_exist_ok=True)
        shutil.copytree(SOURCE / "web", APP / "web", dirs_exist_ok=True)
        shutil.copy2(SOURCE / "dependencies.lock.json", APP / "dependencies.lock.json")
        public_code_tree(APP)
        lock = read_json(APP / "dependencies.lock.json")
        current = save_configuration(data, outbound, old, options.lab)
        public_code_tree(APP)
        for name, body in units().items():
            atomic_write(UNIT_DIR / name, body, mode=0o644)
        run(["systemctl", "daemon-reload"])
        say("2/7 · Устанавливаю и проверяю VLESS-клиент.")
        install_binary(lock["sing_box"][arch], "sing-box", "sing-box")
        run([str(APP / "bin" / "sing-box"), "check", "-c", str(ETC / "sing-box.json")], capture=True)
        run(["systemctl", "restart", "vt-vless"], timeout=45)
        exit_ip = check_vless()
        from . import downloads
        downloads.PROXY = "socks5h://127.0.0.1:1080"
        say("3/7 · Загружаю Telegram-компоненты с проверкой SHA-256.")
        install_binary(lock["caddy"][arch], "caddy", "caddy")
        vendor = APP / "vendor"
        vendor.mkdir(exist_ok=True)
        install_source(lock["backend"], vendor / "mtprotoproxy")
        install_source(lock["relay"], vendor / "relay")
        go_dir = CACHE / ("go-" + lock["go"]["version"] + "-" + arch)
        go_executable = go_dir / "go" / "bin" / "go"
        if not go_executable.exists():
            extract(download(lock["go"][arch], CACHE), go_dir)
        say("4/7 · Собираю WEB-прокси.")
        build_env = dict(os.environ, CGO_ENABLED="0", GOMAXPROCS="1", GOMEMLIMIT="700MiB",
                         GOCACHE=str(CACHE / "gocache"), GOPATH=str(CACHE / "gopath"),
                         GOMODCACHE=str(CACHE / "gomod"), GOTOOLCHAIN="local",
                         HTTPS_PROXY="socks5://127.0.0.1:1080", HTTP_PROXY="socks5://127.0.0.1:1080")
        run([str(go_executable), "-C", str(vendor / "relay"), "build", "-trimpath", "-ldflags=-s -w",
             "-o", str(APP / "bin" / "tproxy-server"), "./cmd/tproxy-server"], timeout=1200, env=build_env)
        public_code_tree(APP)
        say("5/7 · Запускаю панель, Telegram-прокси и HTTPS.")
        run([str(APP / "bin" / "caddy"), "validate", "--config", str(ETC / "Caddyfile"), "--adapter", "caddyfile"], capture=True)
        for unit in ("vt-backend", "vt-relay", "vt-panel", "vt-caddy"):
            run(["systemctl", "restart", unit], timeout=45)
        if shutil.which("ufw"):
            status = subprocess.run(["ufw", "status"], capture_output=True, text=True).stdout
            if "Status: active" in status:
                # Never reset the firewall or change its default policy / SSH rules.
                run(["ufw", "allow", "80/tcp", "comment", "vless-telegram HTTP"])
                run(["ufw", "allow", "443/tcp", "comment", "vless-telegram HTTPS"])
        say("6/7 · Ожидаю HTTPS-сертификат и проверяю ответ Telegram.")
        from .verify import verify
        users = validate_users(read_json(PANEL_STATE / "users.json"))["users"]
        secret = next(u["secret"] for u in users if u["enabled"])
        deadline = time.monotonic() + 240
        certificate = None
        last_error = ""
        while time.monotonic() < deadline:
            try:
                if options.lab:
                    certificate = STATE / "caddy/data/caddy/pki/authorities/local/root.crt"
                verify(current["domain"], secret, ca_file=certificate, timeout=15)
                break
            except Exception as exc:
                last_error = type(exc).__name__ + ": " + str(exc)
                time.sleep(5)
        else:
            raise RuntimeError("Проверка HTTPS/Telegram не прошла: " + last_error + ". Проверьте DNS и входящие порты 80/443 у хостинга.")
        say("7/7 · Включаю автозапуск и сохраняю данные доступа.")
        run(["systemctl", "enable", *[x + ".service" for x in UNITS], "vt-sync.path"], capture=True)
        run(["systemctl", "start", "vt-sync.path"])
        access = "Telegram WEB Proxy\n" + proxy_link(current["domain"], secret) + "\n\n"
        access += "Панель: https://" + current["domain"] + current["panel_path"] + "/login\n"
        access += "Логин: admin\nПароль: " + current["admin_password"] + "\n"
        access += "\nВыход VLESS: " + exit_ip + "\nНужен Telegram с поддержкой WEB Proxy.\n"
        atomic_write(ETC / "access.txt", access)
        current["installed_ok"] = True
        write_json(ETC / "installation.json", current)
        say("\nУстановка завершена. Ответ Telegram проверен.\n\n" + access)
        say("Данные также сохранены в " + str(ETC / "access.txt"))
    except BaseException:
        snapshot.restore()
        raise


def main():
    parser = argparse.ArgumentParser(description="VLESS + Telegram WEB Proxy")
    parser.add_argument("--config", help="JSON: vless_uri, domain, email; права 600")
    parser.add_argument("--reconfigure", action="store_true", help="Заново запросить три параметра")
    parser.add_argument("--check-config", action="store_true", help="Проверить входные данные без установки")
    parser.add_argument("--lab", action="store_true", help=argparse.SUPPRESS)
    options = parser.parse_args()
    try:
        install(options)
    except (Exception, KeyboardInterrupt) as exc:
        say("\nУстановка остановлена: " + str(exc))
        say("Исправьте причину и повторите запуск. Для новой VLESS-ссылки используйте --reconfigure.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
