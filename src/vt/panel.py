"""Small local-only administration app; no third-party frontend dependencies."""
import collections
import html
import json
import secrets
import socket
import subprocess
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from .common import APP, ETC, PANEL_STATE, password_matches, proxy_link, read_json, revision, validate_users, write_json

escape = lambda value: html.escape(str(value), quote=True)


class PanelServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, config, state=PANEL_STATE, secure=True):
        self.config, self.state, self.secure = config, state, secure
        self.sessions, self.login_tokens = {}, {}
        self.failures = collections.OrderedDict()
        self.lock = threading.RLock()
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(address, Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "Web"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_):
        pass

    @property
    def base(self):
        return self.server.config["panel_path"]

    def cookie(self, name):
        try:
            value = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            return value[name].value if name in value else ""
        except cookies.CookieError:
            return ""

    def response(self, code, body=b"", kind="text/html; charset=utf-8", cookie=None, location=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if cookie:
            suffix = "; Path=/; HttpOnly; SameSite=Strict" + ("; Secure" if self.server.secure else "")
            self.send_header("Set-Cookie", cookie + suffix)
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(body)

    def page(self, title, content, **kwargs):
        page = '<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        page += '<title>' + escape(title) + '</title><link rel="stylesheet" href="' + self.base + '/style.css">'
        page += '<body><main><header><span class="brand">TELEGRAM / WEB PROXY</span><h1>' + escape(title) + '</h1></header>'
        page += content + '<footer>VLESS + Telegram · личная панель управления</footer></main><script src="' + self.base + '/app.js" defer></script></body></html>'
        self.response(kwargs.pop("code", 200), page, **kwargs)

    def session(self):
        token = self.cookie("__Host-vt_session")
        now = time.time()
        with self.server.lock:
            self.server.sessions = {k: v for k, v in self.server.sessions.items() if v["until"] > now}
            return self.server.sessions.get(token)

    def login_page(self, error=""):
        token = secrets.token_urlsafe(24)
        with self.server.lock:
            now = time.time()
            self.server.login_tokens = {k: v for k, v in self.server.login_tokens.items() if v > now}
            if len(self.server.login_tokens) >= 500:
                self.server.login_tokens.clear()
            self.server.login_tokens[token] = now + 600
        content = '<section class="card login"><p>Войдите, чтобы управлять подключениями.</p>'
        if error:
            content += '<p class="error">' + escape(error) + '</p>'
        content += '<form method="post" action="' + self.base + '/login"><input type="hidden" name="csrf" value="' + token + '">'
        content += '<label>Логин<input name="username" value="admin" autocomplete="username" required></label><label>Пароль<input type="password" name="password" autocomplete="current-password" required></label><button>Войти</button></form></section>'
        self.page("Вход в панель", content, cookie="__Host-vt_login=" + token + "; Max-Age=600")

    def do_GET(self):
        path = urlsplit(self.path).path
        if path in (self.base + "/style.css", self.base + "/app.js"):
            name = path.rsplit("/", 1)[1]
            kind = "text/css; charset=utf-8" if name.endswith(".css") else "application/javascript; charset=utf-8"
            return self.response(200, (APP / "web" / name).read_bytes(), kind)
        if path == self.base + "/login":
            return self.login_page()
        session = self.session()
        if not session:
            return self.response(303, location=self.base + "/login")
        if path.startswith(self.base + "/qr/"):
            uid = path.rsplit("/", 1)[1]
            users = validate_users(read_json(self.server.state / "users.json"))["users"]
            user = next((u for u in users if u["id"] == uid), None)
            if not user:
                return self.response(404, "Подключение не найдено.", "text/plain; charset=utf-8")
            result = subprocess.run(["qrencode", "-t", "SVG", "-o", "-"],
                                    input=proxy_link(self.server.config["domain"], user["secret"]),
                                    capture_output=True, text=True, timeout=3, check=True)
            return self.response(200, result.stdout, "image/svg+xml")
        if path not in (self.base, self.base + "/", self.base + "/users"):
            return self.response(404, "Страница не найдена.", "text/plain; charset=utf-8")
        document = validate_users(read_json(self.server.state / "users.json"))
        try:
            state = read_json(self.server.state / "status.json")
        except (OSError, ValueError):
            state = {}
        synced = state.get("revision") == revision(document) and state.get("ok")
        pending = '<p class="notice">Настройки применяются. Обновите страницу через несколько секунд.</p>'
        if state.get("ok") is False:
            pending = '<p class="error">Последнее изменение не применено. Проверьте состояние службы vt-sync на сервере.</p>'
        content = '<div class="toolbar"><span class="pill">' + escape(self.server.config["domain"]) + '</span>'
        content += '<form method="post" action="' + self.base + '/logout">' + self.csrf_input(session) + '<button class="secondary">Выйти</button></form></div>'
        if not synced:
            content += pending
        content += '<section class="card"><h2>Новое подключение</h2><form method="post" action="' + self.base + '/add" class="row">'
        content += self.csrf_input(session) + '<label class="grow">Название<input name="name" maxlength="60" required placeholder="Например, мой телефон"></label><button>Создать ссылку</button></form><p class="muted">До 32 отдельных ссылок. Нужен Telegram с поддержкой WEB Proxy.</p></section>'
        for user in document["users"]:
            link = proxy_link(self.server.config["domain"], user["secret"])
            content += '<section class="card"><div class="row"><h2 class="grow">' + escape(user["name"]) + '</h2><span class="pill">' + ("Включено" if user["enabled"] else "Выключено") + '</span></div>'
            content += '<input class="link" readonly aria-label="Ссылка подключения" value="' + escape(link) + '"><div class="actions">'
            content += '<a class="button" href="' + escape(link) + '" rel="noreferrer">Подключить</a><button class="secondary" type="button" data-copy="' + escape(link) + '">Скопировать</button>'
            content += '<a class="button secondary" href="' + self.base + '/qr/' + user["id"] + '" target="_blank" rel="noopener">QR-код</a></div>'
            content += '<div class="actions small">'
            for action, label, confirmation in (
                    ("toggle", "Выключить" if user["enabled"] else "Включить", ""),
                    ("rotate", "Заменить секрет", "Старая ссылка перестанет работать. Продолжить?"),
                    ("delete", "Удалить", "Удалить это подключение?")):
                content += '<form method="post" action="' + self.base + '/' + action + '"' + (' data-confirm="' + escape(confirmation) + '"' if confirmation else "") + '>'
                content += self.csrf_input(session) + '<input type="hidden" name="id" value="' + user["id"] + '"><button class="text-button">' + label + '</button></form>'
            content += '</div></section>'
        content += '<p class="muted">Изменения применяются автоматически и на несколько секунд переподключают активных пользователей.</p>'
        self.page("Ваши подключения", content)

    def csrf_input(self, session):
        return '<input type="hidden" name="csrf" value="' + session["csrf"] + '">'

    def do_POST(self):
        try:
            self.handle_post()
        except (ValueError, KeyError) as exc:
            self.page("Не удалось сохранить", '<section class="card"><p class="error">' + escape(str(exc)) + '</p><a href="' + self.base + '/users">Вернуться</a></section>', code=400)

    def handle_post(self):
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Передача по частям не поддерживается.")
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 16384:
            raise ValueError("Некорректный размер запроса.")
        if self.headers.get("Content-Type", "").split(";")[0] != "application/x-www-form-urlencoded":
            raise ValueError("Некорректный тип запроса.")
        origin = self.headers.get("Origin")
        if origin and origin != "https://" + self.server.config["domain"]:
            return self.response(403, "Запрос отклонён.", "text/plain; charset=utf-8")
        fields = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True, max_num_fields=10)
        if any(len(v) != 1 for v in fields.values()):
            raise ValueError("Повторяющиеся поля.")
        data = {k: v[0] for k, v in fields.items()}
        path = urlsplit(self.path).path
        if path == self.base + "/login":
            token = self.cookie("__Host-vt_login")
            with self.server.lock:
                expiry = self.server.login_tokens.pop(token, 0)
            if expiry < time.time() or not secrets.compare_digest(token, data.get("csrf", "")):
                return self.login_page("Страница устарела. Повторите вход.")
            ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()[:100]
            now = time.time()
            with self.server.lock:
                attempts = [t for t in self.server.failures.get(ip, []) if now - t < 300]
                self.server.failures[ip] = attempts
                while len(self.server.failures) > 1000:
                    self.server.failures.popitem(last=False)
                if len(attempts) >= 8:
                    return self.response(429, "Повторите вход через 5 минут.", "text/plain; charset=utf-8")
                attempts.append(now)
            valid_password = password_matches(data.get("password", ""), self.server.config["password_hash"])
            if data.get("username") != "admin" or not valid_password:
                return self.login_page("Неверный логин или пароль.")
            session_token = secrets.token_urlsafe(32)
            with self.server.lock:
                self.server.failures.pop(ip, None)
                if len(self.server.sessions) >= 100:
                    self.server.sessions.clear()
                self.server.sessions[session_token] = {"until": now + 43200, "csrf": secrets.token_urlsafe(24)}
            return self.response(303, cookie="__Host-vt_session=" + session_token + "; Max-Age=43200",
                                 location=self.base + "/users")
        session = self.session()
        if not session or not secrets.compare_digest(session["csrf"], data.get("csrf", "")):
            return self.response(403, "Запрос отклонён.", "text/plain; charset=utf-8")
        if path == self.base + "/logout":
            with self.server.lock:
                self.server.sessions.pop(self.cookie("__Host-vt_session"), None)
            return self.response(303, cookie="__Host-vt_session=; Max-Age=0", location=self.base + "/login")
        action = path.removeprefix(self.base + "/")
        if action not in ("add", "toggle", "rotate", "delete"):
            return self.response(404, "Страница не найдена.", "text/plain; charset=utf-8")
        with self.server.lock:
            document = validate_users(read_json(self.server.state / "users.json"))
            users = document["users"]
            if action == "add":
                users.append({"id": secrets.token_hex(8), "name": data.get("name", "").strip(),
                              "secret": secrets.token_hex(16), "enabled": True})
            else:
                user = next((u for u in users if u["id"] == data.get("id")), None)
                if user is None:
                    raise ValueError("Подключение не найдено.")
                if action == "toggle":
                    user["enabled"] = not user["enabled"]
                elif action == "rotate":
                    user["secret"] = secrets.token_hex(16)
                else:
                    users.remove(user)
            validate_users(document)
            write_json(self.server.state / "users.json", document, mode=0o640)
        self.response(303, location=self.base + "/users")


def main():
    server = PanelServer(("127.0.0.1", 8090), read_json(ETC / "panel.json"))
    server.serve_forever()


if __name__ == "__main__":
    main()
