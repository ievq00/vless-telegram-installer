"""Strict conversion of common vless:// links to sing-box configuration."""
import base64
import ipaddress
import re
import uuid
from urllib.parse import parse_qs, unquote, urlsplit


def hostname(value):
    value = value.strip().rstrip(".").lower()
    if not value or len(value) > 253 or any(c in value for c in "/:@\\ \t\r\n"):
        raise ValueError("Укажите домен без https://, пути и порта.")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Некорректный домен.") from exc
    if "." not in value or not all(re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)", part) for part in value.split(".")):
        raise ValueError("Некорректный домен.")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("Для HTTPS нужен домен, а не IP-адрес.")


def email_address(value):
    value = value.strip()
    if len(value) > 254 or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", value):
        raise ValueError("Укажите email, например name@example.com.")
    return value


def parse_vless(link):
    link = link.strip()
    if len(link) > 8192 or any(ord(c) < 32 for c in link):
        raise ValueError("Некорректная VLESS-ссылка.")
    try:
        parsed = urlsplit(link)
        if parsed.scheme.lower() != "vless" or not parsed.hostname or not parsed.username or parsed.password:
            raise ValueError()
        account = str(uuid.UUID(unquote(parsed.username)))
        port = parsed.port or 443
        if not 1 <= port <= 65535:
            raise ValueError()
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Ожидается vless://UUID@сервер:порт?...") from exc
    params = parse_qs(parsed.query, keep_blank_values=True)
    if any(len(values) != 1 for values in params.values()):
        raise ValueError("VLESS-ссылка содержит повторяющиеся параметры.")
    q = {key: values[0] for key, values in params.items()}
    if any(any(ord(c) < 32 for c in value) for value in q.values()):
        raise ValueError("Параметры содержат управляющие символы.")
    supported = {"encryption", "security", "type", "flow", "sni", "serverName", "fp", "pbk", "sid", "spx",
                 "alpn", "allowInsecure", "insecure", "host", "path", "serviceName", "mode",
                 "packetEncoding", "headerType", "remarks", "fragment", "eh", "ed"}
    unknown = set(q) - supported
    if unknown:
        raise ValueError("Неподдерживаемые параметры VLESS: " + ", ".join(sorted(unknown)))
    if q.get("encryption", "none") != "none":
        raise ValueError("Эта версия поддерживает VLESS encryption=none.")
    if q.get("headerType", "none") not in ("", "none"):
        raise ValueError("Маскировка headerType не поддерживается.")
    if q.get("fragment") or q.get("mode", "gun") not in ("", "gun"):
        raise ValueError("Параметры fragment и gRPC multiMode не поддерживаются.")
    transport = q.get("type", "tcp").lower()
    if transport == "raw":
        transport = "tcp"
    if transport not in ("tcp", "ws", "grpc", "http", "h2"):
        raise ValueError("Поддерживаются TCP, WebSocket, gRPC и HTTP/2; получен " + transport)
    flow = q.get("flow", "")
    if flow not in ("", "xtls-rprx-vision"):
        raise ValueError("Неподдерживаемый flow.")
    if flow and transport != "tcp":
        raise ValueError("XTLS Vision допускается только с TCP.")
    server = parsed.hostname
    try:
        ipaddress.ip_address(server)
    except ValueError:
        server = hostname(server)
    result = {"type": "vless", "tag": "vless", "server": server, "server_port": port, "uuid": account}
    if flow:
        result["flow"] = flow
    security = q.get("security", "none").lower()
    if security not in ("none", "tls", "reality"):
        raise ValueError("Неподдерживаемый security.")
    if flow and security == "none":
        raise ValueError("XTLS Vision требует TLS или REALITY.")
    if security != "none":
        sni = q.get("sni") or q.get("serverName") or server
        if any(c.isspace() for c in sni) or any(c in sni for c in "/\\"):
            raise ValueError("Некорректный SNI.")
        tls = {"enabled": True, "server_name": sni}
        insecure = q.get("allowInsecure", q.get("insecure", "0"))
        if insecure not in ("0", "false", "", "1", "true"):
            raise ValueError("Некорректный allowInsecure.")
        if insecure in ("1", "true"):
            tls["insecure"] = True
        fp = q.get("fp", "chrome")
        if fp not in ("", "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"):
            raise ValueError("Неподдерживаемый отпечаток TLS.")
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        if q.get("alpn"):
            alpn = q["alpn"].split(",")
            if any(not x or len(x) > 255 or any(ord(c) < 32 for c in x) for x in alpn):
                raise ValueError("Некорректный ALPN.")
            tls["alpn"] = alpn
        if security == "reality":
            public_key = q.get("pbk", "")
            try:
                if not re.fullmatch(r"[A-Za-z0-9_-]{43}", public_key):
                    raise ValueError()
                if len(base64.urlsafe_b64decode(public_key + "=" * (-len(public_key) % 4))) != 32:
                    raise ValueError()
            except Exception as exc:
                raise ValueError("Для REALITY нужен корректный pbk.") from exc
            short_id = q.get("sid", "")
            if not re.fullmatch(r"(?:[a-fA-F0-9]{2}){0,8}", short_id):
                raise ValueError("Некорректный REALITY sid.")
            tls["reality"] = {"enabled": True, "public_key": public_key, "short_id": short_id}
        result["tls"] = tls
    if transport == "ws":
        value = {"type": "ws", "path": q.get("path") or "/"}
        if q.get("host"):
            value["headers"] = {"Host": q["host"]}
        if q.get("ed"):
            if not q["ed"].isdigit() or not 0 <= int(q["ed"]) <= 65535:
                raise ValueError("Некорректный размер early data.")
            value.update(max_early_data=int(q["ed"]), early_data_header_name=q.get("eh") or "Sec-WebSocket-Protocol")
        result["transport"] = value
    elif transport == "grpc":
        result["transport"] = {"type": "grpc", "service_name": q.get("serviceName", "")}
    elif transport in ("http", "h2"):
        result["transport"] = {"type": "http", "path": q.get("path") or "/"}
        if q.get("host"):
            result["transport"]["host"] = q["host"].split(",")
    if q.get("packetEncoding"):
        if q["packetEncoding"] not in ("xudp", "packetaddr"):
            raise ValueError("Неподдерживаемый packetEncoding.")
        result["packet_encoding"] = q["packetEncoding"]
    return result


def singbox_config(outbound, port=1080):
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {"servers": [{"type": "local", "tag": "system"}]},
        "inbounds": [{"type": "socks", "tag": "telegram", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [outbound],
        "route": {"final": "vless", "default_domain_resolver": "system"},
    }
