"""Validation and expansion of direct VLESS links and HTTPS subscriptions."""
import base64
import ipaddress
import socket
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from .vless import parse_vless

MAX_SOURCES = 32
MAX_SUBSCRIPTION = 262144


def validate_vless_settings(document):
    if not isinstance(document, dict) or set(document) != {"sources", "check_interval_minutes"}:
        raise ValueError("Некорректные настройки VLESS.")
    sources = document["sources"]
    interval = document["check_interval_minutes"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_SOURCES:
        raise ValueError("Добавьте от 1 до 32 VLESS-ссылок или подписок.")
    if type(interval) is not int or not 5 <= interval <= 1440:
        raise ValueError("Интервал проверки должен быть от 5 до 1440 минут.")
    seen = set()
    for source in sources:
        if not isinstance(source, str):
            raise ValueError("Некорректный источник VLESS.")
        source = source.strip()
        if not source or len(source) > 8192 or any(ord(char) < 32 for char in source):
            raise ValueError("Каждая строка должна содержать одну VLESS-ссылку или HTTPS-подписку.")
        if not (source.lower().startswith("vless://") or source.lower().startswith("https://")):
            raise ValueError("Поддерживаются строки vless:// и HTTPS-подписки.")
        if source in seen:
            raise ValueError("Одинаковый источник указан несколько раз.")
        seen.add(source)
    return {"sources": [source.strip() for source in sources], "check_interval_minutes": interval}


def _public_subscription_url(url):
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Подписка должна быть обычной HTTPS-ссылкой без логина и фрагмента.")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, parsed.port or 443,
                                                               type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ValueError("Не удалось определить адрес сервера подписки.") from exc
    if not addresses or any(not ipaddress.ip_address(value).is_global for value in addresses):
        raise ValueError("Подписка должна находиться на публичном HTTPS-сервере.")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def fetch_subscription(url):
    _public_subscription_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": "vless-telegram-installer/1.1"})
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request, timeout=20) as response:
            data = response.read(MAX_SUBSCRIPTION + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise ValueError("Не удалось загрузить VLESS-подписку.") from exc
    if len(data) > MAX_SUBSCRIPTION:
        raise ValueError("VLESS-подписка слишком большая.")
    return data


def subscription_links(payload):
    try:
        text = payload.decode("utf-8-sig").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("Подписка содержит неподдерживаемую кодировку.") from exc
    if "vless://" not in text.lower():
        try:
            compact = "".join(text.split())
            text = base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4)).decode("utf-8-sig")
        except (ValueError, UnicodeError) as exc:
            raise ValueError("Подписка не содержит VLESS-ссылок.") from exc
    links = [line.strip() for line in text.splitlines() if line.strip().lower().startswith("vless://")]
    if not links:
        raise ValueError("Подписка не содержит VLESS-ссылок.")
    return links


def resolve_vless_settings(document, fetcher=fetch_subscription):
    document = validate_vless_settings(document)
    links = []
    for source in document["sources"]:
        links.extend([source] if source.lower().startswith("vless://") else subscription_links(fetcher(source)))
    unique = []
    for link in links:
        if link not in unique:
            unique.append(link)
    if not 1 <= len(unique) <= MAX_SOURCES:
        raise ValueError("После загрузки подписок должно быть от 1 до 32 уникальных VLESS-серверов.")
    return [parse_vless(link) for link in unique], unique
