import json
from pathlib import Path

USERS = json.loads(Path("/etc/vless-telegram/backend-users.json").read_text())
PORT = 2398
MODES = {"classic": True, "secure": True, "tls": False}
USE_MIDDLE_PROXY = False
PREFER_IPV6 = False
FAST_MODE = False
MASK = False
LISTEN_ADDR_IPV4 = "127.0.0.1"
LISTEN_ADDR_IPV6 = None
SOCKS5_HOST = "127.0.0.1"
SOCKS5_PORT = 1080
TLS_DOMAIN = "example.com"
MY_DOMAIN = False
METRICS_PORT = 8888
METRICS_LISTEN_ADDR_IPV4 = "127.0.0.1"
METRICS_LISTEN_ADDR_IPV6 = None
METRICS_EXPORT_LINKS = False
