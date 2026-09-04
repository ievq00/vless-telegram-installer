import html
import json
from .common import APP, ETC, PANEL_STATE, STATE

BASE_HARDENING = """NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
LockPersonality=true
UMask=0027
"""


def service(name, description, command, after="network-online.target", extra="", user=None, ready_port=None):
    user = user or name
    text = f"""[Unit]
Description={description}
After={after}
Wants=network-online.target

[Service]
Type=simple
User={user}
Group={user}
Environment=PYTHONPATH={APP}/src
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart={command}
Restart=on-failure
RestartSec=3s
TimeoutStopSec=15s
LimitNOFILE=65536
"""
    if ready_port:
        text += f"ExecStartPost=/usr/bin/python3 -m vt.ready {ready_port}\n"
    text += BASE_HARDENING + extra + "\n[Install]\nWantedBy=multi-user.target\n"
    return text


def units():
    result = {
        "vt-vless.service": service("vt-vless", "VLESS client for Telegram",
            f"{APP}/bin/sing-box run -c {ETC}/sing-box.json", ready_port=1080),
        "vt-backend.service": service("vt-backend", "Telegram MTProto via VLESS",
            "/usr/bin/python3 -m vt.backend", after="network-online.target vt-vless.service",
            extra="IPAddressDeny=any\nIPAddressAllow=localhost\n", ready_port=2398),
        "vt-relay.service": service("vt-relay", "Telegram WEB HTTPS relay",
            f"{APP}/bin/tproxy-server -config {ETC}/relay.json",
            after="network-online.target vt-backend.service",
            extra="IPAddressDeny=any\nIPAddressAllow=localhost\n", ready_port=8080),
        "vt-panel.service": service("vt-panel", "Telegram WEB administration",
            "/usr/bin/python3 -m vt.panel", after="network-online.target vt-relay.service",
            extra=f"ReadWritePaths={PANEL_STATE}\nIPAddressDeny=any\nIPAddressAllow=localhost\n", ready_port=8090),
        "vt-caddy.service": service("vt-caddy", "Telegram WEB HTTPS server",
            f"{APP}/bin/caddy run --config {ETC}/Caddyfile --adapter caddyfile",
            after="network-online.target vt-relay.service vt-panel.service",
            extra=f"AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nReadWritePaths={STATE}/caddy\nEnvironment=XDG_DATA_HOME={STATE}/caddy/data\nEnvironment=XDG_CONFIG_HOME={STATE}/caddy/config\n"),
        "vt-sync.service": f"""[Unit]
Description=Apply Telegram connection changes
After=vt-backend.service vt-relay.service

[Service]
Type=oneshot
Environment=PYTHONPATH={APP}/src
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 -m vt.control
TimeoutStartSec=90s
UMask=0077
""",
        "vt-sync.path": f"""[Unit]
Description=Watch Telegram connection changes

[Path]
PathChanged={PANEL_STATE}/users.json
Unit=vt-sync.service

[Install]
WantedBy=multi-user.target
""",
    }
    return result


def relay_config(domain):
    return {"public_hostname": domain, "listen": "127.0.0.1:8080",
            "admin_listen": "127.0.0.1:8081", "public_dir": str(APP / "site"),
            "profiles_file": str(ETC / "profiles.json")}


def caddyfile(domain, email, panel_path, laboratory=False):
    tls = "    tls internal\n" if laboratory else ""
    return f"""{{
    admin off
    email {email}
}}
{domain} {{
{tls}    encode zstd gzip
    header Strict-Transport-Security "max-age=31536000"
    handle {panel_path}/* {{
        reverse_proxy 127.0.0.1:8090
    }}
    handle {{
        reverse_proxy 127.0.0.1:8080 {{
            transport http {{
                response_header_timeout 40s
            }}
        }}
    }}
}}
"""


def site(domain):
    safe = html.escape(domain)
    return f"""<!doctype html><html lang="ru"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{safe}</title><style>body{{margin:0;font:18px/1.6 system-ui;background:#f5f4ef;color:#23342f}}main{{max-width:680px;margin:18vh auto;padding:30px}}h1{{font-size:44px;line-height:1.1}}small{{color:#668174}}hr{{border:0;border-top:1px solid #d9ded6;margin:30px 0}}</style>
<main><small>{safe}</small><h1>Пространство для новых идей</h1>
<p>Здесь появятся заметки, материалы и полезные ссылки.</p><hr>
<p>Страница готовится к публикации.</p></main></html>
"""
