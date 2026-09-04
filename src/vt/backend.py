"""Launch the upstream MTProto engine through the local VLESS SOCKS listener."""
import importlib.util
import sys
from .common import APP


def main():
    source = APP / "vendor" / "mtprotoproxy" / "mtprotoproxy.py"
    sys.path.insert(0, str(source.parent))
    spec = importlib.util.spec_from_file_location("mtprotoproxy", source)
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)
    # No middle-proxy RPC is used, so detecting the external IP is unnecessary.
    backend.init_ip_info = lambda: backend.my_ip_info.update(ipv4=None, ipv6=None)
    backend.print_tg_info = lambda: print("Telegram backend started.", flush=True)
    backend.TgConnectionPool.MAX_CONNS_IN_POOL = 2
    sys.argv = ["mtprotoproxy", str(APP / "src" / "vt" / "backend_config.py")]
    backend.main()


if __name__ == "__main__":
    main()
