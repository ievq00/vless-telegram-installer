import socket
import sys
import time


def main():
    deadline = time.monotonic() + 12
    port = int(sys.argv[1])
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.1)
    raise SystemExit("Service did not open its local port.")


if __name__ == "__main__":
    main()
