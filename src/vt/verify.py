import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import ssl
import contextlib
import struct
import socket
import time
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def frame(kind, stream, payload=b""):
    return bytes([kind]) + stream.to_bytes(3, "big") + struct.pack(">I", len(payload)) + payload


def frames(body):
    offset = 0
    while offset < len(body):
        assert len(body) - offset >= 8, "Truncated relay frame"
        kind = body[offset]
        stream = int.from_bytes(body[offset + 1:offset + 4], "big")
        length = struct.unpack(">I", body[offset + 4:offset + 8])[0]
        payload = body[offset + 8:offset + 8 + length]
        assert len(payload) == length, "Truncated relay payload"
        yield kind, stream, payload
        offset += 8 + length


def verify(domain, secret_text, ca_file=None, timeout=15, dc=2, direct=False, backend_port=2398):
    secret = bytes.fromhex(secret_text.strip())
    origin = "https://" + domain
    context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))

    def request(path, body=None, bearer=None, headers=None, method=None):
        hdr = {"Origin": origin, "User-Agent": "Telegram-WEB-Proxy-install-check/1.0"}
        if bearer:
            hdr["Authorization"] = "Bearer " + bearer
        if body is not None:
            hdr["Content-Type"] = "application/octet-stream"
        hdr.update(headers or {})
        req = urllib.request.Request(origin + path, data=body, headers=hdr, method=method)
        with opener.open(req, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()

    digest = hmac.new(secret, ("tdesktop-web-proxy-bridge-v1\n" + domain).encode(), hashlib.sha256).digest()
    capability = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    token = None
    sock = None
    if not direct:
        status, headers, body = request("/?bridge=" + capability)
        match = re.search(rb'bootstrap=("[^"\n]+")', body)
        assert status == 200 and match, "Authenticated bridge not returned"
        bootstrap = json.loads(match.group(1))
        status, headers, body = request("/api/v1/session", frame(0x10, 0, b"\x01"), bootstrap)
        token = next(value for key, value in headers.items() if key.lower() == "x-session-token")
        assert list(frames(body)) == [(0x11, 0, b"")], "Relay WELCOME missing"
    try:
        key_secret = secret[1:] if len(secret) == 17 and secret[0] == 0xDD else secret
        assert len(key_secret) == 16
        while True:
            random = bytearray(os.urandom(64))
            if random[0] != 0xEF and random[:4] not in (b"PVrG", b"GET ", b"POST", b"\xee" * 4) and random[4:8] != b"\x00" * 4:
                break
        reverse = bytes(random[55:7:-1])
        encrypt = Cipher(algorithms.AES(hashlib.sha256(bytes(random[8:40]) + key_secret).digest()), modes.CTR(bytes(random[40:56]))).encryptor()
        decrypt = Cipher(algorithms.AES(hashlib.sha256(reverse[:32] + key_secret).digest()), modes.CTR(reverse[32:48])).decryptor()
        random[56:60] = b"\xdd" * 4 if len(secret) == 17 else b"\xee" * 4
        random[60:62] = struct.pack("<h", dc)
        obfuscated_header = bytes(random[:56]) + encrypt.update(bytes(random))[56:64]
        nonce = os.urandom(16)
        payload = struct.pack("<I", 0xBE7E8EF1) + nonce
        message_id = int(time.time() * (1 << 32)) & ~3
        message = b"\x00" * 8 + struct.pack("<QI", message_id, len(payload)) + payload
        if len(secret) == 17:
            message += os.urandom(3)
        packet = obfuscated_header + encrypt.update(struct.pack("<I", len(message)) + message)
        if direct:
            sock = socket.create_connection(("127.0.0.1", backend_port), timeout=12)
            sock.sendall(packet)
        else:
            status, headers, body = request("/api/v1/up", frame(1, 1) + frame(2, 1, packet), token, {"X-Up-Seq": "1"})
            assert status == 204, "Relay uplink failed"
        cursor = "0"
        received = b""
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if direct:
                chunk = sock.recv(4096)
                assert chunk, "MTProxy backend closed the test stream"
                received += decrypt.update(chunk)
            else:
                status, headers, body = request("/api/v1/down", None, token, {"X-Down-Cursor": cursor}, method="POST")
                cursor = next((value for key, value in headers.items() if key.lower() == "x-down-cursor"), cursor)
                for kind, stream, chunk in frames(body):
                    if kind == 3 and stream == 1:
                        raise RuntimeError("MTProxy backend closed the test stream")
                    if kind == 2 and stream == 1:
                        received += decrypt.update(chunk)
            if len(received) >= 4:
                length = struct.unpack("<I", received[:4])[0]
                assert 20 <= length <= 1 << 20, "Invalid MTProto response length"
                if len(received) >= 4 + length:
                    response = received[4:4 + length]
                    assert response[:8] == b"\x00" * 8, "Unexpected MTProto auth key"
                    assert struct.unpack("<I", response[20:24])[0] == 0x05162463, "Expected resPQ from Telegram"
                    assert response[24:40] == nonce, "Telegram response nonce mismatch"
                    return {"transport": "backend" if direct else "https-web-relay", "telegram_dc": dc, "telegram_response": "resPQ", "nonce_match": True}
        raise TimeoutError("Telegram response did not arrive")
    finally:
        if token:
            with contextlib.suppress(Exception):
                request("/api/v1/session", bearer=token, method="DELETE")
        if sock:
            sock.close()


def main():
    from .common import ETC, PANEL_STATE, read_json
    config = read_json(ETC / "installation.json")
    user = next(u for u in read_json(PANEL_STATE / "users.json")["users"] if u["enabled"])
    print(json.dumps(verify(config["domain"], user["secret"])))


if __name__ == "__main__":
    main()
