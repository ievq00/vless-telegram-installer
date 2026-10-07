import unittest
from unittest import mock

from vt.verify import WebSocket


class FakeSocket:
    def __init__(self, incoming=b""):
        self.incoming = incoming
        self.sent = []
        self.closed = False

    def recv(self, length):
        chunk, self.incoming = self.incoming[:length], self.incoming[length:]
        return chunk

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


class WebSocketTests(unittest.TestCase):
    def test_client_binary_frames_are_masked(self):
        sock = FakeSocket()
        websocket = WebSocket(sock)
        with mock.patch("vt.verify.os.urandom", return_value=b"\x01\x02\x03\x04"):
            websocket.send_binary(b"hello")
        self.assertEqual(sock.sent[0][:6], b"\x82\x85\x01\x02\x03\x04")
        self.assertEqual(sock.sent[0][6:], bytes((ord("h") ^ 1, ord("e") ^ 2,
                                                ord("l") ^ 3, ord("l") ^ 4, ord("o") ^ 1)))

    def test_ping_and_fragmented_binary_message(self):
        incoming = b"\x89\x01x" + b"\x02\x02ab" + b"\x80\x02cd"
        sock = FakeSocket(incoming)
        websocket = WebSocket(sock)
        with mock.patch("vt.verify.os.urandom", return_value=b"\x00\x00\x00\x00"):
            self.assertEqual(websocket.receive_binary(), b"abcd")
        self.assertEqual(sock.sent, [b"\x8a\x81\x00\x00\x00\x00x"])


if __name__ == "__main__":
    unittest.main()
