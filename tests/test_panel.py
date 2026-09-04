import copy
import http.client
import re
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode
from vt.common import password_hash, read_json, write_json
from vt.panel import PanelServer
from test_state import DOCUMENT


class PanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.state = Path(cls.directory.name)
        cls.base = "/panel-" + "a" * 32
        config = {"domain": "proxy.example.test", "panel_path": cls.base, "password_hash": password_hash("test-password")}
        cls.server = PanelServer(("127.0.0.1", 0), config, cls.state, secure=False)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.directory.cleanup()

    def setUp(self):
        write_json(self.state / "users.json", copy.deepcopy(DOCUMENT))

    def request(self, method, path, fields=None, cookie="", origin="https://proxy.example.test"):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        headers = {"Cookie": cookie}
        body = None
        if fields is not None:
            body = urlencode(fields)
            headers.update({"Content-Type": "application/x-www-form-urlencoded", "Origin": origin})
        conn.request(method, path, body, headers)
        result = conn.getresponse()
        response = result.status, dict(result.getheaders()), result.read().decode()
        conn.close()
        return response

    def login(self):
        code, headers, body = self.request("GET", self.base + "/login")
        csrf = re.search('name="csrf" value="([^"]+)"', body).group(1)
        login_cookie = headers["Set-Cookie"].split(";", 1)[0]
        code, headers, _ = self.request("POST", self.base + "/login", {"csrf": csrf, "username": "admin", "password": "test-password"}, login_cookie)
        self.assertEqual(code, 303)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        code, _, body = self.request("GET", self.base + "/users", cookie=cookie)
        self.assertEqual(code, 200)
        csrf = re.search('name="csrf" value="([^"]+)"', body).group(1)
        return cookie, csrf

    def test_anonymous_cannot_read_users(self):
        code, headers, body = self.request("GET", self.base + "/users")
        self.assertEqual(code, 303)
        self.assertNotIn("b" * 32, body)

    def test_csrf_and_cross_origin_are_rejected(self):
        cookie, csrf = self.login()
        code, _, _ = self.request("POST", self.base + "/add", {"csrf": "wrong", "name": "extra"}, cookie)
        self.assertEqual(code, 403)
        code, _, _ = self.request("POST", self.base + "/add", {"csrf": csrf, "name": "extra"}, cookie, origin="https://evil.example")
        self.assertEqual(code, 403)
        self.assertEqual(len(read_json(self.state / "users.json")["users"]), 1)

    def test_create_and_escape_user_name(self):
        cookie, csrf = self.login()
        code, _, _ = self.request("POST", self.base + "/add", {"csrf": csrf, "name": "<script>alert(1)</script>"}, cookie)
        self.assertEqual(code, 303)
        code, _, body = self.request("GET", self.base + "/users", cookie=cookie)
        self.assertIn("&lt;script&gt;", body)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertEqual(len(read_json(self.state / "users.json")["users"]), 2)

    def test_last_user_cannot_be_disabled(self):
        cookie, csrf = self.login()
        code, _, _ = self.request("POST", self.base + "/toggle", {"csrf": csrf, "id": "a" * 16}, cookie)
        self.assertEqual(code, 400)
        self.assertTrue(read_json(self.state / "users.json")["users"][0]["enabled"])
