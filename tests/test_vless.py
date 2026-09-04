import unittest
from vt.vless import email_address, hostname, parse_vless, singbox_config

UUID = "11111111-1111-4111-8111-111111111111"
BASE = "vless://" + UUID + "@proxy.example.com:443"


class VlessTests(unittest.TestCase):
    def test_tls_vision(self):
        out = parse_vless(BASE + "?security=tls&type=tcp&flow=xtls-rprx-vision&sni=front.example.com")
        self.assertEqual(out["tls"]["server_name"], "front.example.com")
        self.assertEqual(out["flow"], "xtls-rprx-vision")
        self.assertNotIn("insecure", out["tls"])
        config = singbox_config(out)
        self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")
        self.assertNotIn("tun", str(config))

    def test_reality(self):
        out = parse_vless(BASE + "?security=reality&pbk=" + "A" * 43 + "&sid=1234&fp=chrome")
        self.assertEqual(out["tls"]["reality"]["short_id"], "1234")

    def test_websocket_encoded_path(self):
        out = parse_vless(BASE + "?security=tls&type=ws&host=front.example.com&path=%2Fhello%3Fed%3D1")
        self.assertEqual(out["transport"]["path"], "/hello?ed=1")
        self.assertEqual(out["transport"]["headers"]["Host"], "front.example.com")

    def test_grpc(self):
        out = parse_vless(BASE + "?security=tls&type=grpc&serviceName=sample")
        self.assertEqual(out["transport"]["service_name"], "sample")

    def test_ipv6_server(self):
        out = parse_vless("vless://" + UUID + "@[2001:db8::1]:8443?security=tls&sni=front.example.com")
        self.assertEqual(out["server"], "2001:db8::1")
        self.assertEqual(out["server_port"], 8443)

    def test_unsupported_not_silently_ignored(self):
        for query in ("type=xhttp", "security=reality&pbk=bad", "type=ws&flow=xtls-rprx-vision",
                      "security=tls&unknown=1", "type=tcp&type=ws", "type=ws&host=foo%0d%0abar",
                      "encryption=mlkem", "headerType=http"):
            with self.subTest(query=query), self.assertRaises(ValueError):
                parse_vless(BASE + "?" + query)

    def test_malformed_uuid_and_port(self):
        for value in ("vless://bad@proxy.example.com:443", "vless://" + UUID + "@host:99999", "https://example.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_vless(value)

    def test_domain_and_email_are_not_config_injection(self):
        self.assertEqual(hostname("Proxy.Example.COM."), "proxy.example.com")
        self.assertEqual(email_address("admin@example.com"), "admin@example.com")
        for domain in ("example.com\n{", "https://example.com", "127.0.0.1", "example.com:443", "foo..com"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                hostname(domain)
        for email in ("example.com", "a@b", "a@b.com\nadmin off"):
            with self.subTest(email=email), self.assertRaises(ValueError):
                email_address(email)


if __name__ == "__main__":
    unittest.main()
