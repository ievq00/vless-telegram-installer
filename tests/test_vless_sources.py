import base64
import unittest
from vt.vless_sources import resolve_vless_settings, subscription_links, validate_vless_settings

ONE = "vless://11111111-1111-1111-1111-111111111111@one.example.com:443?security=tls"
TWO = "vless://22222222-2222-2222-2222-222222222222@two.example.com:443?security=tls"


class VlessSourceTests(unittest.TestCase):
    def test_plain_and_base64_subscriptions(self):
        body = (ONE + "\n" + TWO).encode()
        self.assertEqual(subscription_links(body), [ONE, TWO])
        self.assertEqual(subscription_links(base64.urlsafe_b64encode(body).rstrip(b"=")), [ONE, TWO])

    def test_resolve_combines_direct_and_subscription_without_duplicates(self):
        for subscription in ("https://sub.example.com/list", "http://sub.example.com/list"):
            with self.subTest(subscription=subscription):
                settings = {"sources": [ONE, subscription], "check_interval_minutes": 30}
                outbounds, links = resolve_vless_settings(settings, fetcher=lambda _: (ONE + "\n" + TWO).encode())
                self.assertEqual(links, [ONE, TWO])
                self.assertEqual([item["server"] for item in outbounds], ["one.example.com", "two.example.com"])

    def test_http_subscription_source_is_allowed(self):
        settings = {"sources": ["http://sub.example.com/list"], "check_interval_minutes": 30}
        self.assertEqual(validate_vless_settings(settings), settings)

    def test_invalid_values_are_rejected(self):
        invalid = [
            {"sources": [], "check_interval_minutes": 30},
            {"sources": [ONE], "check_interval_minutes": 1},
            {"sources": ["ftp://sub.example.com/list"], "check_interval_minutes": 30},
            {"sources": [ONE, ONE], "check_interval_minutes": 30},
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_vless_settings(value)


if __name__ == "__main__":
    unittest.main()
