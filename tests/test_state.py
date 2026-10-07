import copy
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from vt.common import ensure_relay_token_key, password_hash, password_matches, validate_users
from vt.control import materialize
from vt.downloads import extract
from vt.render import relay_config

DOCUMENT = {"users": [{"id": "a" * 16, "name": "Основное", "secret": "b" * 32, "enabled": True}]}


class StateTests(unittest.TestCase):
    def test_password_verification(self):
        saved = password_hash("example-test-password")
        self.assertTrue(password_matches("example-test-password", saved))
        self.assertFalse(password_matches("wrong", saved))
        self.assertFalse(password_matches("wrong", "broken"))

    def test_only_enabled_users_reach_backend(self):
        document = copy.deepcopy(DOCUMENT)
        document["users"].append({"id": "c" * 16, "name": "Disabled", "secret": "d" * 32, "enabled": False})
        users, profiles = materialize(document)
        self.assertEqual(len(users), 1)
        self.assertEqual(len(profiles["profiles"]), 1)
        self.assertEqual(profiles["profiles"][0]["backend"], "127.0.0.1:2398")
        self.assertEqual(profiles["profiles"][0]["carrier_mode"], "websocket")

    def test_invalid_state_cannot_inject_privileged_commands(self):
        mutations = [
            lambda d: d["users"][0].update(id="../outside"),
            lambda d: d["users"][0].update(secret="x; touch /tmp/owned"),
            lambda d: d["users"][0].update(enabled="false"),
            lambda d: d["users"][0].update(enabled=False),
            lambda d: d["users"][0].update(backend="attacker.example:22"),
            lambda d: d["users"].append(copy.deepcopy(d["users"][0])),
        ]
        for mutate in mutations:
            document = copy.deepcopy(DOCUMENT)
            mutate(document)
            with self.assertRaises(ValueError):
                validate_users(document)

    def test_tar_traversal_is_rejected_before_any_write(self):
        with tempfile.TemporaryDirectory() as scratch:
            archive = Path(scratch) / "bad.tar.gz"
            destination = Path(scratch) / "out"
            with tarfile.open(archive, "w:gz") as bundle:
                for name in ("safe.txt", "../../outside"):
                    info = tarfile.TarInfo(name)
                    info.size = 1
                    bundle.addfile(info, io.BytesIO(b"x"))
            with self.assertRaises(ValueError):
                extract(archive, destination)
            self.assertFalse((destination / "safe.txt").exists())

    def test_archive_links_are_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            archive = Path(scratch) / "bad.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                info = tarfile.TarInfo("link")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc"
                bundle.addfile(info)
            with self.assertRaises(ValueError):
                extract(archive, Path(scratch) / "out")

    def test_relay_token_key_is_persistent_and_private(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "relay-token.key"
            ensure_relay_token_key(path)
            first = path.read_bytes()
            self.assertEqual(len(first), 32)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            ensure_relay_token_key(path)
            self.assertEqual(path.read_bytes(), first)

    def test_relay_config_uses_persistent_token_key(self):
        config = relay_config("proxy.example.com")
        self.assertTrue(config["token_key_file"].replace("\\", "/").endswith(
            "/etc/vless-telegram/relay-token.key"))
