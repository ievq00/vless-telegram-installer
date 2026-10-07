import os
import sys
import types
import unittest
from unittest import mock

if os.name == "nt":
    sys.modules.setdefault("fcntl", types.SimpleNamespace())
    sys.modules.setdefault("grp", types.SimpleNamespace())

from vt import vless_control


class VlessControlTests(unittest.TestCase):
    def test_transient_closed_stream_restarts_dependents_and_retries(self):
        with mock.patch.object(vless_control, "_healthy", side_effect=[True, True]), \
                mock.patch.object(vless_control, "_telegram_healthy",
                                  side_effect=[False, True]), \
                mock.patch.object(vless_control, "_restart") as restart, \
                mock.patch.object(vless_control.time, "sleep") as sleep:
            vless_control._verify_route()

        restart.assert_called_once_with(vless_control.DEPENDENT_UNITS)
        sleep.assert_called_once_with(3)


if __name__ == "__main__":
    unittest.main()
