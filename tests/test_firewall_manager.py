import unittest

from policy_enforcer.firewall_manager import is_whitelisted


class TestFirewallManager(unittest.TestCase):

    def test_whitelisted_ip(self):
        self.assertTrue(is_whitelisted("127.0.0.1"))

    def test_non_whitelisted_ip(self):
        self.assertFalse(is_whitelisted("203.0.113.10"))


if __name__ == "__main__":
    unittest.main()
