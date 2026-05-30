import unittest

from core.validator import validate_ip


class TestValidator(unittest.TestCase):

    def test_valid_ip(self):
        self.assertTrue(validate_ip("8.8.8.8"))

    def test_invalid_ip(self):
        self.assertFalse(validate_ip("999.999.999.999"))

    def test_ipv6_address(self):
        self.assertTrue(validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))


if __name__ == "__main__":
    unittest.main()
