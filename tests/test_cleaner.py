import unittest

from core.cleaner import clean_indicator, infer_indicator_type


class TestCleaner(unittest.TestCase):

    def test_clean_indicator_strips_spaces_and_lowercases(self):
        self.assertEqual(clean_indicator("  Example.COM  "), "example.com")

    def test_infer_ip_type(self):
        self.assertEqual(infer_indicator_type("8.8.8.8"), "ip")

    def test_infer_domain_type(self):
        self.assertEqual(infer_indicator_type("example.com"), "domain")

    def test_infer_unknown_type(self):
        self.assertEqual(infer_indicator_type("not_an_indicator"), "unknown")


if __name__ == "__main__":
    unittest.main()
