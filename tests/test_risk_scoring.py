import unittest

from core.risk_scoring import calculate_risk, calculate_final_score


class TestRiskScoring(unittest.TestCase):

    def test_calculate_risk_for_known_source(self):
        self.assertEqual(calculate_risk("VirusTotal"), 90)

    def test_calculate_risk_for_unknown_source(self):
        self.assertEqual(calculate_risk("UnknownFeed"), 60)

    def test_calculate_final_score_preserves_existing_nonzero_score(self):
        ioc = {"source": "VirusTotal", "risk_score": 70}
        self.assertEqual(calculate_final_score(ioc), 80)

    def test_calculate_final_score_defaults_and_adjusts_for_source(self):
        ioc = {"source": "AlienVault"}
        self.assertEqual(calculate_final_score(ioc), 90)

    def test_calculate_final_score_caps_at_100(self):
        ioc = {"source": "VirusTotal", "risk_score": 95}
        self.assertEqual(calculate_final_score(ioc), 100)


if __name__ == "__main__":
    unittest.main()
