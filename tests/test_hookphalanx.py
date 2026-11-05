"""Unit tests for HookPhalanx phishing sandbox heuristics."""

import unittest
from hookphalanx.analyzer import PhishingAnalyzer, is_private_host


class TestPhishingAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = PhishingAnalyzer(allow_private=False)

    def test_clean_domain(self):
        result = self.analyzer.analyze("https://github.com", fetch_body=False)
        self.assertEqual(result["grade"], "SAFE")
        self.assertEqual(result["score"], 0)
        self.assertEqual(len(result["indicators"]), 0)

    def test_brand_spoofing_subdomain(self):
        result = self.analyzer.analyze("https://paypal.security-update.attacker.xyz/login", fetch_body=False)
        self.assertIn(result["grade"], ("DANGEROUS", "MALICIOUS"))
        self.assertGreaterEqual(result["score"], 45)
        titles = [ind["title"] for ind in result["indicators"]]
        self.assertTrue(any("Deceptive Brand Keyword" in t for t in titles))
        self.assertTrue(any("High-Abuse Top-Level Domain" in t for t in titles))

    def test_ip_address_host(self):
        result = self.analyzer.analyze("http://198.51.100.12/login.php", fetch_body=False)
        self.assertIn(result["grade"], ("SUSPICIOUS", "DANGEROUS"))
        titles = [ind["title"] for ind in result["indicators"]]
        self.assertTrue(any("Direct IP Address" in t for t in titles))
        self.assertTrue(any("Unencrypted Plaintext HTTP" in t for t in titles))

    def test_punycode_detection(self):
        result = self.analyzer.analyze("https://xn--pypal-4ve.com/account", fetch_body=False)
        titles = [ind["title"] for ind in result["indicators"]]
        self.assertTrue(any("Punycode / Homograph" in t for t in titles))

    def test_private_ssrf_blocking(self):
        result = self.analyzer.analyze("http://127.0.0.1:8080/admin", fetch_body=False)
        self.assertEqual(result["grade"], "MALICIOUS")
        self.assertGreaterEqual(result["score"], 90)
        self.assertTrue(is_private_host("127.0.0.1"))
        self.assertTrue(is_private_host("192.168.1.1"))
        self.assertTrue(is_private_host("localhost"))


if __name__ == "__main__":
    unittest.main()
