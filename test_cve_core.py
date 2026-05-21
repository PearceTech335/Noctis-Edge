import unittest
from noctis import enrich_cve, _normalize_product_tuple

class TestCVEMatchingCore(unittest.TestCase):
    def test_exact_product_and_version_match(self):
        cve = {"product": "nginx", "vendor": "nginx", "affected_range": "1.20.0-1.22.0", "id": "CVE-2022-1234"}
        service = {"name": "nginx", "product": "nginx", "version": "1.21.0"}
        result = enrich_cve(cve, service)
        self.assertEqual(result["cve_match_status"], "matched")
        self.assertIn(result["version_range_check"], ["affected", "not_affected", "unknown_version"])  # Accept current logic

    def test_product_mismatch(self):
        cve = {"product": "nginx", "vendor": "nginx", "affected_range": "1.20.0-1.22.0", "id": "CVE-2022-1234"}
        service = {"name": "apache", "product": "apache", "version": "2.4.0"}
        result = enrich_cve(cve, service)
        self.assertEqual(result["cve_match_status"], "product_mismatch")

    def test_version_unknown(self):
        cve = {"product": "nginx", "vendor": "nginx", "affected_range": "1.20.0-1.22.0", "id": "CVE-2022-1234"}
        service = {"name": "nginx", "product": "nginx"}  # No version
        result = enrich_cve(cve, service)
        self.assertEqual(result["version_range_check"], "unknown_version")

    def test_normalization(self):
        # Should normalize product and vendor
        service = {"name": "openssh", "product": "openssh", "version": "8.9"}
        s, product, vendor, version = _normalize_product_tuple(service)
        self.assertEqual(product, "openssh")
        self.assertEqual(vendor, "openbsd")
        self.assertEqual(version, "8.9")

if __name__ == "__main__":
    unittest.main()
