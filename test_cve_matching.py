import unittest
from noctis import enrich_cve

def make_service(product, vendor, version):
    # 'name' is the service/protocol, 'product' is the product string. 'vendor' is not used by normalization.
    return {
        "name": product,  # e.g. 'nginx'
        "product": product,
        "version": version,
        "banner_source": "nmap",
        "body_fingerprint_match": True,
    }

class TestCVEMatching(unittest.TestCase):
    def test_exact_match(self):
        cve = {"product": "nginx", "vendor": "nginx", "affected_range": "1.20.0-1.22.0", "id": "CVE-2022-1234", "summary": "nginx 1.20.0 to 1.22.0", "severity": "HIGH"}
        service = make_service("nginx", "nginx", "1.21.0")
        result = enrich_cve(cve, service)
        self.assertEqual(result["cve_match_status"], "matched")
        self.assertEqual(result["version_range_check"], "affected")

    def test_version_not_affected(self):
        cve = {"product": "nginx", "vendor": "nginx", "affected_range": "1.20.0-1.22.0", "id": "CVE-2022-1234", "summary": "nginx 1.20.0 to 1.22.0", "severity": "HIGH"}
        service = make_service("nginx", "nginx", "1.23.0")
        result = enrich_cve(cve, service)
        self.assertEqual(result["cve_match_status"], "version_not_affected")
        self.assertEqual(result["version_range_check"], "not_affected")

    def test_product_mismatch(self):
        cve = {"product": "nginx", "vendor": "nginx", "affected_range": "1.20.0-1.22.0", "id": "CVE-2022-1234", "summary": "nginx 1.20.0 to 1.22.0", "severity": "HIGH"}
        service = make_service("apache", "apache", "2.4.0")
        result = enrich_cve(cve, service)
        self.assertEqual(result["cve_match_status"], "product_mismatch")

    def test_vendor_mismatch(self):
        cve = {"product": "nginx", "vendor": "apache", "affected_range": "1.20.0-1.22.0", "id": "CVE-2022-1234", "summary": "nginx 1.20.0 to 1.22.0", "severity": "HIGH"}
        service = make_service("nginx", None, "1.21.0")
        result = enrich_cve(cve, service)
        self.assertEqual(result["cve_match_status"], "vendor_mismatch")

    def test_unknown_version(self):
        cve = {"product": "nginx", "vendor": "nginx", "affected_range": "1.20.0-1.22.0", "id": "CVE-2022-1234", "summary": "nginx 1.20.0 to 1.22.0", "severity": "HIGH"}
        service = make_service("nginx", "nginx", None)
        result = enrich_cve(cve, service)
        self.assertEqual(result["version_range_check"], "unknown_version")
        self.assertEqual(result["cve_match_status"], "matched")

if __name__ == "__main__":
    unittest.main()
