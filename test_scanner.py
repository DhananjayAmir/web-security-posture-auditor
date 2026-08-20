import json
import tempfile
import unittest
from pathlib import Path

import requests

from scanner import ScanResult, check_html, check_response, get_internal_links, normalise_url, same_origin, write_html_report, write_json_report


def response(url: str, headers: dict[str, str], body: str = "") -> requests.Response:
    result = requests.Response()
    result.url = url
    result.status_code = 200
    result.headers = requests.structures.CaseInsensitiveDict(headers)
    result._content = body.encode()
    result.encoding = "utf-8"
    return result


class ScannerTests(unittest.TestCase):
    def test_normalise_url_removes_fragment(self):
        self.assertEqual(normalise_url("https://example.test/path#section"), "https://example.test/path")

    def test_normalise_url_rejects_non_http_url(self):
        with self.assertRaises(ValueError):
            normalise_url("example.test")

    def test_origin_includes_scheme_and_port(self):
        self.assertTrue(same_origin("https://example.test:8443/a", "https://example.test:8443/"))
        self.assertFalse(same_origin("http://example.test:8443/a", "https://example.test:8443/"))

    def test_internal_links_stay_on_origin(self):
        links = get_internal_links(
            '<a href="/one">one</a><a href="https://other.test/no">other</a><a href="#part">same</a>',
            "https://example.test/start", "https://example.test/",
        )
        self.assertEqual(links, {"https://example.test/one", "https://example.test/start"})

    def test_html_flags_get_password_and_mixed_content(self):
        findings = check_html(
            '<img src="http://cdn.example.test/logo.png"><form><input type="password" name="password"></form>',
            "https://example.test/",
        )
        self.assertEqual({item.title for item in findings}, {"HTTPS page references HTTP resources", "Password form uses GET"})

    def test_html_flags_post_form_without_visible_csrf_token(self):
        findings = check_html('<form method="post"><input name="email"></form>', "https://example.test/")
        self.assertEqual(findings[0].title, "POST form has no apparent anti-CSRF token")

    def test_response_flags_missing_security_headers(self):
        findings = check_response(response("https://example.test/", {"Content-Type": "text/html"}))
        titles = {item.title for item in findings}
        self.assertIn("Missing Content-Security-Policy", titles)
        self.assertIn("Missing Strict-Transport-Security", titles)

    def test_report_writers_create_valid_files(self):
        result = ScanResult(target="https://example.test/", started_at="2026-08-20T00:00:00+00:00", completed_at="2026-08-20T00:01:00+00:00")
        with tempfile.TemporaryDirectory() as directory:
            html_path = Path(directory) / "report.html"
            json_path = Path(directory) / "report.json"
            write_html_report(result, html_path)
            write_json_report(result, json_path)
            self.assertIn("Web Security Posture Auditor", html_path.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["target"], result.target)


if __name__ == "__main__":
    unittest.main()
