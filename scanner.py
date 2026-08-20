#!/usr/bin/env python3
"""Web Security Posture Auditor — passive, authorization-gated web reviewing.

The tool only makes GET requests to the target origin. It does not submit forms,
use exploit payloads, brute-force credentials, enumerate ports, or follow
cross-origin redirects.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urldefrag, urljoin, urlparse

import requests
from bs4 import BeautifulSoup


APP_NAME = "Web Security Posture Auditor"
VERSION = "1.0.0"
USER_AGENT = f"SecurityPostureAuditor/{VERSION} (+authorized-security-assessment)"
DEFAULT_TIMEOUT = 10
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
HEADER_CHECKS = {
    "Content-Security-Policy": ("medium", "A05:2021 Security Misconfiguration", "Mitigates script injection and unauthorized resource loading."),
    "X-Content-Type-Options": ("medium", "A05:2021 Security Misconfiguration", "Prevents browsers from MIME-sniffing response content."),
    "Referrer-Policy": ("low", "A05:2021 Security Misconfiguration", "Controls referrer information disclosed to other sites."),
    "Permissions-Policy": ("low", "A05:2021 Security Misconfiguration", "Restricts sensitive browser capabilities."),
    "X-Frame-Options": ("medium", "A05:2021 Security Misconfiguration", "Helps protect pages from clickjacking."),
}


@dataclass(frozen=True)
class Finding:
    severity: str
    owasp: str
    category: str
    title: str
    url: str
    detail: str
    remediation: str


@dataclass
class ScanResult:
    target: str
    started_at: str
    completed_at: str = ""
    pages: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tool": APP_NAME, "version": VERSION, "target": self.target,
            "started_at": self.started_at, "completed_at": self.completed_at,
            "pages": self.pages, "findings": [asdict(item) for item in self.findings],
            "errors": self.errors, "summary": severity_counts(self.findings),
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalise_url(value: str) -> str:
    """Validate an HTTP(S) URL and strip its fragment."""
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Target must be an absolute http:// or https:// URL.")
    return urldefrag(value.strip())[0]


def same_origin(candidate: str, root: str) -> bool:
    """Compare scheme, host, and port, not merely hostname."""
    left, right = urlparse(candidate), urlparse(root)
    return (left.scheme.lower(), left.netloc.lower()) == (right.scheme.lower(), right.netloc.lower())


def make_finding(severity: str, owasp: str, category: str, title: str, url: str, detail: str, remediation: str) -> Finding:
    return Finding(severity, owasp, category, title, url, detail, remediation)


def get_internal_links(html_text: str, page_url: str, root_url: str) -> set[str]:
    """Discover unique, fragment-free, same-origin HTTP(S) anchors."""
    soup = BeautifulSoup(html_text, "html.parser")
    links: set[str] = set()
    for anchor in soup.select("a[href]"):
        absolute = urldefrag(urljoin(page_url, anchor.get("href", "").strip()))[0]
        if urlparse(absolute).scheme in {"http", "https"} and same_origin(absolute, root_url):
            links.add(absolute)
    return links


def check_headers(response: requests.Response) -> list[Finding]:
    findings: list[Finding] = []
    url, headers = response.url, response.headers
    if urlparse(url).scheme != "https":
        findings.append(make_finding("high", "A02:2021 Cryptographic Failures", "Transport", "Page served over HTTP", url,
            "Unencrypted HTTP traffic can be read or altered in transit.",
            "Redirect HTTP to HTTPS and enable HSTS after verifying complete HTTPS coverage."))
    for name, (severity, owasp, explanation) in HEADER_CHECKS.items():
        if name not in headers:
            findings.append(make_finding(severity, owasp, "HTTP headers", f"Missing {name}", url, explanation,
                f"Set an appropriate {name} response header."))
    if urlparse(url).scheme == "https" and "Strict-Transport-Security" not in headers:
        findings.append(make_finding("medium", "A05:2021 Security Misconfiguration", "HTTP headers", "Missing Strict-Transport-Security", url,
            "HSTS tells compatible browsers to use HTTPS for future requests.",
            "Set Strict-Transport-Security after confirming all subdomains and paths support HTTPS."))
    csp = headers.get("Content-Security-Policy", "").lower()
    if "unsafe-inline" in csp:
        findings.append(make_finding("low", "A05:2021 Security Misconfiguration", "HTTP headers", "CSP permits unsafe inline content", url,
            "The Content-Security-Policy includes 'unsafe-inline', which weakens script/style injection protection.",
            "Prefer nonce- or hash-based CSP directives and remove unsafe-inline where practical."))
    for header, label in (("Server", "Server header disclosed"), ("X-Powered-By", "Technology header disclosed")):
        if headers.get(header):
            findings.append(make_finding("low", "A05:2021 Security Misconfiguration", "Information disclosure", label, url,
                f"Response exposes {header}: {headers[header]}", f"Remove or minimize the {header} response header where feasible."))
    return findings


def check_cookies(response: requests.Response) -> list[Finding]:
    findings: list[Finding] = []
    for cookie in response.cookies:
        flags = {str(flag).lower() for flag in cookie._rest}
        if urlparse(response.url).scheme == "https" and "secure" not in flags:
            findings.append(make_finding("medium", "A02:2021 Cryptographic Failures", "Cookies", f"Cookie '{cookie.name}' lacks Secure", response.url,
                "This cookie could be sent via an unencrypted HTTP connection.", "Set the Secure attribute on cookies used over HTTPS."))
        if "httponly" not in flags:
            findings.append(make_finding("medium", "A07:2021 Identification and Authentication Failures", "Cookies", f"Cookie '{cookie.name}' lacks HttpOnly", response.url,
                "Scripts may be able to read this cookie if script injection occurs.", "Set HttpOnly unless client-side access is strictly required."))
        if "samesite" not in flags:
            findings.append(make_finding("low", "A01:2021 Broken Access Control", "Cookies", f"Cookie '{cookie.name}' lacks SameSite", response.url,
                "Cross-site requests may carry the cookie more broadly than intended.", "Set an appropriate SameSite attribute (Lax, Strict, or None with Secure)."))
    return findings


def check_html(html_text: str, url: str) -> list[Finding]:
    findings: list[Finding] = []
    soup = BeautifulSoup(html_text, "html.parser")
    if urlparse(url).scheme == "https":
        insecure_assets = []
        for tag in soup.select("script[src], img[src], link[href], iframe[src]"):
            source = tag.get("src") or tag.get("href") or ""
            if source.lower().startswith("http://"):
                insecure_assets.append(source)
        if insecure_assets:
            findings.append(make_finding("medium", "A02:2021 Cryptographic Failures", "Mixed content", "HTTPS page references HTTP resources", url,
                f"Found {len(insecure_assets)} HTTP resource reference(s), for example: {insecure_assets[0]}", "Load resources over HTTPS or use relative URLs."))
    for form in soup.find_all("form"):
        method = form.get("method", "get").lower().strip()
        action = urljoin(url, form.get("action", ""))
        fields = form.find_all(["input", "textarea", "select"])
        names = {field.get("name", "").lower() for field in fields}
        password_present = any(field.get("type", "").lower() == "password" for field in fields)
        if password_present and method == "get":
            findings.append(make_finding("high", "A02:2021 Cryptographic Failures", "Forms", "Password form uses GET", url,
                "GET forms can place credentials in URLs, browser history, logs, and referrer headers.", "Submit credentials with POST over HTTPS."))
        if method == "post" and not any(token in name for name in names for token in ("csrf", "xsrf", "token")):
            findings.append(make_finding("low", "A01:2021 Broken Access Control", "Forms", "POST form has no apparent anti-CSRF token", url,
                "Heuristic only: protections can be implemented outside visible form fields.", "Confirm CSRF protection for state-changing actions (tokens and/or Origin validation)."))
        if action.lower().startswith("http://"):
            findings.append(make_finding("medium", "A02:2021 Cryptographic Failures", "Forms", "Form posts to HTTP", url,
                f"Form action resolves to: {action}", "Use an HTTPS or relative form action."))
        elif not same_origin(action, url):
            findings.append(make_finding("info", "A05:2021 Security Misconfiguration", "Forms", "Form submits to another origin", url,
                f"Form action resolves to: {action}", "Confirm the third-party destination and data-sharing intent are approved."))
    return findings


def check_response(response: requests.Response) -> list[Finding]:
    """Run passive checks that apply to one HTTP response."""
    findings = check_headers(response) + check_cookies(response)
    if "text/html" in response.headers.get("Content-Type", "").lower():
        findings.extend(check_html(response.text, response.url))
    return findings


def scan(target: str, max_pages: int, timeout: int, verbose: bool = False) -> ScanResult:
    """Perform a bounded, same-origin, GET-only posture review."""
    root = normalise_url(target)
    result = ScanResult(target=root, started_at=utc_now())
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    queue: deque[str] = deque([root])
    seen: set[str] = set()
    while queue and len(seen) < max_pages:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        if verbose:
            print(f"[+] Reviewing ({len(seen)}/{max_pages}): {current}", file=sys.stderr)
        try:
            response = session.get(current, timeout=timeout, allow_redirects=False)
            response.raise_for_status()
        except requests.RequestException as exc:
            result.errors.append(f"{current}: {exc}")
            continue
        result.findings.extend(check_response(response))
        location = response.headers.get("Location")
        if response.is_redirect and location:
            redirect = urldefrag(urljoin(current, location))[0]
            if same_origin(redirect, root) and redirect not in seen:
                queue.append(redirect)
            elif not same_origin(redirect, root):
                result.findings.append(make_finding("info", "A05:2021 Security Misconfiguration", "Redirects", "Redirect leaves the assessed origin", current,
                    f"Redirect target: {redirect}", "Confirm the external redirect is intentional. It was not requested by this tool."))
        if "text/html" in response.headers.get("Content-Type", "").lower():
            for link in sorted(get_internal_links(response.text, response.url, root)):
                if link not in seen:
                    queue.append(link)
    result.pages = sorted(seen)
    result.findings.sort(key=lambda item: (SEVERITY_ORDER[item.severity], item.title, item.url))
    result.completed_at = utc_now()
    return result


def severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    counts = Counter(item.severity for item in findings)
    return {level: counts[level] for level in ("high", "medium", "low", "info")}


def print_text_report(result: ScanResult) -> None:
    counts = severity_counts(result.findings)
    print(f"\n{APP_NAME} v{VERSION}\n" + "=" * 45)
    print(f"Target: {result.target}\nPages reviewed: {len(result.pages)} | Findings: {len(result.findings)}")
    print("Severity: " + ", ".join(f"{level}={counts[level]}" for level in counts))
    for item in result.findings:
        print(f"\n[{item.severity.upper()}] {item.title}\n  OWASP: {item.owasp}\n  URL: {item.url}\n  Detail: {item.detail}\n  Fix: {item.remediation}")
    if result.errors:
        print("\nRequest errors:")
        for error in result.errors:
            print(f"  - {error}")


def write_json_report(result: ScanResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")


def write_html_report(result: ScanResult, path: Path) -> None:
    """Create a standalone, shareable HTML report without extra dependencies."""
    path.parent.mkdir(parents=True, exist_ok=True)
    counts = severity_counts(result.findings)
    cards = "".join(f'<div class="count {level}"><b>{counts[level]}</b><span>{level}</span></div>' for level in counts)
    rows = "".join(
        "<article class='finding {severity}'><div class='badge'>{severity}</div><div><h3>{title}</h3><p class='meta'>{owasp} · {category}</p>"
        "<p><b>URL:</b> {url}</p><p>{detail}</p><p><b>Recommended action:</b> {remediation}</p></div></article>".format(
            **{key: html.escape(str(value)) for key, value in asdict(item).items()}
        ) for item in result.findings
    ) or "<p>No findings were generated for the reviewed responses.</p>"
    errors = "".join(f"<li>{html.escape(error)}</li>" for error in result.errors)
    document = f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>{APP_NAME} report</title><style>
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#f4f7fb;color:#182230;max-width:1050px;margin:auto;padding:28px;line-height:1.5}}header{{background:#102a43;color:white;padding:32px;border-radius:14px}}h1{{margin:0}}.subtitle{{opacity:.8}}.counts{{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}}.count{{background:white;border-radius:12px;padding:16px 24px;min-width:90px;box-shadow:0 2px 10px #dbe5ef}}.count b{{font-size:1.8rem;display:block}}.high b,.badge.high{{color:#b42318}}.medium b,.badge.medium{{color:#b54708}}.low b,.badge.low{{color:#175cd3}}.info b,.badge.info{{color:#475467}}.finding{{display:grid;grid-template-columns:88px 1fr;gap:18px;background:white;padding:22px;margin:14px 0;border-radius:12px;box-shadow:0 2px 10px #dbe5ef;border-left:5px solid #98a2b3}}.finding.high{{border-color:#f04438}}.finding.medium{{border-color:#f79009}}.finding.low{{border-color:#2e90fa}}.badge{{font-weight:700;text-transform:uppercase;font-size:.8rem}}h3{{margin:0}}p{{margin:.45rem 0}}.meta{{color:#667085;font-size:.9rem}}footer{{color:#667085;font-size:.85rem;margin:28px 0}}</style></head><body>
<header><h1>{APP_NAME}</h1><p class='subtitle'>Passive, authorized web security posture review</p><p><b>Target:</b> {html.escape(result.target)}<br><b>Completed:</b> {html.escape(result.completed_at)}<br><b>Pages reviewed:</b> {len(result.pages)}</p></header>
<section class='counts'>{cards}</section><main><h2>Findings</h2>{rows}</main>"""
    if errors:
        document += f"<section><h2>Request errors</h2><ul>{errors}</ul></section>"
    document += "<footer>Results are indicators for manual verification, not proof of a vulnerability. Review only systems you own or are explicitly authorized to assess.</footer></body></html>"
    path.write_text(document, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Passive, same-origin web security posture auditor.")
    parser.add_argument("target", help="Authorized HTTP(S) target URL")
    parser.add_argument("--authorized", action="store_true", help="Confirm you are authorized to assess this target")
    parser.add_argument("--max-pages", type=int, default=10, help="Maximum same-origin pages to request, 1–100 (default: 10)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Per-request timeout in seconds, 1–60 (default: 10)")
    parser.add_argument("--verbose", action="store_true", help="Show requested URLs as they are reviewed")
    parser.add_argument("--json", action="store_true", help="Print a JSON report to standard output")
    parser.add_argument("--json-report", metavar="PATH", help="Write a JSON report to PATH")
    parser.add_argument("--html-report", metavar="PATH", help="Write a standalone HTML report to PATH")
    args = parser.parse_args()
    if not args.authorized:
        parser.error("Refusing to send requests without --authorized. Only assess systems you are allowed to review.")
    if not 1 <= args.max_pages <= 100:
        parser.error("--max-pages must be between 1 and 100.")
    if not 1 <= args.timeout <= 60:
        parser.error("--timeout must be between 1 and 60 seconds.")
    try:
        result = scan(args.target, args.max_pages, args.timeout, args.verbose)
    except ValueError as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_text_report(result)
    if args.json_report:
        write_json_report(result, Path(args.json_report))
        print(f"JSON report saved to: {args.json_report}", file=sys.stderr)
    if args.html_report:
        write_html_report(result, Path(args.html_report))
        print(f"HTML report saved to: {args.html_report}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
