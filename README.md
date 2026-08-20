# Web Security Posture Auditor

> Passive web-security review for authorized targets, built with Python, Requests, and BeautifulSoup.

`OWASP · Web Security · Vulnerability Assessment · Automation`

Web Security Posture Auditor is a portfolio-ready command-line tool that reviews an application's **observable security posture**. It makes bounded, same-origin `GET` requests, explains its findings, maps them to relevant OWASP Top 10 categories, and produces terminal, JSON, and standalone HTML reports.

> [!IMPORTANT]
> Only assess systems you own or have explicit written permission to review. This project intentionally performs no payload injection, credential attacks, port scans, form submission, or cross-origin redirect following.

## What it checks

| Area | Examples |
| --- | --- |
| Transport security | HTTP pages, HTTPS pages referencing HTTP assets, insecure form actions |
| Browser protections | CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-Frame-Options |
| Cookies | Missing `Secure`, `HttpOnly`, and `SameSite` attributes |
| Forms | Password fields sent with `GET`, apparent missing anti-CSRF fields, third-party form targets |
| Information disclosure | `Server` and `X-Powered-By` headers |
| Crawl controls | Same-origin link discovery, page limit, request timeout, manual redirect handling |

Findings are indicators for manual verification—not proof that a vulnerability exists. For example, CSRF protection may be supplied through JavaScript or an Origin-checking policy rather than a visible form field.

## Quick start

Requires Python 3.10+.

```powershell
git clone https://github.com/YOUR-USERNAME/web-security-posture-auditor.git
cd web-security-posture-auditor
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Review an authorized application:

```powershell
python scanner.py https://app.example.com --authorized --max-pages 20 --verbose `
  --html-report reports\security-report.html `
  --json-report reports\security-report.json
```

Use `--json` to send structured findings to standard output:

```powershell
python scanner.py https://app.example.com --authorized --json
```

## Safe local demonstration

The included static demo is deliberately minimal and intended only for local testing. In one PowerShell terminal:

```powershell
cd demo-site
python -m http.server 8000
```

In a second terminal, from the project root:

```powershell
python scanner.py http://localhost:8000 --authorized --max-pages 5 --html-report reports\local-demo.html
```

The report will contain expected findings because the local demo uses plain HTTP and intentionally includes examples for the passive checks. Stop the server with `Ctrl+C`.

## Project structure

```text
.
├── scanner.py              # CLI, crawler, checks, and report writers
├── test_scanner.py         # Unit tests
├── demo-site/              # Safe local static demo
├── .github/workflows/      # Continuous test workflow
└── reports/                # Ignored generated reports
```

## Development

```powershell
python -m unittest -v
```

## Portfolio talking points

- Built an authorization-gated passive web-security assessment tool in Python.
- Implemented bounded same-origin crawling using Requests and HTML analysis with BeautifulSoup.
- Translated response and HTML observations into remediation-focused OWASP-aligned findings.
- Created machine-readable JSON and shareable standalone HTML reports.
- Added automated unit tests and GitHub Actions CI.

## Limitations

This is not a replacement for an authenticated penetration test, secure code review, or a DAST platform. It does not execute JavaScript, submit forms, discover hidden endpoints, verify exploitability, or test authorization controls. Its goal is rapid, safe posture visibility and a useful starting point for manual review.

## License

Released under the [MIT License](LICENSE).
