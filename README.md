# Web Security Posture Auditor

I built this project to get more hands-on with Python and the basics of web application security. It is a small command-line tool that reviews public-facing security settings on a website and turns what it finds into a readable report.

The scanner is deliberately passive. It only sends normal `GET` requests to pages on the same site, and it does not try payloads, submit forms, guess passwords, or scan ports. The goal is to spot common configuration gaps and use them as a starting point for a manual review.

## What it looks for

- Missing security headers such as CSP, HSTS, and X-Frame-Options
- Pages or form actions that use plain HTTP
- Cookies missing `Secure`, `HttpOnly`, or `SameSite`
- Basic form issues, including password fields sent with `GET`
- Possible missing CSRF tokens on POST forms
- Server and technology headers that reveal unnecessary information
- HTTP resources loaded by HTTPS pages

Each finding includes a severity, a short explanation, an OWASP Top 10 reference where it makes sense, and a suggested fix.

## Important note

Only use this tool on websites you own or have permission to review. It is not meant to replace a penetration test or a professional security assessment. It does not log in, run JavaScript, verify whether a finding is exploitable, or test access controls.

## Built with

- Python
- Requests
- BeautifulSoup

## Getting started

Clone the repository and install the dependencies:

```powershell
git clone https://github.com/YOUR-USERNAME/web-security-posture-auditor.git
cd web-security-posture-auditor
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Run a review against a target you are authorized to test:

```powershell
python scanner.py https://your-site.example --authorized --max-pages 20
```

To save reports:

```powershell
python scanner.py https://your-site.example --authorized `
  --html-report reports\security-report.html `
  --json-report reports\security-report.json
```

Use `--verbose` to see each page as it is reviewed, or `--json` to print the result directly in JSON format.

## Testing it locally

There is a small static demo site included with the project. It is only there to make it easy to test the scanner without pointing it at a real website.

In one PowerShell window:

```powershell
cd demo-site
python -m http.server 8000
```

In another PowerShell window, from the project folder:

```powershell
python scanner.py http://localhost:8000 --authorized --max-pages 5
```

The demo intentionally produces a few findings. Stop the local server with `Ctrl+C` when you are done.

## Running the tests

```powershell
python -m unittest -v
```

## Why I made it

I wanted a project that combined Python automation with practical cybersecurity concepts. Building it helped me work with HTTP responses, HTML parsing, web security headers, cookies, report generation, and basic test coverage.

## Future improvements

- Better handling for authenticated applications
- More checks and clearer false-positive guidance
- Scan comparison over time
- A small web interface for viewing saved reports

## License

This project is available under the [MIT License](LICENSE).
