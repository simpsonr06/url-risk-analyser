# Security Policy

## Responsible Disclosure

We take application security and user safety seriously. If you discover a vulnerability or security flaw in the **URL Risk Analyser / Phishing Detection Platform**, please report it responsibly instead of opening a public issue.

### Reporting Process
- Please email security findings to the repository maintainer or open a private security advisory on GitHub.
- Include a description of the issue, affected endpoints, step-by-step reproduction instructions, and proof-of-concept payloads where applicable.
- Please allow maintainers reasonable time to review, patch, and release a fix before public disclosure.

---

## Threat Model & Security Controls

### 1. Server-Side Request Forgery (SSRF) Protection
- **Direct Fetching Policy:** The application **never** fetches, downloads, or connects directly to user-submitted target URLs.
- **Outbound Reconnaissance:** Outbound networking is strictly restricted to domain registration telemetry via standard RDAP (`https://rdap.org/domain/{domain}`).
- **Pre-Lookup Filter:**
  - Raw IP addresses (IPv4 / IPv6) and `localhost` are strictly excluded from RDAP queries.
  - Non-public IP ranges (RFC 1918 private subnets, RFC 3927 link-local/cloud metadata `169.254.169.254`, loopback `127.0.0.0/8`, multicast, and reserved addresses) are identified and blocked from outbound queries.
- **Redirect Defense:** RDAP HTTP requests validate redirect destinations, terminating any redirect chain that targets non-HTTPS schemes or private/loopback IP addresses.

### 2. Input Validation and Sanitization
- URLs are length-limited to 2,048 characters to prevent Denial-of-Service (DoS) buffer exhaustion.
- Permitted schemes are strictly limited to `http` and `https`. Schemes such as `javascript:`, `data:`, `file:`, and `ftp:` are rejected immediately with HTTP 400.
- Internationalized Domain Names (IDN) with non-ASCII unicode labels are safely Punycode-encoded before analysis.

### 3. Cross-Site Scripting (XSS) Mitigation
- All user-supplied values, domain registrar names, and heuristic reason indicators rendered on the frontend dashboard undergo HTML entity escaping prior to DOM insertion.

### 4. Abuse Prevention & Rate Limiting
- Public scan endpoints (`/api/scan`) are protected by an in-memory IP rate limiter (default: 60 requests/minute per client IP), returning HTTP 429 with standard `Retry-After` headers.

---

## Known Limitations

- **Heuristic Assessment:** Scoring represents automated heuristic threat indicators and domain age signals, not a definitive verification of website authenticity or malicious intent.
- **RDAP Availability:** Public RDAP servers can experience timeouts, rate limits, or registry omissions (e.g. privacy proxies). The platform handles missing RDAP telemetry gracefully without falsely zeroing the threat score.
