# Security Implementation & Hardening Details

This document explains the security architecture, threat model, and defense-in-depth measures implemented across the application.

---

## 1. Server-Side Request Forgery (SSRF) Mitigations

### The Danger
Applications that accept user-provided URLs risk Server-Side Request Forgery (SSRF) if the backend directly visits the submitted destination. Attackers can trigger requests to internal microservices, loopback devices (`localhost`), link-local metadata endpoints (`169.254.169.254`), or private subnets (`10.0.0.0/8`, `192.168.0.0/16`).

### Defense Implementation
1. **Zero Direct URL Visits:** The application **never** attempts to connect to or scrape the user-submitted target URL. Analysis is strictly static and passive.
2. **Pre-Query Domain Filtering:**
   - RDAP queries are only initiated for syntactically valid public domains.
   - Raw IP addresses (IPv4 / IPv6) are detected and explicitly blocked from RDAP queries via `engine/validator.py`.
   - `check_ip_security()` identifies loopback, private, link-local, multicast, and reserved IP ranges.
3. **Redirect Hijacking Protection:**
   - In `services/rdap_service.py`, external RDAP requests do not automatically follow arbitrary redirects.
   - Each redirect destination is checked: redirects to non-HTTPS schemes or private/loopback/cloud metadata IP addresses are aborted immediately.

---

## 2. Input Validation and Denial-of-Service Defense

- **Maximum Payload Constraints:** `MAX_URL_LENGTH` is enforced (2,048 characters) across Pydantic models and the custom validator.
- **Scheme Whitelisting:** Permitted schemes are restricted strictly to `http` and `https`. Schemes such as `file://`, `javascript:`, `data:`, and `ftp:` are rejected at the edge with HTTP 400.
- **Punycode (IDN) Handling:** Hostnames containing internationalized characters are normalized to ASCII Punycode via `idna.encode()` to prevent homograph bypasses and parser confusion.

---

## 3. Cross-Site Scripting (XSS) Prevention

- Dynamic dashboard views in `frontend/index.html` execute an `escapeHtml()` function over all values rendered into the DOM, including target URLs, registrar strings, and anomaly reason texts.
- Untrusted user input is never executed or injected directly into unescaped template literals.

---

## 4. API Abuse & Rate Limiting

- An in-memory sliding-window rate limiter in `app/limiter.py` tracks client requests per minute.
- Configurable via `RATE_LIMIT_ENABLED` and `RATE_LIMIT_PER_MINUTE`.
- Returns standard HTTP 429 status code with a `Retry-After` header.

---

## 5. Information Disclosure & Error Sanitization

- Server exceptions during scan evaluations are caught and logged internally.
- External clients receive sanitized JSON error responses without stack traces or filesystem paths.
- CORS rules are explicitly configured: wildcard origins (`*`) disable credentials, preventing credential leakage.
