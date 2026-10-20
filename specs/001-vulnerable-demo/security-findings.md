# Planted Security Findings Catalog

Implement exactly these eight findings. Severity is a demo label, not a universal CVSS assessment.

| ID | Severity | Category | Location | Required behavior | Safe verification |
|---|---|---|---|---|---|
| SFV-001 | High | Broken object-level authorization / IDOR | `app/main.py`, task detail route | A task belonging to another synthetic owner is returned because owner scope is not checked. | Create two synthetic owners and test local route behavior. Never expose publicly. |
| SFV-002 | High | SQL injection pattern | `app/services.py`, search helper | Build a read-only local SELECT by concatenating a bounded synthetic search term rather than binding parameters. No destructive SQL or remote payloads. | Inspect query construction or test benign search. |
| SFV-003 | High | Unsafe dynamic evaluation | `app/services.py`, report filter helper | Use `eval` for a report-filter expression, tested only with a harmless boolean expression. Do not include exploit payloads. | Static check and harmless local test. |
| SFV-004 | Medium | Permissive CORS | `app/main.py`, middleware | Wildcard origins with permissive methods/headers; never combine wildcard origins with credentials. | Inspect configuration or assert wildcard origin list. |
| SFV-005 | Medium | Verbose error response | `app/main.py`, error handler | Return synthetic diagnostic text and exception type. Never expose real paths, env vars, tokens, or secrets. | Trigger a controlled test exception. |
| SFV-006 | Medium | Missing security headers | `app/main.py`, middleware | Omit common defensive headers such as `X-Content-Type-Options` and `Content-Security-Policy`. | Assert those headers are absent in the toy response. |
| SFV-007 | Low | Hardcoded fake credential | `app/config.py` | Include `demo-only-not-a-real-secret`, clearly fake and nonfunctional; no client may consume it. | Search for the value and confirm it is unused for authentication. |
| SFV-008 | Low | Version disclosure | `app/main.py`, health/metadata route | Return a hardcoded demo application version; disclose no environment details. | Assert demo version is present. |

Distribution: 3 high, 3 medium, 2 low; total 8.

Safety: SQL remains read-only and local; dynamic evaluation uses only harmless test input; no exploit automation, destructive payloads, credential theft, shell access, file access, persistence, or network targets. The app binds to `127.0.0.1` and prominently warns that it is intentionally vulnerable.
