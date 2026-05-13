# ldapscanner

> Marker-based LDAP injection scanner that consumes raw Burp-style HTTP requests. Built for authorized penetration testing.

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()

`ldapscanner.py` is a single-file CLI tool for detecting LDAP / Active Directory injection vulnerabilities in login forms and search endpoints. It reads a raw HTTP request copied from Burp Suite, injects payloads into user-placed markers, and flags vulnerable fields through response differential analysis.

---

## ⚠️ Legal Notice

This tool is intended **exclusively** for use on systems you own or for which you have **explicit written authorization** to test. Unauthorized use against third-party systems is a criminal offense in most jurisdictions (CFAA in the US, Computer Misuse Act in the UK, NIS2 in the EU, TCK §243-244 in Turkey). The user assumes all responsibility for use of this tool. The authors and contributors disclaim all liability for misuse.

---

## Features

- **Burp-style request parsing** — paste raw HTTP as-is, no reformatting needed
- **Marker-based injection** — drop `USERNAME`, `PASSWORD`, `KNOWNUSER`, `DOMAIN`, `FUZZ` into the body; the tool tests each one in turn
- **185+ built-in payloads** — boolean bypass, AD attribute enumeration, blind enum, encoding bypass, OID-based, DN injection
- **5 detectors** — status change, length diff, success keyword, error gone, redirect change
- **Confidence scoring** — 1 detector → POTENTIAL, 2+ → HIGH CONFIDENCE
- **ASP.NET awareness** — detects `__VIEWSTATE` / `__EVENTVALIDATION` and warns about token expiry
- **Lockout protection** — mandatory confirmation, minimum delay, and max-attempts cap for KNOWNUSER and PASSWORD injection
- **Legacy TLS support** — `--legacy-ssl` flag for older IIS / appliances incompatible with OpenSSL 3+ default policies
- **Auto Content-Length recompute** — header recalculated on every payload
- **URL encoding collision prevention** — already-encoded payloads are not re-encoded
- **JSON reporting** — timestamped, machine-readable output
- **Proxy support** — routes through Burp / ZAP for inspection
- **Graceful Ctrl+C** — partial results are saved on interrupt

---

## Installation

```bash
git clone https://github.com/<user>/ldapscanner.git
cd ldapscanner
pip install -r requirements.txt
```

`requirements.txt`:
```
requests>=2.28
urllib3>=1.26
colorama>=0.4
certifi
```

Or directly:

```bash
pip install requests urllib3 colorama certifi
```

Requires Python 3.8+. Tested on Kali Linux, Ubuntu 22.04+, Windows 10/11, macOS 13+.

---

## Quick Start

### 1. Capture the request in Burp

Burp Proxy → HTTP history → right-click the target POST → **Copy to file** (raw, not curl):

```http
POST /LoginPage.aspx HTTP/1.1
Host: target.example.com
Cookie: ASP.NET_SessionId=quh1kxikgs153cx1q3110mrr
Content-Type: application/x-www-form-urlencoded
Content-Length: 87

__VIEWSTATE=6%2FRrZ2fj...&cboDomain=Emptor&txtLogonName=admin&txtPassword=test&btnSubmit=
```

### 2. Place markers

Replace the **values** you want to fuzz with marker keywords:

```http
POST /LoginPage.aspx HTTP/1.1
Host: target.example.com
Cookie: ASP.NET_SessionId=quh1kxikgs153cx1q3110mrr
Content-Type: application/x-www-form-urlencoded
Content-Length: 87

__VIEWSTATE=6%2FRrZ2fj...&cboDomain=DOMAIN&txtLogonName=USERNAME&txtPassword=PASSWORD&btnSubmit=
```

Save as `request.txt`.

### 3. Run

```bash
python3 ldapscanner.py -r request.txt --ssl
```

For older IIS / legacy appliances:

```bash
python3 ldapscanner.py -r request.txt --ssl --legacy-ssl --no-verify
```

---

## Marker System

Place markers manually in the body; the tool maps each one to its form field automatically.

| Marker | Behavior | Lockout Risk | Notes |
|--------|----------|--------------|-------|
| `USERNAME` | Injects payloads directly | None (invalid users don't increment counter) | Default first choice |
| `KNOWNUSER` | **Appends** payload after a real username | **High** | Requires `--known-user`, enforces 2.0s min delay, max-attempts cap |
| `PASSWORD` | Dummy value by default, injection only with `--inject-password` | **High** | Confirmation prompt |
| `DOMAIN` | Only domain-relevant payloads (objectClass, cn=, uid=, dc=, ou=) | None | Useful for AD multi-tenant systems |
| `FUZZ` | General purpose, full wordlist | None | For generic fields |

**Multi-marker scans:** the tool tests one marker at a time. While injecting field A, all other marked fields use safe baseline values.

### Marker examples

```http
# Single field test
txtLogonName=USERNAME&txtPassword=anything

# Multi-field, sequential scan
cboDomain=DOMAIN&txtLogonName=USERNAME&txtPassword=PASSWORD

# Known user with payload suffix
txtLogonName=KNOWNUSER&txtPassword=anything
# (with --known-user admin, becomes "admin" + payload)

# Generic JSON API
{"query": "FUZZ", "filter": "active"}
```

---

## Scan Modes

```bash
--mode full     # Full wordlist (default, ~185 payloads)
--mode bypass   # Auth-bypass focused (~26 payloads, fast triage)
--mode enum     # Blind enumeration only (cn=a*, samaccountname=admin*, ...)
```

Recommended flow: start with `--mode bypass` for a fast initial sweep, drill into promising fields with `--mode full`, and finish with `--mode enum` to extract usernames once a bypass is confirmed.

---

## Detection Engine

Every payload response is compared against the invalid-user baseline:

| Detector | Description |
|----------|-------------|
| `STATUS_CHANGE` | HTTP status differs from baseline |
| `LENGTH_DIFF` | Body length differs by more than `--threshold` bytes (default 50) |
| `SUCCESS_KEYWORD` | Success keyword found in body (`dashboard`, `welcome`, `home`, ...) |
| `ERROR_GONE` | Baseline error keyword absent from current response (`invalid`, `error`, ...) |
| `REDIRECT_CHANGE` | `Location` header differs from baseline |

**Confidence buckets:**
- 0 detectors → CLEAN (shown only with `--verbose`)
- 1 detector → `[+] POTENTIAL` (yellow)
- 2+ detectors → `[VULN] HIGH CONFIDENCE` (red bold)

### Custom keywords

For non-English or application-specific apps:

```bash
--success-kw "dashboard,welcome,profile,logout,home"
--error-kw "invalid,error,incorrect,failed,unauthorized"
```

For a Turkish app:

```bash
--success-kw "anasayfa,hoşgeldin,başarılı,profil,çıkış"
--error-kw "hatalı,geçersiz,boş,kullanıcı kodu hatalı,şifre yanlış"
```

---

## Safety Features

### KNOWNUSER injection

Appends payloads to a real user account — can trigger lockout policy. The tool enforces:

1. `--known-user <username>` is mandatory (exits otherwise)
2. Lockout warning + interactive **y/N confirmation**
3. Minimum 2.0s delay (override with `--force`, extra warning shown)
4. `--max-attempts` caps the attempt count (default: 10)
5. Per-request attempt counter in output

```bash
python3 ldapscanner.py -r request.txt --ssl \
    --known-user jsmith --max-attempts 5 --delay 3
```

### PASSWORD injection

By default the `PASSWORD` marker is **not** injected — it's substituted with the dummy `Passw0rd!Test`. To enable injection:

```bash
python3 ldapscanner.py -r request.txt --ssl --inject-password
```

This also prompts for confirmation. Bad passwords increment the lockout counter on most systems.

---

## CLI Reference

```
Required:
  -r, --request PATH            Raw HTTP request .txt file

Optional:
  -w, --wordlist PATH           External wordlist (overrides built-in)
  --mode {full,bypass,enum}     Scan mode (default: full)
  --known-user USER             Real username for the KNOWNUSER marker
  --inject-password             Inject payloads into the PASSWORD field
  --max-attempts N              Cap for KNOWNUSER attempts (default: 10)
  --delay SECONDS               Inter-request delay (default: 0.5)
  --force                       Allow KNOWNUSER delay below the 2.0s floor

Network:
  --ssl                         Force HTTPS
  --no-verify                   Disable SSL certificate verification
  --legacy-ssl                  Enable TLS legacy renegotiation + low SECLEVEL
                                (for older IIS / appliances)
  --proxy URL                   Proxy URL (e.g. http://127.0.0.1:8080)
  --timeout SECONDS             Request timeout (default: 10)

Payload control:
  --encode                      URL-encode payloads (skips already-encoded)
  --threshold BYTES             LENGTH_DIFF threshold (default: 50)

Baseline and detection:
  --baseline-user USER          Valid username for success baseline
  --baseline-pass PASS          Valid password for success baseline
  --success-kw "a,b,c"          Custom success keywords
  --error-kw "a,b,c"            Custom error keywords

Output:
  --output FILE                 Custom JSON output filename
  --only-findings               Only write triggered results to JSON
  --verbose                     Print every request including CLEAN ones
```

---

## Common Scenarios

### Scenario 1: Standard ASP.NET login form

```bash
python3 ldapscanner.py -r request.txt --ssl
```

ViewState / EventValidation tokens are detected and warned about at startup. If the baseline starts returning 400/500 mid-scan, re-capture the request from Burp — ASP.NET session tokens expire fast.

### Scenario 2: Legacy enterprise IIS (TLS handshake failure)

```
SSLError: UNSAFE_LEGACY_RENEGOTIATION_DISABLED
```

Fix:

```bash
python3 ldapscanner.py -r request.txt --ssl --legacy-ssl --no-verify
```

The `--legacy-ssl` flag rebuilds the SSL context with `OP_LEGACY_SERVER_CONNECT` and `SECLEVEL=0` ciphers. This resolves the incompatibility between OpenSSL 3+ defaults and older servers that don't implement RFC 5746 secure renegotiation.

### Scenario 3: Burp proxy for inspection

```bash
python3 ldapscanner.py -r request.txt --ssl --no-verify \
    --proxy http://127.0.0.1:8080 --delay 1
```

All requests flow through Burp Proxy — inspect them in HTTP history.

### Scenario 4: Stealth scan (low and slow)

```bash
python3 ldapscanner.py -r request.txt --ssl \
    --delay 5 --mode bypass --only-findings
```

Bypass payloads only, 5-second spacing, JSON contains only findings.

### Scenario 5: Active Directory enumeration

Once you have a confirmed bypass, extract usernames:

```bash
python3 ldapscanner.py -r request.txt --ssl --mode enum --delay 2
```

Iterates `*(|(cn=a*))`, `*(|(samaccountname=admin*))`, etc. — prefix-based enumeration.

### Scenario 6: API endpoint with JSON body

```http
POST /api/search HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGc...
Content-Type: application/json

{"query": "FUZZ", "limit": 10}
```

```bash
python3 ldapscanner.py -r api_request.txt --ssl
```

The `FUZZ` marker works in any body format — JSON, XML, multipart, etc. Just place it where the value goes.

---

## Output Format

Console:

```
[0023/0312] Field: txtLogonName | Payload: *(|(objectClass=*)) | Status: 302 | Len: 1243 (+891) | Time: 0.34s | [STATUS CHANGE] [LENGTH DIFF] [REDIRECT CHANGE]
```

JSON (`ldap_results_YYYYMMDD_HHMMSS.json`):

```json
{
  "meta": {
    "tool": "ldapscanner.py",
    "version": "1.0",
    "target_url": "https://target.example.com/LoginPage.aspx",
    "method": "POST",
    "mode": "full",
    "scan_started": "2026-05-13T14:23:01Z",
    "scan_ended": "2026-05-13T14:27:24Z",
    "total_requests": 312,
    "findings": 7,
    "high_confidence": 2,
    "baseline_invalid": {
      "status": 200, "length": 22984, "time": 0.31, "location": null
    }
  },
  "results": [
    {
      "timestamp": "2026-05-13T14:23:14Z",
      "field": "txtLogonName",
      "marker": "USERNAME",
      "payload": "*(|(objectClass=*))",
      "payload_index": 23,
      "status_code": 302,
      "response_length": 1243,
      "response_time": 0.34,
      "baseline_status": 200,
      "baseline_length": 22984,
      "baseline_time": 0.31,
      "detectors_fired": ["STATUS_CHANGE", "LENGTH_DIFF", "REDIRECT_CHANGE"],
      "confidence": "HIGH",
      "vulnerable": true,
      "error": null
    }
  ]
}
```

---

## From Finding to Exploitation

The tool only *detects*. Recommended workflow after a confirmed finding:

1. **Triage** — manually replay the payload in Burp Repeater, confirm it isn't a false positive
2. **Auth bypass** — replay the bypass payload, follow the redirect, capture the session cookie
3. **Blind enumeration** — DFS-walk usernames via `*)(cn=a*`, `*)(cn=ab*`, etc.
4. **Attribute extraction** — char-by-char enumerate `description`, `memberOf`, `mail` of identified users
5. **High-value targets** — `memberOf=CN=Domain Admins*`, `servicePrincipalName=*` (Kerberoastable), `adminCount=1` to enumerate privileged accounts
6. **Report** — split each impact into its own finding (auth bypass, info disclosure, AD recon — these are separate severities)

References: [HackTricks LDAP Injection](https://book.hacktricks.xyz/pentesting-web/ldap-injection), [PortSwigger LDAP Injection](https://portswigger.net/web-security/ldap-injection), [OWASP WSTG-INPV-06](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection).

---

## Limitations

- Markers are intended for **body** placement; path/header markers technically work but field mapping is body-only
- No HTTP/2 (requests library limitation)
- Not designed for WebSocket or stateful multi-step login flows
- LDAP-specific only — does not test for SQLi, NoSQLi, etc. (use sqlmap, NoSQLMap)
- Apps with strict ASP.NET ViewState validation may require frequent re-capture during long scans

---

## Development

Single-file by design — easy to deploy, easy to audit. To add payloads, edit the `BUILTIN_WORDLIST` constant. To add a detector, extend the `detect()` function.

Before opening an issue / PR:
- Verify against legal targets (DVWA, vAPI, OWASP Juice Shop, the PortSwigger Web Academy LDAP injection labs)
- Confirm existing detectors still work
- `python3 -m py_compile ldapscanner.py` for syntax check

---

## FAQ

**Q: The scan is too slow. Can I speed it up?**
A: You can set `--delay 0` but you may trip rate-limiting or a WAF. Better: use `--mode bypass` to drop to ~26 payloads, then drill into promising fields with `--mode full`.

**Q: Every payload returns CLEAN, but I know the target is vulnerable.**
A: (1) Check the baseline — if invalid users also redirect with 302, your baseline already looks "vulnerable" and payloads produce no differential. (2) Lower `--threshold` (default 50, try 10). (3) Adjust `--success-kw` and `--error-kw` to the target's language and copy. (4) Run with `--verbose` to see every response.

**Q: I'm getting `__VIEWSTATE` validation errors mid-scan.**
A: ViewState is server-signed in ASP.NET and expires quickly. Re-capture the request from Burp and start the scan within 2-3 minutes.

**Q: Which LDAP servers were tested?**
A: Microsoft Active Directory (Windows Server 2012-2022), OpenLDAP 2.4+, Oracle Internet Directory. Uses generic LDAP filter syntax, so any RFC-compliant directory should work.

**Q: Does it find other injection types?**
A: No — LDAP-specific. Use sqlmap, ffuf, or Burp Active Scan for everything else.

**Q: Why not just use Burp Active Scan?**
A: Active Scan is great but it's a black box. `ldapscanner` gives you explicit control over markers, exact payload visibility, lockout-aware rate limiting for AD targets, and machine-readable output for chaining into other tooling. Use both — they complement each other.

---

## Contributing

PRs welcome. Areas of interest: new payloads, new detectors, additional language support for keyword sets, HTTP/2 support, smarter baseline detection.

---

## Contact

- Issues: [GitHub Issues](https://github.com/tburakdirlik/ldapscanner/issues)

**Reminder:** for authorized security testing only. Unauthorized use is the user's responsibility.
