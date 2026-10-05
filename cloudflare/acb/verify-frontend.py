#!/usr/bin/env python3
"""Read-only frontend smoke checks; never accept challenge HTML as a release.

Static mode compares decoded responses to a verified dist directory. Rollback
mode deliberately cannot attest artifact checksums. Access mode checks only the
unauthenticated bank login redirect, never the bank's deployed release.
"""

import argparse
from dataclasses import dataclass
import email
import subprocess
from html.parser import HTMLParser
import http.client
import json
from pathlib import Path
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib


GLOBAL_CSP = "default-src 'self'; base-uri 'none'; frame-ancestors 'self'; form-action 'self'; object-src 'none'; script-src 'self' https://static.cloudflareinsights.com; script-src-elem 'self' https://static.cloudflareinsights.com 'unsafe-inline'; script-src-attr 'none'; connect-src 'self' ws: wss: https://cloudflareinsights.com; img-src 'self' data: blob: https:; font-src 'self' data:; style-src 'self' 'unsafe-inline'"
CREDENTIALS_CSP = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; script-src 'self'; script-src-attr 'none'; connect-src 'self'; img-src 'self' data:; font-src 'self'; style-src 'self' 'unsafe-inline'"
ACCESS_HOST = "thedemontuan.cloudflareaccess.com"
TIMEOUT = 15
MAX_BODY = 25 * 1024 * 1024
JS_MIMES = {"text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript"}


class VerificationError(Exception):
    """A safe diagnostic, intentionally containing no response body or headers."""


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def origin_key(url):
    parsed = urllib.parse.urlsplit(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port or (443 if parsed.scheme == "https" else 80)


def validate_origin(value):
    try:
        parsed = urllib.parse.urlsplit(value)
        valid = (parsed.scheme in {"http", "https"} and parsed.hostname
                 and parsed.username is None and parsed.password is None
                 and parsed.path in {"", "/"} and not parsed.query and not parsed.fragment
                 and not any(c.isspace() or ord(c) < 32 for c in value))
        origin_key(value)  # Also validate the port.
    except ValueError:
        valid = False
    require(valid, "origin must be an HTTP(S) origin without credentials, path, query or fragment")
    return value.rstrip("/")


class SafeRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin, follow):
        self.origin = origin_key(origin)
        self.follow = follow
        self.deadline = 0.0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self.follow:
            return None
        try:
            parsed = urllib.parse.urlsplit(newurl)
            safe = (origin_key(newurl) == self.origin and parsed.username is None
                    and parsed.password is None and not parsed.fragment)
        except ValueError:
            safe = False
        require(safe, "cross-origin or unsafe redirect rejected")
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "request exceeded 15 seconds")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            redirected.timeout = remaining
        return redirected

    def http_error_302(self, req, fp, code, msg, headers):
        location = headers.get("Location") or headers.get("URI")
        if not self.follow or not location:
            return None
        newurl = urllib.parse.urljoin(req.full_url, location)
        try:
            redirected = self.redirect_request(req, fp, code, msg, headers, newurl)
            count = getattr(req, "frontend_redirects", 0)
            require(count < 5, "too many same-origin redirects")
            redirected.frontend_redirects = count + 1
        finally:
            # Never drain or log redirect bodies; they need not be bounded.
            fp.close()
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "request exceeded 15 seconds")
        return self.parent.open(redirected, timeout=remaining)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


@dataclass
class Response:
    status: int
    headers: object
    body: bytes

    def header(self, name):
        return ", ".join(self.headers.get_all(name, []))

    def mime(self):
        values = self.headers.get_all("Content-Type", [])
        require(len(values) == 1 and "," not in values[0], "missing or ambiguous Content-Type")
        return values[0].split(";", 1)[0].strip().lower()


class Client:
    def __init__(self, origin, follow=True):
        self.origin = origin
        self.redirects = SafeRedirects(origin, follow)
        # No cookie jar, authorization, ambient proxies, or redirect to Access.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), self.redirects)

    def get(self, path, headers=None):
        require(path.startswith("/") and not path.startswith("//"), "request path must be origin-relative")
        request = urllib.request.Request(self.origin + path, headers={
            "Accept-Encoding": "identity", "User-Agent": "acb-frontend-verifier/1", **(headers or {})})
        self.redirects.deadline = time.monotonic() + TIMEOUT
        try:
            result = None
            try:
                response = self.opener.open(request, timeout=TIMEOUT)
            except urllib.error.HTTPError as error:
                if error.code == 403 and self.origin.startswith("https://"):
                    error.close()
                    remaining = self.redirects.deadline - time.monotonic()
                    require(remaining > 0, "request exceeded 15 seconds")
                    with tempfile.TemporaryDirectory() as tmpdir:
                        header_path = Path(tmpdir) / "headers.txt"
                        body_path = Path(tmpdir) / "body.bin"
                        cmd = [
                            "curl", "-q",
                            "--noproxy", "*",
                            "-sS",
                            "--dump-header", str(header_path),
                            "--output", str(body_path),
                            "--max-filesize", str(MAX_BODY),
                            "--max-time", f"{remaining:.3f}",
                        ]
                        for k, v in request.headers.items():
                            cmd.extend(["-H", f"{k}: {v}"])
                        cmd.append(self.origin + path)
                        try:
                            proc = subprocess.run(cmd, capture_output=True, timeout=remaining)
                        except (subprocess.TimeoutExpired, OSError):
                            raise VerificationError("HTTP request or response decoding failed") from None
                        if proc.returncode != 0:
                            raise VerificationError("HTTP request or response decoding failed")
                        if not header_path.is_file():
                            raise VerificationError("HTTP request or response decoding failed")
                        header_bytes = header_path.read_bytes()
                        blocks = [b.strip() for b in re.split(rb"\r?\n\r?\n", header_bytes) if b.strip()]
                        if not blocks:
                            raise VerificationError("HTTP request or response decoding failed")
                        final_block = blocks[-1]
                        status_line, _, header_lines = final_block.partition(b"\r\n") if b"\r\n" in final_block else final_block.partition(b"\n")
                        status_match = re.search(r"HTTP/\S+\s+(\d+)", status_line.decode("latin1", errors="replace"))
                        if not status_match:
                            raise VerificationError("HTTP request or response decoding failed")
                        status = int(status_match.group(1))
                        if status == 403:
                            raise VerificationError("HTTP request failed with status 403")
                        body = b""
                        if status == 200:
                            if not body_path.is_file():
                                raise VerificationError("HTTP request or response decoding failed")
                            with open(body_path, "rb") as f:
                                body = f.read(MAX_BODY + 1)
                            require(len(body) <= MAX_BODY, "response exceeds the static asset size limit")
                        headers = email.message_from_bytes(header_lines)
                        require(time.monotonic() <= self.redirects.deadline, "request exceeded 15 seconds")
                        result = Response(status, headers, body)
                else:
                    response = error
            if result is None:
                with response:
                    require(origin_key(response.geturl()) == origin_key(self.origin), "response left the requested origin")
                    status = response.code
                    body = b""
                    # Never read error/redirect bodies, which may contain sensitive data.
                    if status == 200:
                        chunks = []
                        size = 0
                        stream = response.fp if isinstance(response, urllib.error.HTTPError) else response
                        while True:
                            remaining = self.redirects.deadline - time.monotonic()
                            require(remaining > 0, "request exceeded 15 seconds")
                            # urllib's socket timeout alone resets per read. Bound the
                            # whole response, including a slowly streamed body.
                            raw_socket = stream.fp.raw._sock
                            raw_socket.settimeout(remaining)
                            chunk = stream.read1(min(65536, MAX_BODY + 1 - size))
                            if not chunk:
                                break
                            size += len(chunk)
                            require(size <= MAX_BODY, "response exceeds the static asset size limit")
                            chunks.append(chunk)
                            if stream.isclosed():
                                break
                        body = b"".join(chunks)
                    require(time.monotonic() <= self.redirects.deadline, "request exceeded 15 seconds")
                    result = Response(status, response.headers, body)
            encoding = result.header("Content-Encoding").strip().lower()
            if body and encoding not in {"", "identity"}:
                if encoding == "gzip":
                    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                elif encoding == "deflate":
                    decoder = zlib.decompressobj()
                else:
                    raise VerificationError("unsupported response content encoding")
                decoded = decoder.decompress(body, MAX_BODY + 1)
                require(len(decoded) <= MAX_BODY and not decoder.unconsumed_tail,
                        "decoded response exceeds the static asset size limit")
                require(decoder.eof and not decoder.unused_data, "invalid compressed response")
                result.body = decoded
            require(time.monotonic() <= self.redirects.deadline, "request exceeded 15 seconds")
            return result
        except VerificationError:
            raise
        except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException, zlib.error, AttributeError):
            # Do not print exception strings: they can contain URLs or server data.
            raise VerificationError("HTTP request or response decoding failed") from None

    def stream_events(self, path):
        require(path.startswith("/") and not path.startswith("//"), "request path must be origin-relative")
        request = urllib.request.Request(self.origin + path, headers={
            "Accept": "text/event-stream",
            "Accept-Encoding": "identity",
            "User-Agent": "acb-frontend-verifier/1",
        })
        deadline = time.monotonic() + TIMEOUT
        self.redirects.deadline = deadline
        try:
            response = self.opener.open(request, timeout=TIMEOUT)
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as error:
            if time.monotonic() >= deadline or "timed out" in str(error).lower():
                raise VerificationError("request exceeded 15 seconds") from None
            raise VerificationError("failed to open event stream") from None
        with response:
            require(origin_key(response.geturl()) == origin_key(self.origin), "response left the requested origin")
            require(response.code == 200, "event stream did not return 200")
            content_type = response.headers.get("Content-Type", "")
            require(content_type.split(";")[0].strip().lower() == "text/event-stream", "event stream MIME mismatch")
            cache_ctrl = response.headers.get("Cache-Control", "").lower()
            directives = [p.strip() for p in cache_ctrl.split(",") if p.strip()]
            require("no-cache" in directives and "no-transform" in directives, "event stream missing no-cache or no-transform")
            for d in directives:
                k, _, v = d.partition("=")
                k = k.strip()
                require(k != "immutable", "event stream has immutable cache directive")
                if k == "max-age":
                    try:
                        require(int(v.strip()) <= 0, "event stream has positive max-age")
                    except ValueError:
                        raise VerificationError("invalid max-age directive") from None
            stream = response.fp if hasattr(response, "fp") else response
            raw_socket = getattr(stream.fp.raw, "_sock", None) if hasattr(stream, "fp") and hasattr(stream.fp, "raw") else None
            FRAME_LIMIT = 64 * 1024
            received_initial_state = False
            received_heartbeat = False
            total_bytes = 0
            buffer = bytearray()
            while not (received_initial_state and received_heartbeat):
                remaining = deadline - time.monotonic()
                require(remaining > 0, "request exceeded 15 seconds")
                if raw_socket:
                    try:
                        raw_socket.settimeout(remaining)
                    except (OSError, AttributeError):
                        pass
                try:
                    chunk = stream.read1(min(4096, MAX_BODY + 1 - total_bytes)) if hasattr(stream, "read1") else stream.read(min(4096, MAX_BODY + 1 - total_bytes))
                except (OSError, TimeoutError) as error:
                    if time.monotonic() >= deadline or "timed out" in str(error).lower():
                        raise VerificationError("request exceeded 15 seconds") from None
                    raise VerificationError("failed to read from event stream") from None
                require(bool(chunk), "event stream closed prematurely")
                total_bytes += len(chunk)
                require(total_bytes <= MAX_BODY, "response exceeds the static asset size limit")
                buffer.extend(chunk)
                while True:
                    m = re.search(rb"\r?\n\r?\n", buffer)
                    if not m:
                        require(len(buffer) <= FRAME_LIMIT, "SSE frame exceeds frame size limit")
                        break
                    frame_bytes = bytes(buffer[:m.start()])
                    del buffer[:m.end()]
                    require(len(frame_bytes) <= FRAME_LIMIT, "SSE frame exceeds frame size limit")
                    if not frame_bytes.strip():
                        continue
                    event_type = "message"
                    data_lines = []
                    for line in frame_bytes.splitlines():
                        if not line or line.startswith(b":"):
                            continue
                        field, _, val = line.partition(b":")
                        field = field.decode("latin1").strip()
                        val = val.lstrip(b" ")
                        if field == "event":
                            event_type = val.decode("utf-8", errors="replace").strip()
                        elif field == "data":
                            data_lines.append(val)
                    if event_type == "initial_state":
                        require(not received_initial_state, "duplicate initial_state event")
                        require(bool(data_lines), "missing data in initial_state event")
                        payload = b"\n".join(data_lines)
                        try:
                            parsed_payload = json.loads(payload.decode("utf-8"))
                        except (ValueError, UnicodeDecodeError):
                            raise VerificationError("malformed initial_state payload") from None
                        require(isinstance(parsed_payload, dict), "initial_state data must be a JSON object")
                        received_initial_state = True
                    elif event_type == "stream.heartbeat":
                        require(received_initial_state, "stream.heartbeat received before initial_state")
                        require(bool(data_lines), "missing data in stream.heartbeat event")
                        payload = b"\n".join(data_lines)
                        try:
                            parsed_payload = json.loads(payload.decode("utf-8"))
                        except (ValueError, UnicodeDecodeError):
                            raise VerificationError("malformed stream.heartbeat payload") from None
                        require(isinstance(parsed_payload, dict), "stream.heartbeat data must be a JSON object")
                        received_heartbeat = True
                        break

def cache_directives(response):
    directives = {}
    for part in response.header("Cache-Control").split(","):
        part = part.strip()
        if not part:
            continue
        key, separator, value = part.partition("=")
        key = key.strip().lower()
        require(re.fullmatch(r"[a-z][a-z0-9-]*", key) is not None, "invalid Cache-Control directive")
        require(key not in directives, "duplicate Cache-Control directive")
        directives[key] = value.strip().strip('"') if separator else None
        if key in {"public", "no-store", "immutable", "must-revalidate", "proxy-revalidate"}:
            require(not separator, "invalid value on a flag Cache-Control directive")
    require(not ({"public", "private"} <= directives.keys()), "conflicting cache visibility directives")
    require(not ("no-store" in directives and any(k in directives for k in ("public", "immutable", "max-age", "s-maxage"))),
            "conflicting no-store cache directives")
    require(not ("immutable" in directives and any(k in directives for k in ("no-cache", "must-revalidate", "proxy-revalidate"))),
            "conflicting immutable cache directives")
    for key in ("max-age", "s-maxage"):
        if key in directives:
            require(directives[key] is not None and re.fullmatch(r"[0-9]+", directives[key]), "invalid cache lifetime")
    return directives


def revalidating(response, require_policy=True):
    directives = cache_directives(response)
    require("immutable" not in directives, "non-asset response is immutable")
    if require_policy:
        require("no-store" in directives or "no-cache" in directives
                or (directives.get("max-age") == "0" and "must-revalidate" in directives),
                "response lacks a revalidation cache policy")
    for key in ("max-age", "s-maxage"):
        require(int(directives.get(key) or "0") == 0, "non-immutable response has a positive cache lifetime")
    return directives


def csp_policy(value):
    directives = {}
    for part in value.split(";"):
        words = part.split()
        if words:
            name = words[0].lower()
            require(name not in directives, "duplicate CSP directive")
            directives[name] = frozenset(words[1:])
    return directives


def security(response, credentials=False):
    require(response.header("X-Content-Type-Options").strip().lower() == "nosniff", "nosniff header mismatch")
    require(response.header("X-Frame-Options").strip().upper() == "DENY", "frame protection header mismatch")
    referrer = response.header("Referrer-Policy").strip().lower()
    require(referrer in ({"no-referrer"} if credentials else {"strict-origin-when-cross-origin", "no-referrer"}),
            "referrer policy mismatch")
    values = response.header("Content-Security-Policy").split(",")
    require(all(value.strip() for value in values), "missing CSP policy")
    policies = [csp_policy(value) for value in values]
    global_policy, strict_policy = csp_policy(GLOBAL_CSP), csp_policy(CREDENTIALS_CSP)
    if credentials:
        # Multiple CSP policies are enforced by intersection, not last-write wins.
        # Strict script-src also governs script-src-elem absent from that policy.
        require(policies == [strict_policy] or (len(policies) == 2 and global_policy in policies and strict_policy in policies),
                "credentials CSP must be the strict policy or the approved policy intersection")
        require("no-store" in cache_directives(response), "credentials response is not no-store")
    else:
        require(policies == [global_policy], "global CSP policy mismatch")


class EntryHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = False
        self.module = False
        self.entries = []
        self.has_base = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "div" and attrs.get("id") == "root":
            self.root = True
        if tag == "base":
            self.has_base = True
        if tag == "script" and attrs.get("src"):
            is_module = attrs.get("type", "").lower() == "module"
            self.entries.append((attrs["src"], "js", is_module))
        if tag == "link" and attrs.get("href"):
            rel = set(attrs.get("rel", "").lower().split())
            if "stylesheet" in rel:
                self.entries.append((attrs["href"], "css", False))
            elif "modulepreload" in rel:
                self.entries.append((attrs["href"], "js", False))

    handle_startendtag = handle_starttag


def local_entries(body, page_url, origin):
    parser = EntryHTML()
    try:
        parser.feed(body.decode("utf-8"))
        parser.close()
    except (UnicodeError, ValueError):
        raise VerificationError("HTML is not valid UTF-8 entry markup") from None
    require(parser.root and not parser.has_base, "HTML is missing the root mount or changes its base URL")
    entries = []
    for reference, kind, module in parser.entries:
        try:
            url = urllib.parse.urljoin(page_url, reference)
            parsed = urllib.parse.urlsplit(url)
            same_origin = origin_key(url) == origin_key(origin)
        except ValueError:
            raise VerificationError("invalid HTML asset reference") from None
        if not same_origin:
            if parsed.hostname == "static.cloudflareinsights.com":
                continue
            require(not module, "module entry must be same-origin")
            continue  # Existing global CSP permits the external analytics script.
        require(parsed.username is None and parsed.password is None and not parsed.fragment,
                "unsafe HTML asset reference")
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        entries.append((path, kind))
        if module:
            parser.module = True
    require(parser.module, "HTML is missing a local module script entry")
    return entries


class BeaconTag(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.attributes = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.attributes.append(attrs)


def without_edge_beacon(body):
    removed = False

    def replace(match):
        nonlocal removed
        parser = BeaconTag()
        try:
            parser.feed(match.group().decode("utf-8"))
            parser.close()
        except (UnicodeError, ValueError):
            return match.group()
        if removed or len(parser.attributes) != 1:
            return match.group()
        pairs = parser.attributes[0]
        attrs = dict(pairs)
        required = {"src", "integrity", "data-cf-beacon", "crossorigin"}
        if (len(pairs) != len(attrs) or not required <= attrs.keys() or
                not attrs.keys() <= required | {"defer", "type"} or
                not re.fullmatch(r"https://static\.cloudflareinsights\.com/beacon\.min\.js(?:/v[0-9a-f]{32}(?:[0-9]{13})?)?", attrs["src"]) or
                not re.fullmatch(r"sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}", attrs["integrity"]) or
                attrs["crossorigin"] != "anonymous" or
                attrs.get("type", "module") != "module" or
                not attrs["data-cf-beacon"]):
            return match.group()
        removed = True
        return b""

    # Remove only one empty, tightly allowlisted edge analytics tag. All other
    # HTML bytes and every JS/CSS byte remain authoritative.
    return re.sub(rb"<script\b[^>]*>\s*</script\s*>", replace, body, flags=re.IGNORECASE)

def without_edge_security_bootstrap(body, expected=None):
    pattern = (
        rb"<script>\s*"
        rb"window\.__CF\$cv\$params=\{r:'[0-9a-f]+',t:'[A-Za-z0-9+/=]+',u:'[0-9a-f]{32}',"
        rb"ut:'[A-Za-z0-9_.-]+',i:\d+\};"
        rb"\(function\(\)\{if\(!document\.body\)return;var s=document\.createElement\('script'\);"
        rb"s\.src='/cdn-cgi/challenge-platform/scripts/precursor/main\.js';document\.head\.appendChild\(s\);\}\)\(\);"
        rb"\s*</script>"
    )
    matches = list(re.finditer(pattern, body))
    if len(matches) != 1:
        return body, False
    match = matches[0]
    start, end = match.start(), match.end()
    if start > 0 and body[start - 1:start] in (b"\n", b"\r"):
        start -= 1
    elif end < len(body) and body[end:end + 1] in (b"\n", b"\r"):
        end += 1
    cleaned = body[:start] + body[end:]
    if expected and cleaned != expected and cleaned.split() == expected.split():
        if re.sub(rb">\s+<", rb"><", cleaned) == re.sub(rb">\s+<", rb"><", expected):
            return expected, True
    return cleaned, True


class Artifact:
    def __init__(self, directory):
        self.root = Path(directory).resolve()
        require(self.root.is_dir(), "artifact directory does not exist")
        self.bytes_for("/index.html")
        self.immutable = True
        self.edge_analytics_excluded = False
        self.edge_security_excluded = False
        # rules. Read that decision from the verified artifact, not live headers.
        header_file = self.root / "_headers"
        if header_file.is_file():
            try:
                text = header_file.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                raise VerificationError("cannot read artifact headers") from None
            rules = [line for line in text.splitlines() if line and not line[0].isspace() and not line.startswith("#")]
            assets = self.root / "assets"
            fingerprints = [path for path in assets.rglob("*") if path.is_file()
                            and re.search(r"-[A-Za-z0-9_-]{8,}\.[^.]+$", path.name)] if assets.is_dir() else []
            if len(fingerprints) + 4 > 100 and "immutable" not in text:
                require(len(rules) == 4, "artifact rule-limit fallback must retain all security rules")
                self.immutable = False

    def bytes_for(self, request_path):
        parsed = urllib.parse.urlsplit(request_path)
        path = urllib.parse.unquote(parsed.path)
        require(path.startswith("/") and "\\" not in path and "\x00" not in path,
                "unsafe artifact reference")
        parts = path[1:].split("/")
        require(all(part not in {"", ".", ".."} for part in parts), "unsafe artifact reference")
        candidate = self.root.joinpath(*parts)
        require(all(not self.root.joinpath(*parts[:i]).is_symlink() for i in range(1, len(parts) + 1)),
                "artifact references a symlink")
        require(candidate.is_file() and candidate.stat().st_size <= MAX_BODY, "referenced artifact file is missing or oversized")
        try:
            return candidate.read_bytes()
        except OSError:
            raise VerificationError("cannot read referenced artifact file") from None

    def compare(self, path, body):
        expected = self.bytes_for(path)
        normalized = body
        if body != expected and path == "/index.html":
            normalized = without_edge_beacon(body)
            beacon_removed = normalized != body
            normalized, security_removed = without_edge_security_bootstrap(normalized, expected)
            if expected and normalized != expected and normalized.split() == expected.split():
                if re.sub(rb">\s+<", rb"><", normalized) == re.sub(rb">\s+<", rb"><", expected):
                    normalized = expected
            if normalized == expected:
                self.edge_analytics_excluded = beacon_removed
                self.edge_security_excluded = security_removed
                body = normalized
        if body != expected:
            parser = BeaconTag()
            if path == '/index.html':
                parser.feed(body.decode('utf-8', errors='replace'))
            beacon_types = []
            beacon_guards = []
            for pairs in parser.attributes:
                attrs = dict(pairs)
                if attrs.get('src', '').startswith('https://static.cloudflareinsights.com/beacon.min.js'):
                    kind = attrs.get('type', 'missing')
                    beacon_types.append(kind if kind in {'missing', 'module', 'text/javascript', 'application/javascript'} else 'other')
                    known = {'src', 'integrity', 'data-cf-beacon', 'crossorigin', 'defer', 'type'}
                    extra = sorted(name if name in {'async', 'nonce', 'referrerpolicy', 'data-cfasync', 'data-cf-settings'} else 'other'
                                   for name in attrs.keys() - known)
                    beacon_guards.append({
                        'extra_attributes': extra,
                        'duplicate_attributes': len(pairs) != len(attrs),
                        'src_allowed': bool(re.fullmatch(r'https://static\.cloudflareinsights\.com/beacon\.min\.js(?:/v[0-9a-f]{32}(?:[0-9]{13})?)?', attrs['src'])),
                        'integrity_allowed': bool(re.fullmatch(r'sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}', attrs.get('integrity', ''))),
                        'anonymous_crossorigin': attrs.get('crossorigin') == 'anonymous',
                        'data_present': bool(attrs.get('data-cf-beacon'))})
            raise VerificationError(
                f'decoded response checksum does not match artifact: path={path}; '
                f'actual_bytes={len(body)}; artifact_bytes={len(expected)}; '
                f'beacon_removed={normalized != body}; '
                f'whitespace_only={normalized.split() == expected.split()}; '
                f'beacon_types={beacon_types}; beacon_guards={beacon_guards}; '
                f'cf_security_bootstrap={b"window.__CF$cv$params" in body and b"/cdn-cgi/challenge-platform/scripts/precursor/main.js" in body}')


class Verifier:
    def __init__(self, origin, sha, surface, artifact=None):
        self.origin, self.sha, self.surface, self.artifact = origin, sha, surface, artifact
        self.client = Client(origin)
        self.assets = {}

    def backend(self):
        response = self.client.get("/api/public/v1/transactions?limit=1", headers={"Accept": "application/json"})
        require(response.status == 200, "transactions API did not return 200")
        require(response.mime() == "application/json", "transactions API MIME mismatch")
        require("no-store" in cache_directives(response), "transactions API is not no-store")
        security(response)
        try:
            data = json.loads(response.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise VerificationError("invalid JSON from transactions API") from None
        require(isinstance(data, dict), "transactions API response must be a JSON object")
        require(isinstance(data.get("items"), list), "transactions API response missing items list")
        self.client.stream_events("/api/public/v1/events")

    def release(self):
        response = self.client.get("/__release?smoke=" + self.sha)
        require(response.status == 200 and response.mime() == "text/plain", "release status or MIME mismatch")
        require(response.body == (self.sha + "\n").encode("ascii"), "release identity mismatch")
        require("no-store" in cache_directives(response), "release identity is not no-store")
        security(response)
        if self.artifact:
            self.artifact.compare("/__release", response.body)

    def asset(self, path, kind):
        if path in self.assets:
            require(self.assets[path] == kind, "asset has conflicting HTML types")
            return
        response = self.client.get(path)
        require(response.status == 200, "entry asset did not return 200")
        require(response.mime() in (JS_MIMES if kind == "js" else {"text/css"}), "entry asset MIME mismatch")
        require(not response.body.lstrip().lower().startswith((b"<!doctype html", b"<html")), "entry asset is HTML")
        security(response)
        directives = cache_directives(response)
        if not self.artifact or self.artifact.immutable:
            require(directives.get("max-age") == "31536000" and "immutable" in directives and "public" in directives,
                    "entry asset lacks the exact immutable cache policy")
            require("s-maxage" not in directives or directives["s-maxage"] == "31536000", "conflicting shared asset cache lifetime")
        else:
            revalidating(response)
        if self.artifact:
            self.artifact.compare(path, response.body)
        etag = response.header("ETag")
        require(re.fullmatch(r'(?:W/)?"[^"\r\n]*"', etag) is not None, "entry asset lacks a valid ETag")
        conditional = self.client.get(path, {"If-None-Match": etag})
        require(conditional.status in {200, 304}, "conditional asset request did not return 200 or 304")
        require(conditional.header("ETag") == etag, "conditional asset ETag changed")
        conditional_cache = cache_directives(conditional)
        if conditional.status == 200 or conditional.header("Cache-Control"):
            require(conditional_cache == directives, "conditional asset cache policy changed")
        if conditional.status == 200:
            require(conditional.body == response.body and conditional.mime() == response.mime(), "conditional asset bytes or MIME changed")
            security(conditional)
        self.assets[path] = kind

    def page(self, path, credentials=False):
        response = self.client.get(path)
        require(response.status == 200 and response.mime() == "text/html", "SPA page status or MIME mismatch")
        revalidating(response)
        security(response, credentials)
        entries = local_entries(response.body, self.origin + path, self.origin)
        if self.artifact:
            self.artifact.compare("/index.html", response.body)
        for entry, kind in entries:
            self.asset(entry, kind)

    def missing(self):
        response = self.client.get("/assets/definitely-missing.js")
        require(response.status in {200, 404}, "missing asset must be 404 or an HTML SPA fallback")
        revalidating(response, require_policy=response.status == 200)
        require(response.header("X-Content-Type-Options").strip().lower() == "nosniff", "missing asset lacks nosniff")
        if response.status == 200:
            require(response.mime() == "text/html", "missing asset was accepted as JavaScript")
            security(response)
            local_entries(response.body, self.origin + "/assets/definitely-missing.js", self.origin)
            if self.artifact:
                self.artifact.compare("/index.html", response.body)

    def run(self):
        self.release()
        pages = ["/", "/t/smoke-record", "/index.html"]
        if self.surface == "local":
            pages.insert(1, "/admin/activity")
        for page in pages:
            self.page(page)
        if self.surface == "local":
            self.page("/admin/acb-credentials?test=1", credentials=True)
            self.page("/admin/acb-credentials/?test=1", credentials=True)
        self.missing()
        if self.surface == "viewer":
            self.backend()
        checksum = "decoded artifact checksums verified" if self.artifact else "NO artifact checksum comparison (rollback artifact unavailable)"
        cache = "; immutable rules omitted by artifact rule-limit fallback" if self.artifact and not self.artifact.immutable else ""
        if self.artifact and (self.artifact.edge_analytics_excluded or self.artifact.edge_security_excluded):
            excluded = []
            if self.artifact.edge_analytics_excluded:
                excluded.append("analytics")
            if self.artifact.edge_security_excluded:
                excluded.append("security bootstrap")
            checksum += f"; allowlisted edge {' and '.join(excluded)} excluded from HTML comparison"
        extra = "; API JSON and SSE heartbeat verified" if self.surface == "viewer" else ""
        return f"PASS {self.surface}: release {self.sha}; HTML, {len(self.assets)} JS/CSS entries, MIME, cache, security and ETag checks{extra}; {checksum}{cache}"


def check_access_redirect(client, path):
    response = client.get(path)
    require(response.status == 302, "bank Access must return exactly 302 without a session")
    location = response.header("Location")
    require(len(response.headers.get_all("Location", [])) == 1
            and not any(c.isspace() or ord(c) < 32 for c in location), "ambiguous Access redirect destination")
    try:
        parsed = urllib.parse.urlsplit(location)
        valid = (parsed.scheme == "https" and parsed.hostname == ACCESS_HOST
                 and parsed.port in {None, 443} and parsed.username is None
                 and parsed.password is None and not parsed.fragment
                 and parsed.path.startswith("/cdn-cgi/access/login/")
                 and len(parsed.path) > len("/cdn-cgi/access/login/"))
    except ValueError:
        valid = False
    require(valid, "bank Access redirect destination mismatch")


def verify_access(origin):
    client = Client(origin, follow=False)
    check_access_redirect(client, "/")
    check_access_redirect(client, "/api/v1/status")
    return "PASS access: unauthenticated bank 302 to the approved Access login; bank release SHA NOT verified"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True, help="HTTP(S) origin, without path or credentials")
    parser.add_argument("--sha", required=True, help="expected 40-character lowercase release commit")
    parser.add_argument("--mode", required=True, choices=("static", "access", "rollback"))
    parser.add_argument("--surface", choices=("local", "viewer"), help="required for static/rollback; viewer never probes admin static pages")
    parser.add_argument("--artifact", help="verified dist directory; required only for static")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40}", args.sha):
        parser.error("--sha must contain exactly 40 lowercase hex characters")
    if args.mode == "access":
        if args.surface or args.artifact:
            parser.error("access mode accepts neither --surface nor --artifact")
    elif not args.surface:
        parser.error("static and rollback modes require explicit --surface local|viewer")
    if args.mode == "static" and not args.artifact:
        parser.error("static mode requires --artifact for decoded byte/checksum comparison")
    if args.mode == "rollback" and args.artifact:
        parser.error("rollback mode cannot accept --artifact; use static mode when the artifact is available")
    try:
        origin = validate_origin(args.origin)
        if args.mode == "access":
            summary = verify_access(origin)
        else:
            artifact = Artifact(args.artifact) if args.artifact else None
            summary = Verifier(origin, args.sha, args.surface, artifact).run()
        print(summary)
        return 0
    except (VerificationError, OSError):
        error = sys.exc_info()[1]
        diagnostic = str(error) if isinstance(error, VerificationError) else "cannot read artifact files"
        print("FAIL frontend verification: " + diagnostic, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
