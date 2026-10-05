"""HTTP behavior checks for the cookie-free static/Access smoke CLI."""
import contextlib
import gzip
import importlib.util
import io
import email
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("verify_frontend", Path(__file__).parents[1] / "verify-frontend.py")
verify = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verify
spec.loader.exec_module(verify)

SHA = "a" * 40
HTML = (b'<!doctype html><html><body><div id="root"></div>'
        b'<script type="module" src="/assets/index-abcdefgh.js"></script>'
        b'<link rel="stylesheet" href="/assets/index-abcdefgh.css">'
        b'<link rel="modulepreload" href="/assets/vendor-abcdefgh.js">'
        b'</body></html>')
FILES = {"/index.html": HTML, "/__release": (SHA + "\n").encode(),
         "/assets/index-abcdefgh.js": b'console.log("synthetic entry");',
         "/assets/vendor-abcdefgh.js": b'export const fixture = true;',
         "/assets/index-abcdefgh.css": b'body { color: black; }'}
BEACON = (b'<script defer type="module" src="https://static.cloudflareinsights.com/beacon.min.js/v' + b'a' * 32 +
          b'" integrity="sha512-YWJj" data-cf-beacon=\'{"token":"synthetic"}\' crossorigin="anonymous"></script>')
BOOTSTRAP = (b"<script>window.__CF$cv$params={r:'a4566af14c049fe9',t:'MTc5MTE0MDMwMw==',u:'01a1084812f171899f34caceedc09acf',"
             b"ut:'xUDmNdF__f6h4P8acb8d299M9itzGqM.xLB5XPtqou4-1791140303-1.2.1.1',i:60};"
             b"(function(){if(!document.body)return;var s=document.createElement('script');"
             b"s.src='/cdn-cgi/challenge-platform/scripts/precursor/main.js';document.head.appendChild(s);})();</script>")


class FrontendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.artifact = Path(self.temp.name)
        for path, body in FILES.items():
            target = self.artifact / path.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        self.requests = []
        self.mutate = lambda path, status, headers, body: (status, headers, body)
        self.conditional_200 = False
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                owner.requests.append((self.path, dict(self.headers)))
                path = urllib.parse.urlsplit(self.path).path
                credentials = path in {"/admin/acb-credentials", "/admin/acb-credentials/"}
                headers = {
                    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer" if credentials else "strict-origin-when-cross-origin",
                    "Content-Security-Policy": verify.CREDENTIALS_CSP if credentials else verify.GLOBAL_CSP,
                    "Cache-Control": "public, max-age=0, must-revalidate",
                    "Set-Cookie": "synthetic=never-forward; Path=/",
                }
                status = 200
                if path == "/__release":
                    body = FILES[path]
                    headers.update({"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store"})
                elif path in FILES and path.startswith("/assets/"):
                    body = FILES[path]
                    headers.update({"Content-Type": "text/css" if path.endswith(".css") else "application/javascript",
                                    "Cache-Control": "public, max-age=31536000, immutable", "ETag": '"fixture"'})
                    if self.headers.get("If-None-Match") and not owner.conditional_200:
                        status, body = 304, b""
                elif path == "/api/public/v1/transactions":
                    body = b'{"items":[],"summary":{}}'
                    headers.update({"Content-Type": "application/json", "Cache-Control": "no-store"})
                elif path == "/api/public/v1/events":
                    body = b'event: initial_state\ndata: {"epoch":"ep1","watermark":0}\n\nevent: stream.heartbeat\ndata: {"slot":"green"}\n\n'
                    headers.update({"Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-transform"})
                else:
                    body = HTML
                    headers["Content-Type"] = "text/html; charset=utf-8"
                    if credentials:
                        headers["Cache-Control"] = "no-store"
                status, headers, body = owner.mutate(self.path, status, headers, body)
                self.send_response(status)
                for key, value in headers.items():
                    for item in value if isinstance(value, list) else [value]:
                        self.send_header(key, item)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def run_static(self, surface="local"):
        return verify.Verifier(self.origin, SHA, surface, verify.Artifact(self.artifact)).run()

    def fail_mutation(self, mutation, diagnostic, surface="local"):
        self.mutate = mutation
        with self.assertRaisesRegex(verify.VerificationError, diagnostic):
            self.run_static(surface)

    def test_static_local_checks_all_entries_and_credentials_without_cookies(self):
        self.assertIn("checksums verified", self.run_static())
        paths = [path for path, _ in self.requests]
        self.assertIn("/admin/activity", paths)
        self.assertIn("/admin/acb-credentials?test=1", paths)
        self.assertIn("/admin/acb-credentials/?test=1", paths)
        self.assertIn("/assets/vendor-abcdefgh.js", paths)
        self.assertTrue(any("If-None-Match" in headers for _, headers in self.requests))
        self.assertFalse(any("Cookie" in headers or "Authorization" in headers for _, headers in self.requests))

    def test_viewer_never_probes_admin(self):
        self.run_static("viewer")
        self.assertFalse(any(path.startswith("/admin") for path, _ in self.requests))

    def test_timestamped_beacon_does_not_hide_application_tampering(self):
        beacon = BEACON.replace(b'a' * 32 + b'"', b'a' * 32 + b'1788362987495"')
        def inject(path, status, headers, body):
            if headers.get("Content-Type", "").startswith("text/html"):
                body = body.replace(b"</body>", beacon + b"</body>")
            return status, headers, body
        self.mutate = inject

    def test_edge_security_bootstrap_and_beacon_excluded_without_hiding_tampering(self):
        def inject(path, status, headers, body):
            if headers.get("Content-Type", "").startswith("text/html"):
                body = body.replace(b"</body>", BEACON + b"\n" + BOOTSTRAP + b"</body>")
            return status, headers, body
        self.mutate = inject
        self.assertIn("edge analytics and security bootstrap excluded from HTML comparison", self.run_static("viewer"))
        def tamper(path, status, headers, body):
            status, headers, body = inject(path, status, headers, body)
            if path == "/":
                body = body.replace(b'id="root"', b'id="root" data-tampered="true"')
            return status, headers, body
        self.mutate = tamper
        self.fail_mutation(tamper, "checksum does not match")

    def test_foreign_or_duplicate_security_bootstrap_is_not_excluded(self):
        variants = [BOOTSTRAP.replace(b"/cdn-cgi/challenge-platform/scripts/precursor/main.js", b"https://evil.invalid/main.js"),
                    BOOTSTRAP.replace(b"i:60", b"i:60; eval('alert(1)')"),
                    BOOTSTRAP + BOOTSTRAP]
        for bootstrap in variants:
            with self.subTest(bootstrap=bootstrap):
                def mutation(path, status, headers, body):
                    if path == "/":
                        body = body.replace(b"</body>", bootstrap + b"</body>")
                    return status, headers, body
                self.fail_mutation(mutation, "checksum does not match")
    def test_beacon_cannot_hide_changed_application_html_or_script_bytes(self):
        for target in ("/", "/assets/index-abcdefgh.js"):
            with self.subTest(target=target):
                def mutation(path, status, headers, body):
                    if path == target:
                        body = body.replace(b"</body>", BEACON + b"</body>") + b"tampered"
                    return status, headers, body
                self.fail_mutation(mutation, "checksum does not match")

    def test_foreign_active_duplicate_or_nonempty_beacon_is_not_excluded(self):
        variants = [BEACON.replace(b"static.cloudflareinsights.com", b"other.example"),
                    BEACON.replace(b" defer", b' onload="alert(1)" defer'),
                    BEACON.replace(b"</script>", b"alert(1)</script>"),
                    BEACON + BEACON]
        for beacon in variants:
            with self.subTest(beacon=beacon):
                def mutation(path, status, headers, body):
                    if path == "/":
                        body = body.replace(b"</body>", beacon + b"</body>")
                    return status, headers, body
                self.fail_mutation(mutation, "checksum does not match|same-origin")

    def test_rollback_explicitly_does_not_attest_checksums(self):
        summary = verify.Verifier(self.origin, SHA, "viewer").run()
        self.assertIn("NO artifact checksum comparison", summary)

    def test_conditional_200_same_bytes_and_etag_is_allowed(self):
        self.conditional_200 = True
        self.run_static()

    def test_changed_conditional_etag_fails(self):
        count = {}
        def mutation(path, status, headers, body):
            count[path] = count.get(path, 0) + 1
            if path.endswith(".js") and count[path] == 2:
                headers["ETag"] = '"changed"'
            return status, headers, body
        self.fail_mutation(mutation, "ETag changed")

    def test_missing_asset_404_allowed_with_nosniff(self):
        def mutation(path, status, headers, body):
            return (404, headers, b"synthetic not found") if path == "/assets/definitely-missing.js" else (status, headers, body)
        self.mutate = mutation
        self.run_static()

    def test_missing_asset_cannot_be_immutable_or_javascript(self):
        for replacement, diagnostic in [("Cache-Control", "non-asset response is immutable"), ("Content-Type", "accepted as JavaScript")]:
            with self.subTest(replacement=replacement):
                def mutation(path, status, headers, body):
                    if path == "/assets/definitely-missing.js":
                        headers[replacement] = "public, max-age=31536000, immutable" if replacement == "Cache-Control" else "application/javascript"
                    return status, headers, body
                self.fail_mutation(mutation, diagnostic)

    def test_release_challenge_or_wrong_sha_fails(self):
        for mime, body, diagnostic in [("text/html", HTML, "MIME mismatch"), ("text/plain", b"b" * 40 + b"\n", "identity mismatch")]:
            with self.subTest(mime=mime):
                def mutation(path, status, headers, original):
                    if path.startswith("/__release"):
                        headers["Content-Type"] = mime
                        return status, headers, body
                    return status, headers, original
                self.fail_mutation(mutation, diagnostic)

    def test_html_requires_root_and_local_module(self):
        for replacement in [b'<html><div id="root"></div></html>', b'<html><script type="module" src="/assets/index-abcdefgh.js"></script></html>']:
            with self.subTest(html=replacement):
                def mutation(path, status, headers, body):
                    return status, headers, replacement if path == "/" else body
                self.fail_mutation(mutation, "root mount|local module")

    def test_asset_checksum_and_mime_are_authoritative(self):
        for key, diagnostic in [("bytes", "checksum"), ("mime", "MIME mismatch")]:
            with self.subTest(key=key):
                def mutation(path, status, headers, body):
                    if path == "/assets/index-abcdefgh.js":
                        if key == "bytes":
                            body += b"// mismatch"
                        else:
                            headers["Content-Type"] = "text/html"
                    return status, headers, body
                self.fail_mutation(mutation, diagnostic)

    def test_decoded_gzip_compares_to_artifact(self):
        def mutation(path, status, headers, body):
            if status == 200:
                headers["Content-Encoding"] = "gzip"
                body = gzip.compress(body)
            return status, headers, body
        self.mutate = mutation
        self.run_static()

    def test_strict_csp_intersection_fallback_allowed(self):
        def mutation(path, status, headers, body):
            headers["Referrer-Policy"] = "no-referrer"
            if path.startswith("/admin/acb-credentials"):
                headers["Content-Security-Policy"] = [verify.GLOBAL_CSP, verify.CREDENTIALS_CSP]
            return status, headers, body
        self.mutate = mutation
        self.run_static()

    def test_credentials_cannot_keep_only_global_policy_or_join_referrers(self):
        for key, value, diagnostic in [("Content-Security-Policy", verify.GLOBAL_CSP, "credentials CSP"),
                                       ("Referrer-Policy", "strict-origin-when-cross-origin, no-referrer", "referrer")]:
            with self.subTest(key=key):
                def mutation(path, status, headers, body):
                    if path.startswith("/admin/acb-credentials"):
                        headers[key] = value
                    return status, headers, body
                self.fail_mutation(mutation, diagnostic)

    def test_conflicting_cache_rules_fail(self):
        for policy in ["no-store, public, max-age=0", "public, max-age=31536000, max-age=0, immutable",
                       "public, max-age=31536000, immutable, must-revalidate"]:
            with self.subTest(policy=policy):
                def mutation(path, status, headers, body):
                    if path.endswith(".js"):
                        headers["Cache-Control"] = policy
                    return status, headers, body
                self.fail_mutation(mutation, "conflicting|duplicate")

    def test_same_origin_redirect_does_not_forward_set_cookie(self):
        def mutation(path, status, headers, body):
            if path == "/":
                headers["Location"] = "/index.html"
                return 302, headers, b"synthetic private redirect body"
            return status, headers, body
        self.mutate = mutation
        self.run_static()
        self.assertFalse(any("Cookie" in headers for _, headers in self.requests))

    def test_external_redirect_rejected_without_following(self):
        def mutation(path, status, headers, body):
            headers["Location"] = "https://example.invalid/private"
            return 302, headers, b"synthetic sensitive body"
        self.fail_mutation(mutation, "cross-origin")
        self.assertEqual(len(self.requests), 1)

    def test_access_checks_exact_redirect_and_no_sha_attestation(self):
        def mutation(path, status, headers, body):
            headers["Location"] = "https://thedemontuan.cloudflareaccess.com/cdn-cgi/access/login/fixture?opaque=value"
            return 302, headers, b"synthetic sensitive body"
        self.mutate = mutation
        self.assertIn("SHA NOT verified", verify.verify_access(self.origin))
        self.assertEqual(len(self.requests), 2)

    def test_access_rejects_challenge_wrong_status_or_destination(self):
        for status, location in [(200, "https://thedemontuan.cloudflareaccess.com/cdn-cgi/access/login/fixture"),
                                 (303, "https://thedemontuan.cloudflareaccess.com/cdn-cgi/access/login/fixture"),
                                 (302, "https://evil.invalid/cdn-cgi/access/login/fixture"),
                                 (302, "https://thedemontuan.cloudflareaccess.com/not-login")]:
            with self.subTest(status=status, location=location):
                def mutation(path, original_status, headers, body):
                    headers["Location"] = location
                    return status, headers, body
                self.mutate = mutation
                with self.assertRaises(verify.VerificationError):
                    verify.verify_access(self.origin)

    def test_cli_does_not_log_sensitive_response(self):
        def mutation(path, status, headers, body):
            return 403, headers, b"DO-NOT-LOG-ACCOUNT-FIXTURE"
        self.mutate = mutation
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = verify.main(["--origin", self.origin, "--sha", SHA, "--mode", "static", "--surface", "viewer", "--artifact", str(self.artifact)])
        self.assertEqual(code, 1)
        self.assertNotIn("DO-NOT-LOG", stdout.getvalue() + stderr.getvalue())

    def test_cli_requires_explicit_surface_and_artifact(self):
        invalid = [["--mode", "static"], ["--mode", "static", "--surface", "viewer"],
                   ["--mode", "rollback"], ["--mode", "rollback", "--surface", "viewer", "--artifact", str(self.artifact)],
                   ["--mode", "access", "--surface", "viewer"], ["--mode", "access", "--artifact", str(self.artifact)]]
        for args in invalid:
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                verify.main(["--origin", self.origin, "--sha", SHA, *args])

    def test_rule_budget_fallback_revalidates_all_assets(self):
        for number in range(97):
            (self.artifact / "assets" / f"extra{number}-abcdefgh.js").write_bytes(b"export {};")
        (self.artifact / "_headers").write_text("/*\n  X-Frame-Options: DENY\n/__release\n  Cache-Control: no-store\n/admin/acb-credentials\n  Cache-Control: no-store\n/admin/acb-credentials/\n  Cache-Control: no-store\n")
        def mutation(path, status, headers, body):
            if path.startswith("/assets/"):
                headers["Cache-Control"] = "public, max-age=0, must-revalidate"
            return status, headers, body
        self.mutate = mutation
        self.assertIn("rule-limit fallback", self.run_static())

    def test_missing_artifact_entry_fails(self):
        (self.artifact / "assets/index-abcdefgh.js").unlink()
        with self.assertRaisesRegex(verify.VerificationError, "missing or oversized"):
            self.run_static()

    def test_artifact_traversal_rejected(self):
        artifact = verify.Artifact(self.artifact)
        for path in ["/../private.js", "/assets/%2e%2e/private.js", "/assets/%5cprivate.js"]:
            with self.subTest(path=path), self.assertRaisesRegex(verify.VerificationError, "unsafe artifact"):
                artifact.bytes_for(path)

    def test_viewer_probes_api_and_sse_heartbeat(self):
        summary = self.run_static("viewer")
        self.assertIn("API JSON and SSE heartbeat verified", summary)
        paths = [urllib.parse.urlsplit(path).path for path, _ in self.requests]
        self.assertIn("/api/public/v1/transactions", paths)
        self.assertIn("/api/public/v1/events", paths)

    def test_local_never_probes_backend(self):
        self.run_static("local")
        paths = [urllib.parse.urlsplit(path).path for path, _ in self.requests]
        self.assertFalse(any(p.startswith("/api/") for p in paths))

    def test_api_swallowed_by_spa_fails(self):
        def mutation(path, status, headers, body):
            if urllib.parse.urlsplit(path).path == "/api/public/v1/transactions":
                headers = {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=0, must-revalidate"}
                return 200, headers, HTML
            return status, headers, body
        self.fail_mutation(mutation, "MIME mismatch", surface="viewer")

    def test_api_malformed_json_or_wrong_shape_fails(self):
        for bad_body, err in [(b"not-json", "invalid JSON"), (b'{"items":"not-list"}', "items list"), (b'[]', "JSON object")]:
            with self.subTest(bad_body=bad_body):
                def mutation(path, status, headers, body):
                    if urllib.parse.urlsplit(path).path == "/api/public/v1/transactions":
                        headers["Content-Type"] = "application/json"
                        headers["Cache-Control"] = "no-store"
                        return 200, headers, bad_body
                    return status, headers, body
                self.fail_mutation(mutation, err, surface="viewer")

    def test_api_empty_items_is_valid(self):
        def mutation(path, status, headers, body):
            if urllib.parse.urlsplit(path).path == "/api/public/v1/transactions":
                headers["Content-Type"] = "application/json"
                headers["Cache-Control"] = "no-store"
                return 200, headers, b'{"items":[],"summary":{}}'
            return status, headers, body
        self.mutate = mutation
        self.assertIn("API JSON and SSE heartbeat verified", self.run_static("viewer"))

    def test_sse_wrong_mime_fails(self):
        def mutation(path, status, headers, body):
            if urllib.parse.urlsplit(path).path == "/api/public/v1/events":
                headers = {"Content-Type": "text/plain", "Cache-Control": "no-cache, no-transform"}
                return 200, headers, b"data: test\n\n"
            return status, headers, body
        self.fail_mutation(mutation, "event stream MIME mismatch", surface="viewer")

    def test_sse_missing_heartbeat_or_eof_fails(self):
        def mutation(path, status, headers, body):
            if urllib.parse.urlsplit(path).path == "/api/public/v1/events":
                headers = {"Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-transform"}
                return 200, headers, b'event: initial_state\ndata: {"epoch":"ep1","watermark":0}\n\n'
            return status, headers, body
        self.fail_mutation(mutation, "stream closed prematurely", surface="viewer")

    def test_sse_malformed_target_frame_fails(self):
        def mutation(path, status, headers, body):
            if urllib.parse.urlsplit(path).path == "/api/public/v1/events":
                headers = {"Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-transform"}
                return 200, headers, b'event: initial_state\ndata: {"epoch":"ep1"}\n\nevent: stream.heartbeat\ndata: not-json\n\n'
            return status, headers, body
        self.fail_mutation(mutation, "malformed stream.heartbeat payload", surface="viewer")

    def test_sse_deadline_bounded(self):
        def delayed(path, status, headers, body):
            if urllib.parse.urlsplit(path).path == "/api/public/v1/events":
                time.sleep(0.1)
                return status, headers, body
            return status, headers, body
        self.mutate = delayed
        client = verify.Client(self.origin)
        with patch.object(verify, "TIMEOUT", 0.03):
            with self.assertRaisesRegex(verify.VerificationError, "exceeded"):
                client.stream_events("/api/public/v1/events")

    def test_access_rejects_when_api_status_fails(self):
        def mutation(path, status, headers, body):
            p = urllib.parse.urlsplit(path).path
            if p == "/":
                headers["Location"] = "https://thedemontuan.cloudflareaccess.com/cdn-cgi/access/login/fixture?opaque=value"
                return 302, headers, b""
            elif p == "/api/v1/status":
                return 200, {"Content-Type": "application/json"}, b"{}"
            return status, headers, body
        self.mutate = mutation
        with self.assertRaisesRegex(verify.VerificationError, "302"):
            verify.verify_access(self.origin)

    @contextlib.contextmanager
    def https_server(self, handler_fn):
        with tempfile.TemporaryDirectory() as d:
            key = os.path.join(d, "k.pem")
            crt = os.path.join(d, "c.pem")
            subprocess.check_call(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                                   "-keyout", key, "-out", crt, "-days", "1",
                                   "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
                                  stderr=subprocess.DEVNULL)
            old_cert = os.environ.get("SSL_CERT_FILE")
            os.environ["SSL_CERT_FILE"] = crt

            class SSLHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    handler_fn(self)
                def log_message(self, *args):
                    pass

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(crt, key)
            server = ThreadingHTTPServer(("127.0.0.1", 0), SSLHandler)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            try:
                yield f"https://127.0.0.1:{server.server_port}"
            finally:
                if old_cert:
                    os.environ["SSL_CERT_FILE"] = old_cert
                else:
                    os.environ.pop("SSL_CERT_FILE", None)
                server.shutdown()
                server.server_close()
                t.join()

    def test_curl_fallback_preserves_crlf_in_body(self):
        body_content = b"<html>\r\n\r\n<body>preserved\r\n\r\nnewlines</body></html>"
        def cb(handler):
            handler.send_response(200)
            handler.send_header("Content-Type", "text/html")
            handler.send_header("Content-Length", str(len(body_content)))
            handler.end_headers()
            handler.wfile.write(body_content)
        with self.https_server(cb) as origin:
            client = verify.Client(origin)
            client.opener.open = lambda req, timeout=None: (_ for _ in ()).throw(
                urllib.error.HTTPError(req.full_url, 403, "Forbidden", email.message_from_string("Server: cloudflare\r\n"), io.BytesIO(b"waf")))
            res = client.get("/index.html")
            self.assertEqual(res.body, body_content)

    def test_curl_fallback_oversized_body_rejected(self):
        body_content = b"x" * 200
        def cb(handler):
            handler.send_response(200)
            handler.send_header("Content-Type", "text/plain")
            handler.send_header("Content-Length", str(len(body_content)))
            handler.end_headers()
            handler.wfile.write(body_content)
        with self.https_server(cb) as origin:
            client = verify.Client(origin)
            client.opener.open = lambda req, timeout=None: (_ for _ in ()).throw(
                urllib.error.HTTPError(req.full_url, 403, "Forbidden", email.message_from_string("Server: cloudflare\r\n"), io.BytesIO(b"waf")))
            with patch.object(verify, "MAX_BODY", 50):
                with self.assertRaisesRegex(verify.VerificationError, "failed|exceeds"):
                    client.get("/test")

    def test_curl_fallback_gzip_decompressed(self):
        raw = b"raw\r\n\r\ngzip-content"
        compressed = gzip.compress(raw)
        def cb(handler):
            handler.send_response(200)
            handler.send_header("Content-Type", "text/html")
            handler.send_header("Content-Encoding", "gzip")
            handler.send_header("Content-Length", str(len(compressed)))
            handler.end_headers()
            handler.wfile.write(compressed)
        with self.https_server(cb) as origin:
            client = verify.Client(origin)
            client.opener.open = lambda req, timeout=None: (_ for _ in ()).throw(
                urllib.error.HTTPError(req.full_url, 403, "Forbidden", email.message_from_string("Server: cloudflare\r\n"), io.BytesIO(b"waf")))
            res = client.get("/test")
            self.assertEqual(res.body, raw)

    def test_curl_fallback_403_twice_fails_safely_no_body_leaked(self):
        def cb(handler):
            handler.send_response(403)
            handler.send_header("Content-Type", "text/html")
            body = b"SENSITIVE_SECOND_403_BODY"
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)
        with self.https_server(cb) as origin:
            client = verify.Client(origin)
            client.opener.open = lambda req, timeout=None: (_ for _ in ()).throw(
                urllib.error.HTTPError(req.full_url, 403, "Forbidden", email.message_from_string("Server: cloudflare\r\n"), io.BytesIO(b"waf")))
            with self.assertRaises(verify.VerificationError) as caught:
                client.get("/test")
            self.assertNotIn("SENSITIVE", str(caught.exception))

    def test_curl_fallback_nonzero_fails_safely(self):
        client = verify.Client("https://127.0.0.1:1")
        client.opener.open = lambda req, timeout=None: (_ for _ in ()).throw(
            urllib.error.HTTPError(req.full_url, 403, "Forbidden", email.message_from_string("Server: cloudflare\r\n"), io.BytesIO(b"waf")))
        with self.assertRaisesRegex(verify.VerificationError, "failed"):
            client.get("/test")
if __name__ == "__main__":
    unittest.main()
