#!/usr/bin/env python3
"""
Intentionally vulnerable lab: reflected XSS, stored XSS, SSRF.
Open endpoints for scanners that cannot send custom tokens.

WARNING: If exposed to the public internet, anyone can abuse SSRF/XSS.
Use a short-lived Codespace / lock security group when possible.
"""

import html
import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

HOST = os.environ.get("XSS_LAB_HOST", "127.0.0.1")
PORT = int(os.environ.get("XSS_LAB_PORT", "8088"))

# In-memory stored XSS board (resets when process restarts)
COMMENTS = []


class LabHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            body = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>XSS/SSRF Lab</title></head>
<body>
<h1>Scanner Lab (XSS / Stored XSS / SSRF)</h1>
<p>Open for scanner testing — no access token.</p>
<ul>
  <li><a href="/search?q=test">GET /search?q=</a> — reflected XSS</li>
  <li><a href="/board">GET /board</a> — stored XSS board</li>
  <li><a href="/ssrf?url=https://example.com">GET /ssrf?url=</a> — SSRF fetch</li>
  <li><a href="/health">GET /health</a> — health check</li>
</ul>
<h2>Post comment (stored XSS)</h2>
<form method="POST" action="/board">
  <input name="comment" size="60" value="hello">
  <button type="submit">Submit</button>
</form>
</body></html>"""
            return self._html(200, body)

        if path == "/health":
            return self._json(200, {"ok": True})

        if path == "/search":
            # Reflected XSS — no encoding
            q = qs.get("q", [""])[0]
            body = (
                "<!DOCTYPE html><html><body>"
                "<h1>Search</h1><p>You searched for: %s</p>"
                "<p><a href='/'>Home</a></p></body></html>"
            ) % q
            return self._html(200, body)

        if path == "/board":
            # Stored XSS — comments rendered raw
            items = "".join("<li>%s</li>" % c for c in COMMENTS)
            body = (
                "<!DOCTYPE html><html><body>"
                "<h1>Message Board (stored XSS)</h1>"
                "<ul>%s</ul>"
                "<p><a href='/'>Home</a></p>"
                "</body></html>"
            ) % items
            return self._html(200, body)

        if path == "/ssrf":
            # SSRF — server fetches attacker-controlled URL
            url = qs.get("url", [""])[0]
            if not url:
                return self._html(400, "<h1>400</h1><p>need url=</p>")
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "xss-lab-ssrf/1.0"},
                    method="GET",
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = resp.read(4096)
                    status = resp.getcode()
                    ctype = resp.headers.get("Content-Type", "")
                preview = data.decode("utf-8", errors="replace")
                body = (
                    "<!DOCTYPE html><html><body>"
                    "<h1>SSRF result</h1>"
                    "<p>URL: %s</p>"
                    "<p>Status: %s</p>"
                    "<p>Content-Type: %s</p>"
                    "<pre>%s</pre>"
                    "</body></html>"
                ) % (html.escape(url), status, html.escape(ctype), html.escape(preview))
                return self._html(200, body)
            except Exception as e:
                return self._html(
                    502,
                    "<h1>SSRF fetch failed</h1><pre>%s</pre>" % html.escape(str(e)),
                )

        return self._html(404, "<h1>404</h1>")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        form = parse_qs(raw.decode("utf-8", errors="replace"))

        if path == "/board":
            comment = form.get("comment", [""])[0]
            if comment:
                COMMENTS.append(comment)
                if len(COMMENTS) > 100:
                    COMMENTS.pop(0)
            self.send_response(302)
            self.send_header("Location", "/board")
            self.end_headers()
            return

        return self._html(404, "<h1>404</h1>")

    def _html(self, code, body):
        data = body.encode("utf-8", errors="replace")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    httpd = HTTPServer((HOST, PORT), LabHandler)
    print("Lab http://%s:%s/  (no token)" % (HOST, PORT))
    httpd.serve_forever()


if __name__ == "__main__":
    main()
