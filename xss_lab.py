#!/usr/bin/env python3
"""Minimal reflected XSS lab for local / Codespaces scanner testing.
Default bind: 127.0.0.1 — set XSS_LAB_HOST=0.0.0.0 only inside private Codespaces.
"""

import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

HOST = os.environ.get("XSS_LAB_HOST", "127.0.0.1")
PORT = int(os.environ.get("XSS_LAB_PORT", "8088"))


class XSSHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            body = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>XSS Lab</title></head>
<body>
  <h1>Local XSS Lab</h1>
  <p>Intentionally vulnerable — for your scanner only.</p>
  <ul>
    <li><a href="/search?q=test">/search?q=</a> (reflected XSS)</li>
    <li><a href="/echo?name=test">/echo?name=</a> (reflected XSS)</li>
  </ul>
  <form action="/search" method="GET">
    <input name="q" value="hello">
    <button type="submit">Search</button>
  </form>
</body></html>"""
            return self._html(200, body)

        if path == "/search":
            q = qs.get("q", [""])[0]
            body = (
                "<!DOCTYPE html><html><head><meta charset='utf-8'>"
                "<title>Search</title></head><body>"
                "<h1>Search result</h1>"
                "<p>You searched for: %s</p>"
                "<p><a href='/'>Home</a></p>"
                "</body></html>"
            ) % q
            return self._html(200, body)

        if path == "/echo":
            name = qs.get("name", [""])[0]
            body = (
                "<!DOCTYPE html><html><head><meta charset='utf-8'>"
                "<title>Echo</title></head><body>"
                "<div id='msg'>Hello, %s</div>"
                "</body></html>"
            ) % name
            return self._html(200, body)

        return self._html(404, "<h1>404</h1>")

    def _html(self, code, body):
        data = body.encode("utf-8", errors="replace")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)


def main():
    httpd = HTTPServer((HOST, PORT), XSSHandler)
    print("XSS lab: http://%s:%s/" % (HOST, PORT))
    print("Ctrl+C to stop.")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
