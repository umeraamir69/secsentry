"""Serve the dashboard on loopback only.

Binds 127.0.0.1 by design — a scan report is a map of where your credentials
leaked, so it must never be reachable from the network. ADR-006.
"""

from __future__ import annotations

import json
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from secsentry.reports.html import render

HOST = "127.0.0.1"


def _handler(payload: dict):
    body = render(payload).encode("utf-8")
    raw = json.dumps(payload, indent=2).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def _send(self, content: bytes, content_type: str) -> None:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(content)

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            if self.path.startswith("/report.json"):
                self._send(raw, "application/json; charset=utf-8")
            elif self.path in ("/", "/index.html"):
                self._send(body, "text/html; charset=utf-8")
            else:
                self.send_error(404)

        def log_message(self, *args) -> None:
            pass

    return Handler


def serve(payload: dict, port: int = 8765, open_browser: bool = True) -> None:
    server = ThreadingHTTPServer((HOST, port), _handler(payload))
    url = f"http://{HOST}:{server.server_port}"
    print(f"SecSentry dashboard  {url}")
    print("Loopback only. Secrets are masked. Ctrl-C to stop.")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
