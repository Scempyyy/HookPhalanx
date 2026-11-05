"""Embedded HTTP server for HookPhalanx phishing sandbox dashboard."""

import http.server
import json
import os
import socketserver
import urllib.parse
from .analyzer import PhishingAnalyzer

STATIC_DIR = os.path.join(os.path.dirname(__file__), "web")


class HookPhalanxHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler serving API endpoints and sandbox UI."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "active", "service": "HookPhalanx"}).encode("utf-8"))
            return
        elif parsed.path == "/api/scan":
            query = urllib.parse.parse_qs(parsed.query)
            target = query.get("url", [""])[0]
            if not target:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing 'url' query parameter"}).encode("utf-8"))
                return
            
            analyzer = PhishingAnalyzer(allow_private=False)
            result = analyzer.analyze(target, fetch_body=True)
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode("utf-8"))
            return

        return super().do_GET()

    def do_POST(self):
        if self.path == "/api/scan":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            try:
                data = json.loads(post_body)
                target = data.get("url", "")
                analyzer = PhishingAnalyzer(allow_private=False)
                result = analyzer.analyze(target, fetch_body=True)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(result).encode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass


def run_server(port: int = 7088, host: str = "127.0.0.1"):
    """Starts the HookPhalanx web console."""
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((host, port), HookPhalanxHandler) as httpd:
        print(f"[*] HookPhalanx Sandbox running at http://{host}:{port}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Stopping HookPhalanx server.")
