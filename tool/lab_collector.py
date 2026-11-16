"""Private, loopback-only metadata receiver for explicit lab fixtures.

Both operations require a bearer secret. This is not a public OAST service.
Run behind an access-controlled private TLS reverse proxy if needed.
"""
import collections
import datetime
import hmac
import http.server
import json
import os
import re
import ssl
import time

TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{32,128}")
LABEL_PATTERN = re.compile(r"[a-f0-9]{32}")
MAX_EVENTS = 200
TTL_SECONDS = 3600


def create_tls_context(environ):
    """Optional direct TLS on the private fixture endpoint, never a proxy."""
    cert = environ.get("ODIN_LAB_TLS_CERT", "")
    key = environ.get("ODIN_LAB_TLS_KEY", "")
    if not cert and not key:
        return None
    if not cert or not key:
        raise ValueError("Both ODIN_LAB_TLS_CERT and ODIN_LAB_TLS_KEY are required.")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert, keyfile=key)
    return context


class Collector(http.server.HTTPServer):
    def __init__(self, token, port=8765, tls_context=None):
        if not TOKEN_PATTERN.fullmatch(token):
            raise ValueError("Set ODIN_LAB_TOKEN to a 32–128 character URL-safe secret.")
        self.token = "Bearer " + token
        self.tls_context = tls_context
        self.events = collections.deque(maxlen=MAX_EVENTS)
        super().__init__(("127.0.0.1", port), Handler)

    def get_request(self):
        sock, address = super().get_request()
        if self.tls_context is None:
            return sock, address
        try:
            sock.settimeout(5)
            return self.tls_context.wrap_socket(sock, server_side=True), address
        except OSError:
            sock.close()
            raise
        except ValueError as error:
            sock.close()
            raise OSError('TLS connection rejected.') from error

    def prune(self):
        cutoff = time.monotonic() - TTL_SECONDS
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_args):
        pass

    def reply(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.close_connection = True

    def authorized(self):
        if self.path != "/events":
            self.reply(404)
            return False
        auth = self.headers.get_all("Authorization", [])
        if len(auth) != 1 or not hmac.compare_digest(
            auth[0].encode("utf-8"), self.server.token.encode("ascii")
        ):
            self.reply(401)
            return False
        if self.headers.get("Transfer-Encoding") is not None:
            self.reply(400)
            return False
        return True

    def do_GET(self):
        if not self.authorized():
            return
        if self.headers.get_all("Content-Length", []) not in ([], ["0"]):
            self.reply(400)
            return
        self.server.prune()
        self.reply(200, json.dumps([event for _, event in self.server.events],
                                   separators=(",", ":")).encode("utf-8"))

    def do_POST(self):
        if not self.authorized():
            return
        length = self.headers.get_all("Content-Length", [])
        if len(length) != 1 or not re.fullmatch(r"[0-9]{1,3}", length[0]):
            self.reply(400)
            return
        size = int(length[0])
        if not 0 < size <= 512 or self.headers.get_content_type() != "application/json":
            self.reply(400)
            return
        try:
            body = self.rfile.read(size)
            if len(body) != size:
                raise ValueError()
            event = json.loads(body)
            if (not isinstance(event, dict) or set(event) != {"label", "protocol"}
                    or not isinstance(event["label"], str)
                    or not LABEL_PATTERN.fullmatch(event["label"])
                    or event["protocol"] not in ("http", "https")
                    or (self.server.tls_context is not None and event["protocol"] != "https")):
                raise ValueError()
        except (ValueError, UnicodeError, TimeoutError, RecursionError):
            self.reply(400)
            return
        self.server.prune()
        event["observedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.server.events.append((time.monotonic(), event))
        self.reply(204)


def main():
    token = os.environ.get("ODIN_LAB_TOKEN", "")
    context = create_tls_context(os.environ)
    with Collector(token, tls_context=context) as server:
        scheme = "https" if context is not None else "http"
        print("Private fixture receiver: " + scheme + "://127.0.0.1:8765/events")
        server.serve_forever()


if __name__ == "__main__":
    main()
