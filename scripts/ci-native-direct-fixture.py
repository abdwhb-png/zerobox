#!/usr/bin/env python3
"""Serve a public-address HTTP/TLS fixture for native mediated TCP tests."""

import argparse
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread


BODY = b"<html><body><h1>Example Domain</h1></body></html>\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, _format, *_args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--http-port", type=int, default=80)
    parser.add_argument("--https-port", type=int, default=443)
    args = parser.parse_args()

    http = ThreadingHTTPServer((args.address, args.http_port), Handler)
    https = ThreadingHTTPServer((args.address, args.https_port), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(args.cert, args.key)
    https.socket = tls.wrap_socket(https.socket, server_side=True)

    Thread(target=http.serve_forever, daemon=True).start()
    https.serve_forever()


if __name__ == "__main__":
    main()
