#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
"""Small, dependency-free network fixtures for the workload image proof."""

import argparse
import http.server
import signal
import socket
import struct
import time


class FixtureHTTP(http.server.BaseHTTPRequestHandler):
    server_version = "workload-debug-fixture/1"

    def log_message(self, _format, *_args):
        return

    def _send(self, status, body=b"", headers=None):
        self.send_response(status)
        for name, value in headers or []:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/get":
            self._send(200, b"fixture-get\n", [("Content-Type", "text/plain")])
        elif self.path == "/redirect":
            self._send(302, b"redirect\n", [("Location", "/get")])
        elif self.path == "/large":
            self._send(200, b"x" * 4096)
        elif self.path == "/slow":
            time.sleep(self.server.slow_seconds)
            self._send(200, b"fixture-slow\n")
        else:
            self._send(404, b"not-found\n")

    def do_HEAD(self):  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/head":
            self._send(200, b"fixture-head\n", [("X-Fixture", "head")])
        else:
            self._send(404, b"not-found\n")

    def do_OPTIONS(self):  # noqa: N802 - BaseHTTPRequestHandler API
        self._send(204, b"", [("Allow", "GET, HEAD, OPTIONS")])


class FixtureHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, slow_seconds):
        super().__init__(address, FixtureHTTP)
        self.slow_seconds = slow_seconds


def dns_response(packet, expected_name, address):
    if len(packet) < 12:
        return b""
    transaction_id = packet[:2]
    question_end = packet.find(b"\x00", 12)
    if question_end < 0 or question_end + 5 > len(packet):
        return b""
    question = packet[12 : question_end + 5]
    labels = []
    cursor = 12
    while cursor < question_end:
        length = packet[cursor]
        cursor += 1
        labels.append(packet[cursor : cursor + length].decode("ascii", "ignore"))
        cursor += length
    name = ".".join(labels).lower()
    flags = 0x8180 if name == expected_name.lower() else 0x8183
    header = transaction_id + struct.pack("!HHHH", flags, 1, 1 if flags == 0x8180 else 0, 0)
    if flags != 0x8180:
        return header + question
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton(address)
    return header + question + answer


def run_dns(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    sock.settimeout(0.5)
    stopped = False

    def stop(_signum, _frame):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopped:
        try:
            packet, peer = sock.recvfrom(4096)
        except socket.timeout:
            continue
        response = dns_response(packet, args.name, args.address)
        if response:
            sock.sendto(response, peer)
    sock.close()


def run_http(args):
    server = FixtureHTTPServer((args.host, args.port), args.slow_seconds)
    signal.signal(signal.SIGTERM, lambda _signum, _frame: server.shutdown())
    signal.signal(signal.SIGINT, lambda _signum, _frame: server.shutdown())
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)
    dns = subparsers.add_parser("dns")
    dns.add_argument("--host", default="127.0.0.1")
    dns.add_argument("--port", type=int, required=True)
    dns.add_argument("--name", required=True)
    dns.add_argument("--address", required=True)
    dns.set_defaults(run=run_dns)
    http = subparsers.add_parser("http")
    http.add_argument("--host", default="127.0.0.1")
    http.add_argument("--port", type=int, required=True)
    http.add_argument("--slow-seconds", type=float, default=4)
    http.set_defaults(run=run_http)
    args = parser.parse_args()
    args.run(args)


if __name__ == "__main__":
    main()
