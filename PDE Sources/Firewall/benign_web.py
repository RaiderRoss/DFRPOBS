#!/usr/bin/env python3
"""
The bank's public web front, for the benign users' ordinary web traffic.

Runs on the research VM, bound to the tunnel address, and answers real HTTP on the plain
ports and HTTPS on the TLS ports: a page like any bank's public site. Its job is fidelity.
Before it existed, benign users made a bare TCP connect and closed it at once, to ports where
nothing listened — zero-byte, refused flows that look to a flow-based IDS exactly like a
scan. Slips' machine-learning models flagged hundreds of them per window and put innocent
users next to its alert threshold. Real customers load real pages; so do these now.

Attack traffic does not come here in any way that changes it: the attacker's sweep targets
denied ports, and the guaranteed-alert profile has its own accept-and-close listener.
"""

import argparse
import os
import signal
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = (b"<!doctype html><html><head><title>PDE Bank</title></head><body>"
        b"<h1>PDE Bank</h1><p>Personal banking, loans and savings.</p>"
        b"<p><a href=\"/rates\">Rates</a> | <a href=\"/branches\">Branches</a> | "
        b"<a href=\"/contact\">Contact</a></p></body></html>\n")


# How long one customer may hold a connection without sending anything. A browser that
# stalls is dropped rather than left holding a thread.
CLIENT_IDLE_SECONDS = 10


class Server(ThreadingHTTPServer):
    # socketserver's default listen backlog is 5, which a burst of customers overflows;
    # the dropped SYNs would show up as page loads that never started.
    request_queue_size = 128
    daemon_threads = True


class TLSServer(Server):
    """HTTPS with the handshake in each connection's own thread.

    Wrapping the listening socket instead does every handshake inside accept(), in the one
    thread that accepts for the port. One client slow to finish its handshake then holds up
    every customer behind it: they connect, send their hello and hear nothing — page loads
    that fail for reasons no real bank's web front would give."""

    def __init__(self, address, handler, context):
        self.context = context
        super().__init__(address, handler)

    def finish_request(self, request, client_address):
        # Runs in the connection's thread (ThreadingMixIn.process_request_thread).
        request.settimeout(CLIENT_IDLE_SECONDS)
        try:
            tls = self.context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            tls.close()


class Handler(BaseHTTPRequestHandler):
    server_version = "PDE-Bank-Web/1.0"
    protocol_version = "HTTP/1.1"
    timeout = CLIENT_IDLE_SECONDS

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(PAGE)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAGE)))
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, fmt, *args):
        # Not evidence, and not wanted as evidence: the firewall and the IDS already record
        # these connections. Silence keeps this from filling the VM's disk over a batch.
        pass


def ports(text):
    return [int(p) for p in (text or "").split(",") if p.strip()]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", required=True, help="address to bind: the tunnel's VM end, never 0.0.0.0")
    ap.add_argument("--http-ports", default="", help="comma-separated plain-HTTP ports")
    ap.add_argument("--https-ports", default="", help="comma-separated HTTPS ports")
    ap.add_argument("--cert", help="PEM certificate for the HTTPS ports")
    ap.add_argument("--key", help="PEM private key for the HTTPS ports")
    ap.add_argument("--pidfile", required=True, help="written once every port is bound")
    args = ap.parse_args()

    if args.host in ("0.0.0.0", "", "*"):
        raise SystemExit("--host must name one address; 0.0.0.0 would publish this on every interface")
    plain, tls = ports(args.http_ports), ports(args.https_ports)
    if not plain and not tls:
        raise SystemExit("no ports given")
    if tls and not (args.cert and args.key):
        raise SystemExit("HTTPS ports need --cert and --key")

    ctx = None
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.cert, args.key)
    servers = []
    for port in plain + tls:
        try:
            srv = (TLSServer((args.host, port), Handler, ctx) if port in tls
                   else Server((args.host, port), Handler))
        except OSError as exc:
            raise SystemExit("cannot bind %s:%d: %s" % (args.host, port, exc))
        servers.append(srv)

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    for srv in servers:
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    # Written last and atomically: the shell waits on this file, so it must never exist for a
    # server that has not bound every port.
    tmp = args.pidfile + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(str(os.getpid()))
    os.replace(tmp, args.pidfile)
    print("web front on %s: http %s, https %s (pid %d)"
          % (args.host, plain or "-", tls or "-", os.getpid()), flush=True)
    signal.pause()


if __name__ == "__main__":
    main()
