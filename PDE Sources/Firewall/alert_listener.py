#!/usr/bin/env python3
"""
Accept-and-close listener behind ALERT_PORTS, for the guaranteed-alert attack profile.

Runs on the HOST side of the veth, bound to the host address, so the attacker's
connections cross the host INPUT chain and are logged by ufw exactly like every other
simulated connection. Its only job is to complete the TCP handshake: Slips rates a
connection to a port it has no service record for HIGH when the connection was
ESTABLISHED and MEDIUM when it was not, and nothing else in the lab answers on such a
port.

Each connection is accepted and closed at once. Nothing is read or sent, so both sides
close with a FIN and Zeek records the connection as SF, which Slips reads as established.
"""

import argparse
import os
import selectors
import signal
import socket
import sys


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", required=True, help="address to bind: the veth's host IP")
    ap.add_argument("--ports", required=True, help="comma-separated TCP ports")
    ap.add_argument("--pidfile", required=True,
                    help="written with this process's PID once every port is bound")
    args = ap.parse_args()

    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    if not ports:
        raise SystemExit("no ports given")

    sel = selectors.DefaultSelector()
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((args.host, port))
        except OSError as exc:
            raise SystemExit("cannot bind %s:%d: %s" % (args.host, port, exc))
        s.listen(512)
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ)

    # Stopped with SIGTERM; exit quietly rather than with a traceback in the log.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    # Written last, and atomically. The shell waits for this file to appear, so it must
    # never exist for a listener that bound only some of its ports.
    tmp = args.pidfile + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(str(os.getpid()))
    os.replace(tmp, args.pidfile)
    print("listening on %s ports %s (pid %d)" % (args.host, args.ports, os.getpid()),
          flush=True)

    while True:
        for key, _ in sel.select():
            try:
                conn, _ = key.fileobj.accept()
            except (BlockingIOError, InterruptedError):
                continue
            conn.close()


if __name__ == "__main__":
    main()
