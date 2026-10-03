#!/usr/bin/env python3
"""
TCP relay putting the bank's port on the VM's tunnel address, on the host.

Runs ON the research VM. Fineract is a Docker-published port, and packets to a published
port are rewritten in nat/PREROUTING and cross FORWARD, never INPUT — so the VM's ufw
cannot log them. The one connection an investigator most wants in the firewall evidence,
the attacker logging into the bank, would be the one connection missing from it.

This listens on the tunnel address as an ordinary host process. A simulated user's
connection is therefore delivered locally, crosses INPUT, and is logged by ufw exactly like
every other connection in the window. Only then is a second connection opened to the
container.

Bytes are passed through untouched and nothing is parsed, so Fineract's TLS is still
negotiated between the user and Fineract: this is not a TLS terminator and holds no key.
What it does change is the address Fineract sees a request coming from, which is why the
bank's own attribution is by login and not by address — see Banking/README.md.
"""

import argparse
import os
import signal
import socket
import sys
import threading


def split_hostport(text, what):
    """`host:port` -> (host, port). IPv6 literals are not accepted; the lab is v4 only."""
    if text.count(":") != 1:
        raise SystemExit("%s must be host:port, got %r" % (what, text))
    host, _, port = text.partition(":")
    if not host:
        raise SystemExit("%s needs an address to bind, not just a port" % what)
    try:
        return host, int(port)
    except ValueError:
        raise SystemExit("%s has a non-numeric port: %r" % (what, text))


def pump(src, dst):
    """
    One direction, until the source closes.

    The half-close is forwarded rather than both sockets simply being dropped: a client
    that has finished sending but is still waiting to read (which is what an HTTP request
    on a keep-alive connection looks like) must see the far end's FIN, or it waits for a
    response that has already been sent.
    """
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        # A reset from either end is ordinary here: the generators open and abandon
        # connections deliberately. It is the other direction's job to finish up.
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client, target):
    try:
        upstream = socket.create_connection(target, timeout=10)
    except OSError as exc:
        # Logged, not fatal. The bank being down must not take the relay with it, or the
        # next window fails for a reason that has nothing to do with the bank.
        print("relay: cannot reach %s:%d: %s" % (target[0], target[1], exc), flush=True)
        client.close()
        return

    upstream.settimeout(None)
    # Nagle off in both directions: the payloads here are small request/response pairs, and
    # holding one back waiting for company adds latency to every call the scenario makes.
    for s in (client, upstream):
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    up = threading.Thread(target=pump, args=(client, upstream), daemon=True)
    up.start()
    pump(upstream, client)
    up.join(timeout=10)
    for s in (client, upstream):
        try:
            s.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--listen", required=True,
                    help="address:port to listen on — the VM's tunnel address, never 0.0.0.0")
    ap.add_argument("--target", required=True, help="address:port of the real service")
    ap.add_argument("--pidfile", required=True,
                    help="written with this process's PID once the socket is listening")
    args = ap.parse_args()

    listen_host, listen_port = split_hostport(args.listen, "--listen")
    target = split_hostport(args.target, "--target")

    # Bound to one address on purpose. On 0.0.0.0 this would publish Fineract, with its
    # default credentials, on every interface the VM has.
    if listen_host in ("0.0.0.0", "*", ""):
        raise SystemExit("--listen must name one address; 0.0.0.0 would expose the bank")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((listen_host, listen_port))
    except OSError as exc:
        raise SystemExit("cannot bind %s:%d: %s" % (listen_host, listen_port, exc))
    srv.listen(512)

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    # Written last and atomically: the shell waits on this file, so it must never exist for
    # a relay that is not yet accepting.
    tmp = args.pidfile + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(str(os.getpid()))
    os.replace(tmp, args.pidfile)
    print("relay: %s:%d -> %s:%d (pid %d)"
          % (listen_host, listen_port, target[0], target[1], os.getpid()), flush=True)

    while True:
        try:
            client, _ = srv.accept()
        except InterruptedError:
            continue
        except OSError as exc:
            print("relay: accept failed: %s" % exc, flush=True)
            continue
        threading.Thread(target=handle, args=(client, target), daemon=True).start()


if __name__ == "__main__":
    main()
