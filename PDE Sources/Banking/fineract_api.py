"""
A minimal Fineract API client for the PDE banking source. Standard library only, because
it runs inside the lab's network namespace with whatever python3 the host has.

It can bind each connection to a chosen source address. In the lab a "user" is an IP —
that is what the firewall log and the IDS know them by — so a banking request has to leave
from the same address its user's other traffic does, or the three sources would describe
three different people.
"""

import base64
import http.client
import json
import ssl
import time
from urllib.parse import urlsplit

# Fineract serves a self-signed certificate. There is nothing to verify it against in a
# sandbox, and the lab reaches it over an SSH tunnel that is itself authenticated.
_TLS = ssl.create_default_context()
_TLS.check_hostname = False
_TLS.verify_mode = ssl.CERT_NONE

DATE_FORMAT = "dd MMMM yyyy"


class FineractError(Exception):
    def __init__(self, status, body, what):
        self.status, self.body = status, body
        super().__init__("%s failed: HTTP %s %s" % (what, status, _brief(body)))


def _brief(body):
    if isinstance(body, dict):
        errs = body.get("errors") or []
        msg = body.get("defaultUserMessage") or body.get("developerMessage") or ""
        if errs:
            msg += " | " + "; ".join(e.get("defaultUserMessage", "") for e in errs[:3])
        return msg[:300]
    return str(body)[:300]


class Fineract:
    """One authenticated identity against one Fineract. `base` is the provider root, e.g.
    https://10.99.0.1:8443/fineract-provider — the /api/v1 prefix is added here."""

    def __init__(self, base, username, password, tenant="default", source_ip=None, timeout=20):
        u = urlsplit(base.rstrip("/"))
        self.host, self.port = u.hostname, u.port or 443
        self.prefix = u.path + "/api/v1"
        self.username = username
        self.tenant = tenant
        self.source_ip = source_ip
        self.timeout = timeout
        token = base64.b64encode(("%s:%s" % (username, password)).encode()).decode()
        self._headers = {
            "Authorization": "Basic " + token,
            "Fineract-Platform-TenantId": tenant,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def request(self, method, path, body=None):
        """Returns (status, parsed body, elapsed seconds). One connection per request:
        each is then its own flow in the capture, as a browser session's calls would be
        from the network's point of view, and a stuck request cannot poison the next."""
        conn = http.client.HTTPSConnection(
            self.host, self.port, timeout=self.timeout, context=_TLS,
            source_address=(self.source_ip, 0) if self.source_ip else None)
        t0 = time.monotonic()
        try:
            conn.request(method, self.prefix + path,
                         body=json.dumps(body) if body is not None else None,
                         headers=self._headers)
            resp = conn.getresponse()
            raw = resp.read()
            status = resp.status
        finally:
            conn.close()
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = raw.decode("utf-8", "replace")
        return status, parsed, time.monotonic() - t0

    def call(self, method, path, body=None, what=None):
        """request(), but a non-2xx is an exception. For setup, where failure means stop."""
        status, parsed, _ = self.request(method, path, body)
        if not 200 <= status < 300:
            raise FineractError(status, parsed, what or "%s %s" % (method, path))
        return parsed


def fineract_date(dt):
    """Fineract takes dates as strings in a declared format. Always sent with the format
    and locale beside them, never relying on the server's defaults."""
    return dt.strftime("%d %B %Y")
