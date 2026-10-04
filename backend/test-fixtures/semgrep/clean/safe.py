"""Fixture: the same operations as the vulnerable tree, written safely.

Exists to prove the ruleset discriminates rather than pattern-matching on the
presence of an API. A finding here would mean a false positive.
"""

import hashlib
import secrets
import sqlite3
import subprocess
import urllib.request
from pathlib import Path

import yaml

ALLOWED_HOSTS = {"api.internal"}


def sql_injection(conn, user_id):
    # Parameterized: the value never becomes SQL.
    return conn.cursor().execute("SELECT * FROM users WHERE id = ?", (user_id,))


def command_injection(user):
    # Argument vector, no shell.
    return subprocess.call(["ls", user], shell=False)


def safe_path(name):
    # Resolve and confirm the result stays under the base directory.
    base = Path("/var/data").resolve()
    target = (base / name).resolve()
    if base not in target.parents:
        raise ValueError("path escapes the base directory")
    return target.read_text()


def escaped_html(name):
    import html

    return "<div>" + html.escape(name) + "</div>"


def ssrf(url):
    """Fetch a URL after checking it against the allowlist.

    Known limitation, documented in `scanners/semgrep/firecrow-sast.yml`: the
    SSRF rule matches `urlopen(<variable>)` syntactically and cannot see that
    the host was validated first, so the call below is reported even though it
    is safe. The rule stays deliberately broad — a version that understood this
    particular guard would miss the unguarded case, which is the one that
    matters. Treat the finding as a review signal, not a proof.

    This fixture therefore cannot be used to assert a zero-finding result; see
    `tests/semgrep_integration.rs`, which asserts the *absence* of the seven
    rule families it is meant to prove the ruleset discriminates on.
    """
    from urllib.parse import urlparse

    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return urllib.request.urlopen(url).read()


def safe_load(text):
    return yaml.safe_load(text)


def strong_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()


def strong_token():
    return secrets.token_urlsafe(32)


def unused_connection():
    return sqlite3.connect(":memory:")
