"""Fixture: one detection per Fire Crow SAST rule family.

Not real code. Each function is a minimal, deterministic trigger so the live
end-to-end test can assert rule id, location, severity and scanner metadata
against known line numbers.
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import urllib.request

import yaml


def sql_injection(conn, user_id):
    # CWE-89: value concatenated into SQL
    return conn.cursor().execute("SELECT * FROM users WHERE id = '" + user_id + "'")


def command_injection(user):
    # CWE-78: shell interprets metacharacters from `user`
    return subprocess.call("ls " + user, shell=True)


def code_injection(expr):
    # CWE-95: arbitrary code execution
    return eval(expr)


def path_traversal(name):
    # CWE-22: ".." escapes the base directory
    return open("/var/data/" + name).read()


def xss(response, name):
    # CWE-79: unescaped input in an HTML response
    response.write("<div>" + name + "</div>")


def ssrf(url):
    # CWE-918: outbound request to a non-literal URL
    return urllib.request.urlopen(url).read()


def unsafe_pickle(blob):
    # CWE-502: unpickling executes arbitrary code
    return pickle.loads(blob)


def unsafe_yaml(text):
    # CWE-502: yaml.load constructs arbitrary Python objects
    return yaml.load(text)


def weak_hash(password):
    # CWE-327: MD5 is broken
    return hashlib.md5(password.encode()).hexdigest()


def weak_token():
    # CWE-330: predictable randomness for a token
    return random.randint(0, 10**9)


DB_PASSWORD = "prod-db-password-9f2c1a"
API_TOKEN = "ghp_live_2f9c1a8e4b7d3c6a5e8f1b2c9d4e7a0b"
