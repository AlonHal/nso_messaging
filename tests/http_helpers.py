"""Reusable HTTP request helpers for integration tests."""

import base64
import hashlib
import hmac
import json
import urllib.request


def request_json(url, method="GET", payload=None):
    """Send a JSON request and return its status and decoded response."""
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=2) as response:
        return response.status, json.load(response)


def request_raw(url, body):
    """Send an unsigned raw JSON body for malformed-request tests."""
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=2) as response:
        return response.status, json.load(response)


def authenticated_request_json(url, account_id, auth_key, method="GET", payload=None):
    """Sign the exact method, path, and serialized body used by the server."""
    data = None if payload is None else json.dumps(payload).encode()
    path = url[url.index("/", len("http://")) :]
    signing_input = method.encode() + b"\n" + path.encode() + b"\n" + (data or b"")
    secret = base64.urlsafe_b64decode(auth_key.encode())
    signature = hmac.new(secret, signing_input, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
            "X-Auth-Account": account_id,
            "X-Auth-Signature": signature,
        },
    )
    with urllib.request.urlopen(request, timeout=2) as response:
        return response.status, json.load(response)


def authenticated_request_raw(url, account_id, auth_key, body, method="POST"):
    """Sign and send an exact raw body, including intentionally malformed JSON."""
    path = url[url.index("/", len("http://")) :]
    signing_input = method.encode() + b"\n" + path.encode() + b"\n" + body
    secret = base64.urlsafe_b64decode(auth_key.encode())
    signature = hmac.new(secret, signing_input, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Content-Type": "application/json",
            "X-Auth-Account": account_id,
            "X-Auth-Signature": signature,
        },
    )
    with urllib.request.urlopen(request, timeout=2) as response:
        return response.status, json.load(response)


def register(server, phone_number):
    """Register a test account and return its response credentials."""
    _, account = request_json(
        server.base_url + "/register",
        "POST",
        {"phone_number": phone_number},
    )
    return account
