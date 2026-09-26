"""Shared fixtures for integration and CLI tests."""

import threading

import pytest

from nso_messaging.server import MessagingServer


@pytest.fixture
def running_server(tmp_path):
    """Run an isolated HTTP server for a test and cleanly shut it down."""
    server = MessagingServer("127.0.0.1", 0, tmp_path / "server")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=2)
