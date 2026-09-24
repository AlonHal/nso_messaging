"""Shared timeout configuration, loadable from an optional JSON file.

Debugging a request handler under a breakpoint can pause execution far longer
than a typical request should take. Centralizing timeout defaults here lets
that be extended via a config file instead of editing source or retyping CLI
flags for every command.
"""

import json
import os
from pathlib import Path

DEFAULT_REQUEST_TIMEOUT = 5.0
DEFAULT_SOCKET_TIMEOUT = None

_CONFIG_ENV_VAR = "NSO_MESSAGING_CONFIG"
_DEFAULT_CONFIG_PATH = Path("nso-messaging.config.json")


def load_config(path: str | Path | None = None) -> dict:
    """Load timeout configuration from a JSON file, if one is present.

    Resolution order: an explicit ``path``, the ``NSO_MESSAGING_CONFIG``
    environment variable, then ``nso-messaging.config.json`` in the current
    directory. A missing file yields an empty config so defaults apply.
    """
    candidate = Path(path) if path else Path(os.environ.get(_CONFIG_ENV_VAR, _DEFAULT_CONFIG_PATH))
    if not candidate.exists():
        return {}
    return json.loads(candidate.read_text())


def resolve_request_timeout(cli_value: float | None, config: dict) -> float:
    """Resolve the client HTTP request timeout, preferring an explicit CLI value."""
    if cli_value is not None:
        return cli_value
    return config.get("request_timeout", DEFAULT_REQUEST_TIMEOUT)


def resolve_socket_timeout(cli_value: float | None, config: dict) -> float | None:
    """Resolve the server socket read timeout, preferring an explicit CLI value."""
    if cli_value is not None:
        return cli_value
    return config.get("socket_timeout", DEFAULT_SOCKET_TIMEOUT)
