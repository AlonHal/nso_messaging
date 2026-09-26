"""Tests for timeout config resolution: explicit path, env var, default file,
missing file, and CLI-over-config precedence."""

import json

import pytest

from nso_messaging.config import (
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_SOCKET_TIMEOUT,
    load_config,
    resolve_request_timeout,
    resolve_socket_timeout,
)


def test_load_config_missing_file_returns_empty_dict(tmp_path):
    """Use an empty config when the requested config file does not exist."""
    assert load_config(tmp_path / "does-not-exist.json") == {}


def test_load_config_reads_explicit_path(tmp_path):
    """Load JSON settings from an explicitly provided path."""
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"request_timeout": 42}))

    assert load_config(config_path) == {"request_timeout": 42}


def test_load_config_uses_env_var_when_no_path_given(tmp_path, monkeypatch):
    """Use the environment-selected config when no explicit path is given."""
    config_path = tmp_path / "from-env.json"
    config_path.write_text(json.dumps({"socket_timeout": 17}))
    monkeypatch.setenv("NSO_MESSAGING_CONFIG", str(config_path))

    assert load_config() == {"socket_timeout": 17}


def test_load_config_uses_default_filename_in_cwd(tmp_path, monkeypatch):
    """Load the conventional config filename from the current directory."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NSO_MESSAGING_CONFIG", raising=False)
    (tmp_path / "nso-messaging.config.json").write_text(json.dumps({"request_timeout": 99}))

    assert load_config() == {"request_timeout": 99}


def test_load_config_falls_back_to_empty_dict_without_env_or_default_file(tmp_path, monkeypatch):
    """Fall back to defaults when neither environment nor file config exists."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NSO_MESSAGING_CONFIG", raising=False)

    assert load_config() == {}


@pytest.mark.parametrize(
    ("cli_value", "config", "expected"),
    [
        (10.0, {"request_timeout": 20}, 10.0),
        (None, {"request_timeout": 20}, 20),
        (None, {}, DEFAULT_REQUEST_TIMEOUT),
    ],
)
def test_resolve_request_timeout_precedence(cli_value, config, expected):
    """Resolve request timeout with explicit CLI values taking precedence."""
    assert resolve_request_timeout(cli_value, config) == expected


@pytest.mark.parametrize(
    ("cli_value", "config", "expected"),
    [
        (30.0, {"socket_timeout": 60}, 30.0),
        (None, {"socket_timeout": 60}, 60),
        (None, {}, DEFAULT_SOCKET_TIMEOUT),
    ],
)
def test_resolve_socket_timeout_precedence(cli_value, config, expected):
    """Resolve socket timeout with explicit CLI values taking precedence."""
    assert resolve_socket_timeout(cli_value, config) == expected
