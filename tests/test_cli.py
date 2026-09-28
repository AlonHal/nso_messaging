import json

from nso_messaging.cli import main


def test_cli_register_send_receive_and_history(running_server, tmp_path, capsys):
    """Exercise primary registration, message exchange, and local history via CLI."""
    alice_dir = tmp_path / "alice"
    bob_dir = tmp_path / "bob"
    server = running_server.base_url

    main(["register", "--server", server, "--phone", "+15550020", "--name", "Alice", "--state-dir", str(alice_dir)])
    main(["register", "--server", server, "--phone", "+15550021", "--name", "Bob", "--state-dir", str(bob_dir)])
    capsys.readouterr()

    main(["send", "--server", server, "--phone", "+15550020", "--state-dir", str(alice_dir), "--recipient", "+15550021", "--message", "hello"])
    sent = json.loads(capsys.readouterr().out)
    assert sent["content"] == "hello"

    main(["receive", "--server", server, "--phone", "+15550021", "--state-dir", str(bob_dir)])
    received = json.loads(capsys.readouterr().out)
    assert received[0]["content"] == "hello"

    main(["history", "--state-dir", str(bob_dir)])
    history = json.loads(capsys.readouterr().out)
    assert history[0]["direction"] == "received"


def test_cli_listen_emits_received_messages_as_json_lines(tmp_path, monkeypatch, capsys):
    """Expose the long-running client polling mode through the CLI."""
    observed = {}
    message = {"message_id": "message-1", "content": "hello"}

    class ListeningClient:
        """Stub a client listener that yields one delivered message."""

        def __init__(self, *args, **kwargs):
            pass

        def listen(self, poll_interval):
            observed["poll_interval"] = poll_interval
            yield message

    monkeypatch.setattr("nso_messaging.cli.MessagingClient", ListeningClient)

    main(
        [
            "listen", "--server", "http://localhost:8000", "--phone", "+15550024",
            "--state-dir", str(tmp_path / "listener"), "--poll-interval", "0.25",
        ]
    )

    assert observed["poll_interval"] == 0.25
    assert json.loads(capsys.readouterr().out) == message


def test_cli_links_companion_through_offer_primary_and_registration_steps(
    running_server, tmp_path, capsys
):
    """Run file-offer creation, primary approval, and companion completion via CLI."""
    server = running_server.base_url
    link_directory = tmp_path / "link-files"
    primary_state = tmp_path / "primary"
    companion_state = tmp_path / "companion"
    phone_number = "+15550026"
    link_id = "cli-pairing-26"

    main(
        [
            "register", "--server", server, "--phone", phone_number,
            "--state-dir", str(primary_state), "--encryption-enabled",
        ]
    )
    capsys.readouterr()
    main(
        [
            "link-offer", "--server", server, "--phone", phone_number,
            "--state-dir", str(companion_state), "--link-id", link_id,
            "--link-dir", str(link_directory),
        ]
    )
    capsys.readouterr()
    main(
        [
            "link", "--server", server, "--phone", phone_number,
            "--state-dir", str(primary_state), "--link-id", link_id,
            "--link-dir", str(link_directory),
        ]
    )
    linked = json.loads(capsys.readouterr().out)
    assert linked["status"] == "pending"

    main(
        [
            "register", "--server", server, "--phone", phone_number,
            "--state-dir", str(companion_state), "--client-role", "companion",
            "--encryption-enabled", "--link-id", link_id,
            "--link-dir", str(link_directory),
        ]
    )
    registration = json.loads(capsys.readouterr().out)
    assert registration["client_role"] == "companion"
    assert registration["device_id"]


def test_cli_config_option_must_precede_subcommand(running_server, tmp_path, capsys):
    """Verify the global config option is accepted before a command."""
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"request_timeout": 30}))
    alice_dir = tmp_path / "alice"
    server = running_server.base_url

    main(
        [
            "--config", str(config_path),
            "register", "--server", server, "--phone", "+15550022", "--state-dir", str(alice_dir),
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert result["phone_number"] == "+15550022"


def test_cli_resolves_configured_timeout_and_explicit_override(tmp_path, monkeypatch):
    """Ensure an explicit request timeout overrides the loaded config value."""
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"request_timeout": 30}))
    captured = []

    class RecordingClient:
        """Stand in for MessagingClient and capture the timeout it was constructed with."""

        def __init__(self, *args, **kwargs):
            captured.append(kwargs)

        def register(self, name):
            return {}

    monkeypatch.setattr("nso_messaging.cli.MessagingClient", RecordingClient)

    main(
        [
            "--config", str(config_path),
            "register", "--server", "http://x", "--phone", "+1", "--state-dir", str(tmp_path / "a"),
        ]
    )
    assert captured[-1]["request_timeout"] == 30

    # an explicit --request-timeout still overrides the config file
    main(
        [
            "--config", str(config_path),
            "register", "--server", "http://x", "--phone", "+2", "--state-dir", str(tmp_path / "b"),
            "--request-timeout", "5",
        ]
    )
    assert captured[-1]["request_timeout"] == 5

