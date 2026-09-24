import json
import threading

import pytest

from nso_messaging.cli import main
from nso_messaging.server import MessagingServer


@pytest.fixture
def running_server(tmp_path):
    server = MessagingServer("127.0.0.1", 0, tmp_path / "server")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_cli_register_send_receive_and_history(running_server, tmp_path, capsys):
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


def test_cli_config_option_accepted_before_and_after_subcommand(running_server, tmp_path, capsys):
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
    capsys.readouterr()

    main(
        [
            "register",
            "--server", server,
            "--phone", "+15550023",
            "--state-dir", str(tmp_path / "bob"),
            "--config", str(config_path),
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert result["phone_number"] == "+15550023"

