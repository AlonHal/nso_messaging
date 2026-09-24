"""Command-line interface for the primary client and local server."""

import argparse
import json
import logging

from .client import MessagingClient
from .config import load_config, resolve_request_timeout, resolve_socket_timeout
from .server import MessagingServer

logger = logging.getLogger(__name__)


def build_parser():
    """Build the command-line parser for server and client operations.

    Arguments are parsed here, while network and persistence behavior remains
    in the client and server classes for direct testing.
    """
    # A shared parent lets --config appear either before or after the
    # subcommand (e.g. both `nso-messaging --config f.json serve` and
    # `nso-messaging serve --config f.json` work).
    config_parent = argparse.ArgumentParser(add_help=False)
    config_parent.add_argument(
        "--config",
        help="Path to a JSON config file for request/socket timeouts "
        "(defaults to nso-messaging.config.json or NSO_MESSAGING_CONFIG)",
    )

    parser = argparse.ArgumentParser(prog="nso-messaging", parents=[config_parent])
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", parents=[config_parent])
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--data-dir", default="server-data")
    serve.add_argument(
        "--socket-timeout",
        type=float,
        default=None,
        help="Socket read timeout in seconds (default: no timeout)",
    )

    register = commands.add_parser("register", parents=[config_parent])
    _add_client_options(register)
    register.add_argument("--name")

    send = commands.add_parser("send", parents=[config_parent])
    _add_client_options(send)
    send.add_argument("--recipient", required=True)
    send.add_argument("--message", required=True)

    receive = commands.add_parser("receive", parents=[config_parent])
    _add_client_options(receive)

    history = commands.add_parser("history", parents=[config_parent])
    history.add_argument("--state-dir", required=True)
    return parser


def _add_client_options(parser):
    """Add options shared by client commands."""
    parser.add_argument("--server", required=True)
    parser.add_argument("--phone", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--client-role", default="primary")
    parser.add_argument("--encryption-enabled", action="store_true")
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=None,
        help="HTTP request timeout in seconds (default: 5, or from config)",
    )


def _client_from_args(args, config):
    """Construct a client from parsed command-line options."""
    return MessagingClient(
        args.server,
        args.phone,
        args.state_dir,
        client_role=args.client_role,
        encryption_enabled=args.encryption_enabled,
        request_timeout=resolve_request_timeout(args.request_timeout, config),
    )


def main(argv=None):
    """Execute one CLI command and print its JSON result to standard output.

    Operational logs go to stderr through the logging module, leaving stdout
    machine-readable for shell scripts and automated CLI tests.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(processName)s:%(threadName)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    args = build_parser().parse_args(argv)
    config = load_config(args.config)
    if args.command == "serve":
        server = MessagingServer(
            args.host,
            args.port,
            args.data_dir,
            socket_timeout=resolve_socket_timeout(args.socket_timeout, config),
        )
        # Print the selected port before blocking so callers can discover it
        # when they request an ephemeral port for local development.
        print(json.dumps({"server_url": server.base_url}), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.shutdown()
        return
    if args.command == "register":
        result = _client_from_args(args, config).register(args.name)
    elif args.command == "send":
        result = _client_from_args(args, config).send(args.recipient, args.message)
    elif args.command == "receive":
        result = _client_from_args(args, config).receive()
    else:
        # History does not need a server connection, but it reuses the client's
        # query implementation so CLI and library results stay identical.
        result = MessagingClient.__new__(MessagingClient)
        result.database_path = args.state_dir + "/messages.sqlite3"
        result = MessagingClient.history(result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
