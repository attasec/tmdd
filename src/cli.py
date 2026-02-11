#!/usr/bin/env python3
"""TMDD CLI - Single entry point for all TMDD operations."""
import argparse
import sys

from .commands import init, lint, feature, compile
from .utils import DEFAULT_MODEL_DIR, TMDDError


_COMMANDS = {
    "init": init.cmd_init,
    "lint": lint.cmd_lint,
    "feature": feature.cmd_feature,
    "compile": compile.cmd_compile,
}


def main():
    p = argparse.ArgumentParser(
        prog="tmdd",
        description="TMDD - Threat Modeling Driven Development",
        epilog="Commands: init, lint, feature, compile. For diagrams: python diagram.py <path>",
    )
    sub = p.add_subparsers(dest="command")

    # init
    i = sub.add_parser("init", help="Create a new TMDD project")
    i.add_argument("path", nargs="?", default=DEFAULT_MODEL_DIR, help=f"Directory to initialize (default: {DEFAULT_MODEL_DIR})")
    i.add_argument("-n", "--name", default="My System", help="System name")
    i.add_argument("-d", "--description", default="System description", help="Description")
    i.add_argument("-t", "--template", default="minimal", help="Template (minimal, web-app, api)")
    i.add_argument("-l", "--list", action="store_true", help="List templates")

    # lint
    l = sub.add_parser("lint", help="Validate threat model")
    l.add_argument("path", nargs="?", default=DEFAULT_MODEL_DIR, help=f"Threat model directory (default: {DEFAULT_MODEL_DIR})")
    l.add_argument("--no-mitigations", action="store_true", help="Allow unmapped threats (flat list instead of threat→mitigation mapping)")

    # feature
    f = sub.add_parser("feature", help="Threat-model-first feature workflow")
    f.add_argument("name", help="Feature name")
    f.add_argument("-p", "--path", default=DEFAULT_MODEL_DIR, help=f"Threat model directory (default: {DEFAULT_MODEL_DIR})")
    f.add_argument("-d", "--description", help="Feature description")

    # compile
    c = sub.add_parser("compile", help="Generate consolidated files")
    c.add_argument("path", nargs="?", default=DEFAULT_MODEL_DIR, help=f"Threat model directory (default: {DEFAULT_MODEL_DIR})")
    c.add_argument("-f", "--feature", help="Generate for specific feature")

    args = p.parse_args()
    if not args.command:
        p.print_help()
        return 0

    handler = _COMMANDS.get(args.command)
    if not handler:
        p.print_help()
        return 1

    try:
        return handler(args)
    except TMDDError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
