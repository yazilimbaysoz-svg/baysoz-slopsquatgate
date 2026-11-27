"""Manifest parsers. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from slopsquatgate.parsers.cargo_parser import parse_cargo
from slopsquatgate.parsers.common import ParseError, read_text
from slopsquatgate.parsers.go_parser import parse_go
from slopsquatgate.parsers.npm_parser import parse_npm
from slopsquatgate.parsers.python_parser import parse_python

PARSERS = (parse_python, parse_npm, parse_cargo, parse_go)

__all__ = ["PARSERS", "ParseError", "parse_cargo", "parse_go", "parse_npm", "parse_python", "read_text"]
