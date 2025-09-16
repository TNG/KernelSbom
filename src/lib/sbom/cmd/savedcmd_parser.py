# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH <info@tngtech.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import re
import shlex
from dataclasses import dataclass
from typing import Callable, Optional, Union

class CommandParserException(Exception):
    """Raised when a command string cannot be parsed correctly."""
    pass

@dataclass
class Option:
    name: str
    value: Optional[str] = None  # None means flag without value

@dataclass
class Positional:
    value: str

def _parse_command(command: str) -> list[Union[Option, Positional]]:
    """
    Parses a shell-style command string into a list of structured objects:
    - Positional: Includes the command itself and any positional arguments.
    - Options: Handles short/long options with or without values 
                (e.g. '--opt val', '--opt=val', '--flag').

    Returns:
        List of `Positional` and `Option` objects in command order.
    """
    tokens = shlex.split(command)
    parsed = []
    i = 0
    while i < len(tokens):
        token = tokens[i]

        # Positional
        if not token.startswith('-'):
            parsed.append(Positional(token))
            i += 1
            continue

        # Option with equals sign (--opt=val)
        if '=' in token:
            name, value = token.split('=', 1)
            parsed.append(Option(name=name, value=value))
            i += 1
            continue

        # Option with space-separated value (--opt val)
        if i + 1 < len(tokens) and not tokens[i + 1].startswith('-'):
            parsed.append(Option(name=token, value=tokens[i + 1]))
            i += 2
            continue

        # Option without value (--flag)
        parsed.append(Option(name=token))
        i += 1

    return parsed

def _parse_objcopy_command(savedcmd: str) -> list[str]:
    command_parts = _parse_command(savedcmd)
    positionals = [part.value for part in command_parts if isinstance(part, Positional)]
    # expect positionals to be ['objcopy', input_file] or ['objcopy', input_file, output_file]
    if not (len(positionals) == 2 or len(positionals) == 3):
        raise CommandParserException("Invalid objcopy command format.")
    return [positionals[1]]

def _parse_link_vmlinux_command(savedcmd: str) -> list[str]:
    # TODO: Implement link-vmlinux.sh parsing
    return []

# Command parser registry
COMMAND_PARSERS: list[tuple[re.Pattern, Callable[[str], list[str]]]] = [
    (re.compile(r'^objcopy\b'), _parse_objcopy_command),
    (re.compile(r'^(.*/)?link-vmlinux\.sh\b'), _parse_link_vmlinux_command)
]

def parse_savedcmd(savedcmd: str) -> list[str]:
    """
    Parses a command line string and returns the input files of that command.

    Returns:
        input_files (list[str]): Input files of the command.

    Raises:
        NotImplementedError: If no parser matches the command.
        CommandParserException: If parsing fails inside a matched parser.
    """
    for pattern, parser in COMMAND_PARSERS:
        if pattern.search(savedcmd):
            return parser(savedcmd)
    raise NotImplementedError(f"No parser matched command: {savedcmd}")
