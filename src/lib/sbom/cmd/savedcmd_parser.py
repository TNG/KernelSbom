# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only

import re
import shlex
from dataclasses import dataclass
from typing import Optional, Union


@dataclass
class Option:
    name: str
    value: Optional[str] = None  # None means flag without value


@dataclass
class Positional:
    value: str


_SUBCOMMAND_PATTERN = re.compile(r"\$\$\(([^()]*)\)")
"""Pattern to match $$(...) blocks"""


def _parse_single_command(command: str) -> list[Union[Option, Positional]]:
    """
    Parses a shell-style command string into a list of structured objects:
    - Positional: Includes the command itself and any positional arguments.
    - Options: Handles short/long options with or without values
                (e.g. '--opt val', '--opt=val', '--flag').

    Returns:
        List of `Positional` and `Option` objects in command order.
    """
    #  Wrap all $$(...) blocks in double quotes to prevent shlex from splitting them.
    command_with_protected_subcommands = _SUBCOMMAND_PATTERN.sub(lambda m: f'"$$({m.group(1)})"', command)
    tokens = shlex.split(command_with_protected_subcommands)

    parsed: list[Option | Positional] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]

        # Positional
        if not token.startswith("-"):
            parsed.append(Positional(token))
            i += 1
            continue

        # Option with equals sign (--opt=val)
        if "=" in token:
            name, value = token.split("=", 1)
            parsed.append(Option(name=name, value=value))
            i += 1
            continue

        # Option with space-separated value (--opt val)
        if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
            parsed.append(Option(name=token, value=tokens[i + 1]))
            i += 2
            continue

        # Option without value (--flag)
        parsed.append(Option(name=token))
        i += 1

    return parsed


def _parse_single_command_positionals_only(command: str) -> list[str]:
    command_parts = _parse_single_command(command)
    positionals = [p.value for p in command_parts if isinstance(p, Positional)]
    if len(positionals) != len(command_parts):
        raise NotImplementedError(
            f"Invalid command format: expected positional arguments only but got options in command {command}."
        )
    return positionals


def _parse_objcopy_command(command: str) -> list[str]:
    command_parts = _parse_single_command(command)
    positionals = [part.value for part in command_parts if isinstance(part, Positional)]
    # expect positionals to be ['objcopy', input_file] or ['objcopy', input_file, output_file]
    if not (len(positionals) == 2 or len(positionals) == 3):
        raise NotImplementedError(
            f"Invalid objcopy command format: expected 2 or 3 positional arguments, got {len(positionals)} ({positionals})"
        )
    return [positionals[1]]


def _parse_link_vmlinux_command(command: str) -> list[str]:
    """
    For simplicity we do not parse the `scripts/link-vmlinux.sh` script.
    Instead the `vmlinux.a` dependency is just hardcoded for now.
    """
    return ["vmlinux.a"]


def _parse_noop(command: str) -> list[str]:
    """
    No-op parser for commands with no input files (e.g., 'rm', 'true').
    Returns an empty list.
    """
    return []


def _parse_ar_command(command: str) -> list[str]:
    positionals = _parse_single_command_positionals_only(command)
    # expect positionals to be ['ar', flags, output, input1, input2, ...]
    flags = positionals[1]
    if "r" not in flags:
        # 'r' option indicates that new files are added to the archive.
        # If this option is missing we won't find any relevant input files.
        return []
    return positionals[3:]


def _parse_ar_piped_command(command: str) -> list[str]:
    printf_command, _ = command.split("|", 1)
    positionals = _parse_single_command_positionals_only(printf_command.strip())
    # expect positionals to be ['printf', '{prefix_path}%s ', input1, input2, ...]
    return positionals[2:]


def _parse_gcc_command(command: str) -> list[str]:
    # TODO: implement this function
    return []


# Command parser registry
COMMAND_PARSERS = [
    (re.compile(r"^objcopy\b"), _parse_objcopy_command),
    (re.compile(r"^(.*/)?link-vmlinux\.sh\b"), _parse_link_vmlinux_command),
    (re.compile(r"^rm\b"), _parse_noop),
    (re.compile(r"^true\b"), _parse_noop),
    (re.compile(r"^ar\b"), _parse_ar_command),
    (re.compile(r"^printf\b.*\| xargs ar\b"), _parse_ar_piped_command),
    (re.compile(r"^gcc\b"), _parse_gcc_command),
]


def parse_savedcmd(savedcmd: str) -> list[str]:
    """
    Parses a command line string and returns the input files of that command.

    Returns:
        input_files (list[str]): Input files of the command.
    """
    input_files: list[str] = []
    for command in savedcmd.split(";"):
        command = command.strip()
        matched_parser = next((parser for pattern, parser in COMMAND_PARSERS if pattern.match(command)), None)
        if matched_parser is None:
            raise NotImplementedError(f"No parser matched command: {command}")
        input_files.extend(matched_parser(command))
    return input_files
