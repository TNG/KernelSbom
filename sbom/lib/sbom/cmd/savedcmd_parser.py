# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only

from pathlib import Path
import re
import shlex
from dataclasses import dataclass
from typing import Callable, Optional, Union


@dataclass
class Option:
    name: str
    value: Optional[str] = None  # None means flag without value


@dataclass
class Positional:
    value: str


_SUBCOMMAND_PATTERN = re.compile(r"\$\$\(([^()]*)\)")
"""Pattern to match $$(...) blocks"""


def _tokenize_single_command(
    command: str, flag_options: list[str] | None = None, concatenated_value_options: list[str] | None = None
) -> list[Union[Option, Positional]]:
    """
    Parse a shell command into a list of Options and Positionals.
    - Positional: the command and any positional arguments.
    - Options: handles flags and options with values provided as space-separated, equals-sign, or concatenated forms
        (e.g., '--opt val', '--opt=val', '--optValue', '--flag').

    Args:
        command: Command line string.
        flag_options: Options that are flags without values (e.g., '--verbose').
        concatenated_value_options: Options with values concatenated (e.g., '-I/usr/include').

    Returns:
        List of `Option` and `Positional` objects in command order.
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

        # Option without value (--flag)
        if flag_options and token in flag_options:
            parsed.append(Option(name=token))
            i += 1
            continue

        # Option with concatenated value
        if concatenated_value_options:
            matched_option = next(
                (o for o in concatenated_value_options if token.startswith(o) and len(token) > len(o)), None
            )
            if matched_option:
                parsed.append(Option(name=matched_option, value=token.removeprefix(matched_option)))
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

        raise NotImplementedError(f"Unrecognized token: {token} in command {command}")

    return parsed


def _tokenize_single_command_positionals_only(command: str) -> list[str]:
    command_parts = _tokenize_single_command(command)
    positionals = [p.value for p in command_parts if isinstance(p, Positional)]
    if len(positionals) != len(command_parts):
        raise NotImplementedError(
            f"Invalid command format: expected positional arguments only but got options in command {command}."
        )
    return positionals


def _parse_objcopy_command(command: str) -> list[Path]:
    command_parts = _tokenize_single_command(command, flag_options=["-S"])
    positionals = [part.value for part in command_parts if isinstance(part, Positional)]
    # expect positionals to be ['objcopy', input_file] or ['objcopy', input_file, output_file]
    if not (len(positionals) == 2 or len(positionals) == 3):
        raise NotImplementedError(
            f"Invalid objcopy command format: expected 2 or 3 positional arguments, got {len(positionals)} ({positionals})"
        )
    return [Path(positionals[1])]


def _parse_link_vmlinux_command(command: str) -> list[Path]:
    """
    For simplicity we do not parse the `scripts/link-vmlinux.sh` script.
    Instead the `vmlinux.a` dependency is just hardcoded for now.
    """
    return [Path("vmlinux.a")]


def _parse_noop(command: str) -> list[Path]:
    """
    No-op parser for commands with no input files (e.g., 'rm', 'true').
    Returns an empty list.
    """
    return []


def _parse_ar_command(command: str) -> list[Path]:
    positionals = _tokenize_single_command_positionals_only(command)
    # expect positionals to be ['ar', flags, output, input1, input2, ...]
    flags = positionals[1]
    if "r" not in flags:
        # 'r' option indicates that new files are added to the archive.
        # If this option is missing we won't find any relevant input files.
        return []
    return [Path(p) for p in positionals[3:]]


def _parse_ar_piped_command(command: str) -> list[Path]:
    printf_command, _ = command.split("|", 1)
    positionals = _tokenize_single_command_positionals_only(printf_command.strip())
    # expect positionals to be ['printf', '{prefix_path}%s ', input1, input2, ...]
    return [Path(p) for p in positionals[2:]]


def _parse_gcc_command(command: str) -> list[Path]:
    parts = shlex.split(command)
    if "-c" not in parts:
        raise NotImplementedError(f"Unsupported gcc command: missing '-c' compile flag.\nCommand: {command}")
    # expect last positional argument ending in `.c` or `.S` to be the input file
    for part in reversed(parts):
        if not part.startswith("-") and Path(part).suffix in [".c", ".S"]:
            return [Path(part)]
    raise ValueError(f"Could not find input source file in command: {command}")


def _parse_syscallhdr_command(command: str) -> list[Path]:
    command_parts = _tokenize_single_command(command.strip(), flag_options=["--emit-nr"])
    positionals = [p.value for p in command_parts if isinstance(p, Positional)]
    # expect positionals to be ["sh", path/to/syscallhdr.sh, input, output]
    return [Path(positionals[2])]


def _parse_syscalltbl_command(command: str) -> list[Path]:
    command_parts = _tokenize_single_command(command.strip())
    positionals = [p.value for p in command_parts if isinstance(p, Positional)]
    # expect positionals to be ["sh", path/to/syscalltbl.sh, input, output]
    return [Path(positionals[2])]


def _parse_mkcapflags_command(command: str) -> list[Path]:
    positionals = _tokenize_single_command_positionals_only(command)
    # expect positionals to be ["sh", path/to/mkcapflags.sh, output, input1, input2]
    return [Path(positionals[3]), Path(positionals[4])]


def _parse_orc_hash_command(command: str) -> list[Path]:
    positionals = _tokenize_single_command_positionals_only(command)
    # expect positionals to be ["sh", path/to/orc_hash.sh, '<', input, '>', output]
    return [Path(positionals[3])]


def _parse_vdso2c_command(command: str) -> list[Path]:
    positionals = _tokenize_single_command_positionals_only(command.strip())
    # expect positionals to be ['vdso2c', raw_input, stripped_input, output]
    return [Path(positionals[1]), Path(positionals[2])]


def _parse_genheaders_command(_: str) -> list[Path]:
    # At the time of writing `security/selinux/genheaders.c` includes `classmap.h` and `initial_sid_to_string.h`.
    # Since parsing .c files is out of scope for this tool the two header files are hardcoded.
    return [Path("security/selinux/include/classmap.h"), Path("security/selinux/include/initial_sid_to_string.h")]


def _parse_ld_command(command: str) -> list[Path]:
    command_parts = _tokenize_single_command(
        command=command.strip(),
        flag_options=["-shared", "--no-undefined", "--eh-frame-hdr", "-Bsymbolic"],
    )
    positionals = [p.value for p in command_parts if isinstance(p, Positional)]
    # expect positionals to be ["ld", input1, input2, ...]
    return [Path(p) for p in positionals[1:]]


def _parse_sed_command(command: str) -> list[Path]:
    command_parts = shlex.split(command)
    # expect command parts to be ["sed", *, input, ">", output]
    if command_parts[-2] == ">":
        return [Path(command_parts[-3])]
    raise NotImplementedError("Unrecognized sed command format: {command}")


# Command parser registry
SINGLE_COMMAND_PARSERS: list[tuple[re.Pattern[str], Callable[[str], list[Path]]]] = [
    (re.compile(r"^objcopy\b"), _parse_objcopy_command),
    (re.compile(r"^(.*/)?link-vmlinux\.sh\b"), _parse_link_vmlinux_command),
    (re.compile(r"^rm\b"), _parse_noop),
    (re.compile(r"^mkdir\b"), _parse_noop),
    (re.compile(r"^echo[^|]*$"), _parse_noop),
    (re.compile(r"^(/bin/)?true\b"), _parse_noop),
    (re.compile(r"^(/bin/)?false\b"), _parse_noop),
    (re.compile(r"^ar\b"), _parse_ar_command),
    (re.compile(r"^printf\b.*\| xargs ar\b"), _parse_ar_piped_command),
    (re.compile(r"^gcc\b"), _parse_gcc_command),
    (re.compile(r"sh (.*/)?syscallhdr\.sh\b"), _parse_syscallhdr_command),
    (re.compile(r"sh (.*/)?syscalltbl\.sh\b"), _parse_syscalltbl_command),
    (re.compile(r"sh (.*/)?mkcapflags\.sh\b"), _parse_mkcapflags_command),
    (re.compile(r"sh (.*/)?orc_hash\.sh\b"), _parse_orc_hash_command),
    (re.compile(r"(.*/)?vdso2c\b"), _parse_vdso2c_command),
    (re.compile(r"(.*/)?genheaders\b"), _parse_genheaders_command),
    (re.compile(r"^ld\b"), _parse_ld_command),
    (re.compile(r"^sed\b"), _parse_sed_command),
    (re.compile(r"^(.*/)?objtool\b"), _parse_noop),
]

# If Block pattern to match a simple, single-level if-then-fi block. Nested If blocks are not supported.
IF_BLOCK_PATTERN = re.compile(
    r"""
    ^if(.*?);\s*         # Match 'if <condition>;' (non-greedy)
    then(.*?);\s*        # Match 'then <body>;' (non-greedy)
    fi\b                 # Match 'fi'
    """,
    re.VERBOSE,
)


@dataclass
class IfBlock:
    condition: str
    then_statement: str


def _unwrap_outer_parentheses(s: str) -> str:
    s = s.strip()
    if not (s.startswith("(") and s.endswith(")")):
        return s

    count = 0
    for i, char in enumerate(s):
        if char == "(":
            count += 1
        elif char == ")":
            count -= 1
            # If count is 0 before the end, outer parentheses don't match
            if count == 0 and i != len(s) - 1:
                return s

    # outer parentheses do match, unwrap once
    return _unwrap_outer_parentheses(s[1:-1])


def _split_commands(commands: str) -> list[str | IfBlock]:
    single_commands: list[str | IfBlock] = []
    remaining_command = _unwrap_outer_parentheses(commands)
    while len(remaining_command) > 0:
        remaining_command = remaining_command.strip()

        # if block
        matched_if = IF_BLOCK_PATTERN.match(remaining_command)
        if matched_if:
            condition, then_statement = matched_if.groups()
            single_commands.append(IfBlock(condition.strip(), then_statement.strip()))
            full_matched = matched_if.group(0)
            remaining_command = remaining_command.removeprefix(full_matched).lstrip("; \n")
            continue

        # command until next semicolon
        if ";" in remaining_command:
            single_command, remaining_command = remaining_command.split(";", maxsplit=1)
            single_commands.append(single_command)
            continue

        single_commands.append(remaining_command)
        break
    return single_commands


def parse_commands(commands: str) -> list[Path]:
    """
    Parses a collection of command line commands separated by semicolon and returns the combined input files required for these commands.

    Returns:
        input_files (list[str]): Input files of the commands.
    """
    input_files: list[Path] = []
    for single_command in _split_commands(commands):
        if isinstance(single_command, IfBlock):
            inputs = parse_commands(single_command.then_statement)
            if inputs:
                raise NotImplementedError(
                    f"Input files in IfBlock 'then' statement are not supported: {single_command.then_statement}"
                )
            continue

        matched_parser = next(
            (parser for pattern, parser in SINGLE_COMMAND_PARSERS if pattern.match(single_command)), None
        )
        if matched_parser is None:
            raise NotImplementedError(f"No parser matched command: {single_command}")
        inputs = matched_parser(single_command)
        input_files.extend(inputs)
    return input_files
