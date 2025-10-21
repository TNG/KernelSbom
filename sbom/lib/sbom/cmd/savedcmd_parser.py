# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

import logging
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


def _tokenize_single_command(command: str, flag_options: list[str] | None = None) -> list[Union[Option, Positional]]:
    """
    Parse a shell command into a list of Options and Positionals.
    - Positional: the command and any positional arguments.
    - Options: handles flags and options with values provided as space-separated, or equals-sign
        (e.g., '--opt val', '--opt=val', '--flag').

    Args:
        command: Command line string.
        flag_options: Options that are flags without values (e.g., '--verbose').

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
        if (token.startswith("-") and i + 1 < len(tokens) and tokens[i + 1].startswith("-")) or (
            flag_options and token in flag_options
        ):
            parsed.append(Option(name=token))
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


def _parse_dd_command(command: str) -> list[Path]:
    match = re.match(r"dd.*?if=(\S+)", command)
    if match:
        return [Path(match.group(1))]
    return []


def _parse_cat_command(command: str) -> list[Path]:
    if "|" in command or ">" in command:
        logging.warning(f"Skip parsing command because the given pipe/redirect destination is not supported {command}")
        return []
    positionals = _tokenize_single_command_positionals_only(command)
    # expect positionals to be ["cat", input1, input2, ...]
    return [Path(p) for p in positionals[1:]]


def _parse_compound_command(command: str) -> list[Path]:
    compound_command_parsers: list[tuple[re.Pattern[str], Callable[[str], list[Path]]]] = [
        (re.compile(r"dd\b"), _parse_dd_command),
        (re.compile(r"cat.*?|\s+sh\b.*?xz_wrap\.sh"), lambda c: _parse_cat_command(c.split("|")[0])),
        (re.compile(r"cat\b"), _parse_cat_command),
        (re.compile(r"echo\b"), _parse_noop),
        (re.compile(r"\S+="), _parse_noop),
        (re.compile(r"printf\b"), _parse_noop),
        (re.compile(r"sed\b"), _parse_sed_command),
        (
            re.compile(r"(.*/)scripts/bin2c\s*<"),
            lambda c: [Path(input)] if (input := c.split("<")[1].strip()) != "/dev/null" else [],
        ),
    ]

    match = re.match(r"\s*[\(\{](.*)[\)\}]\s*>", command, re.DOTALL)
    if match is None:
        logging.error(f"No inner commands found for compound command {command}")
        return []
    input_files: list[Path] = []
    inner_commands = _split_commands(match.group(1))
    for inner_command in inner_commands:
        if isinstance(inner_command, IfBlock):
            logging.warning(
                f"Skip parsing inner command of compound command because IfBlock is not supported {inner_command}"
            )
            continue

        parser = next((parser for pattern, parser in compound_command_parsers if pattern.match(inner_command)), None)
        if parser is None:
            logging.warning(
                f"Skip parsing inner command of compound command because no parser was found for {inner_command}"
            )
            continue
        input_files += parser(inner_command)
    return input_files


def _parse_objcopy_command(command: str) -> list[Path]:
    command_parts = _tokenize_single_command(command, flag_options=["-S", "-w"])
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


def _parse_ar_piped_xargs_command(command: str) -> list[Path]:
    printf_command, _ = command.split("|", 1)
    positionals = _tokenize_single_command_positionals_only(printf_command.strip())
    # expect positionals to be ['printf', '{prefix_path}%s ', input1, input2, ...]
    return [Path(p) for p in positionals[2:]]


def _parse_gcc_or_clang_command(command: str) -> list[Path]:
    parts = shlex.split(command)
    # compile mode: expect last positional argument ending in `.c` or `.S` to be the input file
    for part in reversed(parts):
        if not part.startswith("-") and Path(part).suffix in [".c", ".S"]:
            return [Path(part)]

    # linking mode: expect all .o files to be the inputs
    return [Path(p) for p in parts if p.endswith(".o")]


def _parse_rustc_command(command: str) -> list[Path]:
    parts = shlex.split(command)
    # expect last positional argument ending in `.rs` to be the input file
    for part in reversed(parts):
        if not part.startswith("-") and Path(part).suffix == ".rs":
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


def _parse_xen_hypercalls_command(command: str) -> list[Path]:
    positionals = _tokenize_single_command_positionals_only(command)
    # expect positionals to be ["sh", path/to/xen-hypercalls.sh, output, input1, input2, ...]
    return [Path(p) for p in positionals[3:]]


def _parse_vdso2c_command(command: str) -> list[Path]:
    positionals = _tokenize_single_command_positionals_only(command.strip())
    # expect positionals to be ['vdso2c', raw_input, stripped_input, output]
    return [Path(positionals[1]), Path(positionals[2])]


def _parse_ld_command(command: str) -> list[Path]:
    command_parts = _tokenize_single_command(
        command=command.strip(),
        flag_options=[
            "-shared",
            "--no-undefined",
            "--eh-frame-hdr",
            "-Bsymbolic",
            "-r",
            "--no-ld-generated-unwind-info",
            "--no-dynamic-linker",
            "-pie",
            "--no-dynamic-linker--whole-archive",
            "--whole-archive",
            "--no-whole-archive",
            "--start-group",
            "--end-group",
        ],
    )
    positionals = [p.value for p in command_parts if isinstance(p, Positional)]
    # expect positionals to be ["ld", input1, input2, ...]
    return [Path(p) for p in positionals[1:]]


def _parse_sed_command(command: str) -> list[Path]:
    command_parts = shlex.split(command)
    # expect command parts to be ["sed", *, input]
    input = command_parts[-1]
    if input == "/dev/null":
        return []
    return [Path(input)]


def _parse_nm_piped_command(command: str) -> list[Path]:
    nm_command, _ = command.split("|", 1)
    command_parts = _tokenize_single_command(
        command=nm_command.strip(),
        flag_options=["p", "--defined-only"],
    )
    positionals = [p.value for p in command_parts if isinstance(p, Positional)]
    # expect positionals to be ["nm", input1, input2, ...]
    return [Path(p) for p in positionals[1:]]


def _parse_pnm_to_logo_command(command: str) -> list[Path]:
    command_parts = shlex.split(command)
    # expect command parts to be ["pnmtologo", <options>, input]
    return [Path(command_parts[-1])]


def _parse_perl_command(command: str) -> list[Path]:
    positionals = _tokenize_single_command_positionals_only(command.strip())
    # expect positionals to be ["perl", input]
    return [Path(positionals[1])]


def _parse_strip_command(command: str) -> list[Path]:
    command_parts = _tokenize_single_command(command, flag_options=["--strip-debug"])
    positionals = [p.value for p in command_parts if isinstance(p, Positional)]
    # expect positionals to be ["strip", input1, input2, ...]
    return [Path(p) for p in positionals[1:]]


def _parse_mkpiggy_command(command: str) -> list[Path]:
    mkpiggy_command, _ = command.split(">", 1)
    positionals = _tokenize_single_command_positionals_only(mkpiggy_command)
    # expect positionals to be ["mkpiggy", input]
    return [Path(positionals[1])]


def _parse_relocs_command(command: str) -> list[Path]:
    if ">" not in command:
        # Only consider relocs commands that redirect output to a file.
        # If there's no redirection, we assume it produces no output file and therefore has no input we care about.
        return []
    relocs_command, _ = command.split(">", 1)
    command_parts = shlex.split(relocs_command)
    # expect command_parts to be ["relocs", options, input]
    return [Path(command_parts[-1])]


def _parse_mk_elfconfig_command(command: str) -> list[Path]:
    positionals = _tokenize_single_command_positionals_only(command)
    # expect positionals to be ["mk_elfconfig", "<", input, ">", output]
    return [Path(positionals[2])]


def _parse_flex_command(command: str) -> list[Path]:
    parts = shlex.split(command)
    # expect last positional argument ending in `.l` to be the input file
    for part in reversed(parts):
        if not part.startswith("-") and Path(part).suffix in [".l"]:
            return [Path(part)]
    raise ValueError(f"Could not find input source file in command: {command}")


def _parse_bison_command(command: str) -> list[Path]:
    parts = shlex.split(command)
    # expect last positional argument ending in `.y` to be the input file
    for part in reversed(parts):
        if not part.startswith("-") and Path(part).suffix in [".y"]:
            return [Path(part)]
    raise ValueError(f"Could not find input source file in command: {command}")


def _parse_tools_build_command(command: str) -> list[Path]:
    positionals = _tokenize_single_command_positionals_only(command)
    # expect positionals to be ["tools/build", "input1", "input2", "input3", "output"]
    return [Path(p) for p in positionals[1:-1]]


# Command parser registry
SINGLE_COMMAND_PARSERS: list[tuple[re.Pattern[str], Callable[[str], list[Path]]]] = [
    (re.compile(r"\(.*?\)\s*>", re.DOTALL), _parse_compound_command),
    (re.compile(r"\{.*?\}\s*>", re.DOTALL), _parse_compound_command),
    (re.compile(r"^(llvm-)?objcopy\b"), _parse_objcopy_command),
    (re.compile(r"^(.*/)?link-vmlinux\.sh\b"), _parse_link_vmlinux_command),
    (re.compile(r"^rm\b"), _parse_noop),
    (re.compile(r"^mkdir\b"), _parse_noop),
    (re.compile(r"^echo[^|]*$"), _parse_noop),
    (re.compile(r"^(/bin/)?true\b"), _parse_noop),
    (re.compile(r"^(/bin/)?false\b"), _parse_noop),
    (re.compile(r"^(llvm-)?ar\b"), _parse_ar_command),
    (re.compile(r"^printf\b.*\| xargs (llvm-)?ar\b"), _parse_ar_piped_xargs_command),
    (re.compile(r"^(gcc|clang)\b"), _parse_gcc_or_clang_command),
    (re.compile(r".*rustc\b"), _parse_rustc_command),
    (re.compile(r"sh (.*/)?syscallhdr\.sh\b"), _parse_syscallhdr_command),
    (re.compile(r"sh (.*/)?syscalltbl\.sh\b"), _parse_syscalltbl_command),
    (re.compile(r"sh (.*/)?mkcapflags\.sh\b"), _parse_mkcapflags_command),
    (re.compile(r"sh (.*/)?orc_hash\.sh\b"), _parse_orc_hash_command),
    (re.compile(r"sh (.*/)?xen-hypercalls\.sh\b"), _parse_xen_hypercalls_command),
    (re.compile(r"(.*/)?vdso2c\b"), _parse_vdso2c_command),
    (re.compile(r"(.*/)?genheaders\b"), _parse_noop),
    (re.compile(r"^(.*/)?mkcpustr\s+>"), _parse_noop),
    (re.compile(r"^ld\b"), _parse_ld_command),
    (re.compile(r"^sed.*?>"), lambda c: _parse_sed_command(c.split(">")[0])),
    (re.compile(r"^(.*/)?objtool\b"), _parse_noop),
    (re.compile(r"^(llvm-)?nm\b.*?\|"), _parse_nm_piped_command),
    (re.compile(r"^(.*/)?pnmtologo\b"), _parse_pnm_to_logo_command),
    (re.compile(r"^perl\b"), _parse_perl_command),
    (re.compile(r"^(.*/)polgen\b"), _parse_noop),
    (re.compile(r"^(llvm-)?strip\b"), _parse_strip_command),
    (re.compile(r"^(.*/)?mkpiggy.*?>"), _parse_mkpiggy_command),
    (re.compile(r"^cat\b.*?[\|>]"), lambda c: _parse_cat_command(c.split("|")[0].split(">")[0])),
    (re.compile(r"^(.*/)?relocs\b"), _parse_relocs_command),
    (re.compile(r"^(.*/)?mk_elfconfig.*?<.*?>"), _parse_mk_elfconfig_command),
    (re.compile(r"^flex\b"), _parse_flex_command),
    (re.compile(r"^bison\b"), _parse_bison_command),
    (re.compile(r"^(.*/)?tools/build\b"), _parse_tools_build_command),
    (re.compile(r"make -f .*/arch/x86/Makefile\.postlink"), _parse_noop),
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


def _find_first_top_level_semicolon_position(commands: str) -> int | None:
    in_single_quote = False
    in_double_quote = False
    in_curly_braces = 0
    in_braces = 0
    for i, char in enumerate(commands):
        if char == "'" and not in_double_quote:
            # Toggle single quote state (unless inside double quotes)
            in_single_quote = not in_single_quote
        elif char == '"' and not in_single_quote:
            # Toggle double quote state (unless inside single quotes)
            in_double_quote = not in_double_quote

        if in_single_quote or in_double_quote:
            continue

        # Toggle braces state
        if char == "{":
            in_curly_braces += 1
        if char == "}":
            in_curly_braces -= 1

        if char == "(":
            in_braces += 1
        if char == ")":
            in_braces -= 1

        elif char == ";" and in_curly_braces == 0 and in_braces == 0:
            # Found top level semicolon
            return i

    return None


def _split_commands(commands: str) -> list[str | IfBlock]:
    single_commands: list[str | IfBlock] = []
    remaining_commands = _unwrap_outer_parentheses(commands)
    while len(remaining_commands) > 0:
        remaining_commands = remaining_commands.strip()

        # if block
        matched_if = IF_BLOCK_PATTERN.match(remaining_commands)
        if matched_if:
            condition, then_statement = matched_if.groups()
            single_commands.append(IfBlock(condition.strip(), then_statement.strip()))
            full_matched = matched_if.group(0)
            remaining_commands = remaining_commands.removeprefix(full_matched).lstrip("; \n")
            continue

        # command until next semicolon
        found_semicolon_pos = _find_first_top_level_semicolon_position(remaining_commands)
        if found_semicolon_pos is not None:
            single_commands.append(remaining_commands[:found_semicolon_pos].strip())
            remaining_commands = remaining_commands[found_semicolon_pos + 1 :].strip()
            continue

        # single last command
        single_commands.append(remaining_commands)
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
                logging.warning(
                    f"Skip command because input files in IfBlock 'then' statement are not supported: {single_command.then_statement}"
                )
            continue

        matched_parser = next(
            (parser for pattern, parser in SINGLE_COMMAND_PARSERS if pattern.match(single_command)), None
        )
        if matched_parser is None:
            logging.warning(f"Skipped parsing command because no matching parser was found for: {single_command}")
            continue
        inputs = matched_parser(single_command)
        input_files.extend(inputs)
    return input_files
