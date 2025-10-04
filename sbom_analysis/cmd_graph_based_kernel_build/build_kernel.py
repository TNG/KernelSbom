#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only


from dataclasses import dataclass
from difflib import SequenceMatcher
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess


STRACE_POTENTIAL_MISSING_FILE_PATTERN = re.compile(r'(?:openat|newfstatat)\(.*?,\s+"([^"]+)"')

MAKE_ERROR_PATTERNS = [
    re.compile(
        r"(?P<full_error>No rule to make target '(?P<missing_file>[^']+)', needed by '(?P<reference_file>[^']+)')"
    ),
    re.compile(
        r"(?P<full_error>(?P<reference_file>[^\s:]+):\d+:\d+: fatal error: (?P<missing_file>[^\s:]+): No such file or directory)"
    ),
    re.compile(
        r"(?P<full_error>LD\s+(?P<reference_file>[^\s]+)\nld: cannot find (?P<missing_file>[^\s:]+): No such file or directory)"
    ),
    # re.compile(r"(No rule to make target '([^'\s]+)')"),
    # re.compile(r"(cannot find ([^'\s]+): No such file or directory)"),
    # re.compile(r"(cannot open ([^'\s]+): No such file)"),
    # re.compile(r"(note: .*? is defined in header ‘<([^>]+)>’; did you forget to ‘#include <[^>]+>’)"),
    # re.compile(r"(cannot open linker script file.*?write\(2, \"([^\"]+)\".*?\))", re.DOTALL),
]


@dataclass
class MakeError:
    message: str
    missing_file_path: Path
    reference_file: Path

    @staticmethod
    def from_log_outputs(log_outputs: list[str]) -> "MakeError":
        combined = "\n".join(log_outputs)
        for pattern in MAKE_ERROR_PATTERNS:
            match = pattern.search(combined)
            if match:
                return MakeError(
                    message=match.group("full_error"),
                    missing_file_path=Path(match.group("missing_file")),
                    reference_file=Path(match.group("reference_file")),
                )
        raise NotImplementedError("Build failed, but no make error could be detected.")


def build_kernel(
    missing_sources_in_cmd_graph: list[Path],
    cmd_src_tree: Path,
    cmd_output_tree: Path,
    src_tree: Path,
    output_tree: Path,
    missing_sources_in_cmd_graph_path: Path,
) -> None:
    def save_missing_file(missing_file: Path) -> None:
        logging.info(f"Successfully fixed make error with: {missing_file}.")
        missing_sources_in_cmd_graph.append(missing_file)
        with open(missing_sources_in_cmd_graph_path, "wt") as f:
            json.dump([str(source_file) for source_file in missing_sources_in_cmd_graph], f, indent=2)
        logging.info(f"Saved {potential_missing_file} in {missing_sources_in_cmd_graph_path}")

    previous_make_error_message: str | None = None
    potential_missing_file: Path | None = None
    while True:
        logging.info("Build kernel")
        returncode, log_outputs = _run_command(
            ["make", f"O={cmd_output_tree.relative_to(cmd_src_tree)}"], cmd_src_tree, live_output=True
        )
        if returncode == 0:
            if potential_missing_file is not None:
                save_missing_file(potential_missing_file)
            logging.info("Successfully built kernel")
            return

        make_error = MakeError.from_log_outputs(log_outputs)

        is_new_error = make_error.message != previous_make_error_message
        if is_new_error:
            if potential_missing_file is not None:
                # potential missing file from last iteration did fix the previous error
                save_missing_file(potential_missing_file)
            logging.info(f"Build failed with: {make_error.message}")

            # Create new list of potential missing files
            # logging.info("Reinvoke make with strace for further analysis")
            # _, strace_outputs = _run_command(
            #     f"strace -f -s 1024 make O={cmd_output_tree.relative_to(cmd_src_tree)}".split(" "),
            #     cmd_src_tree,
            # )
            # strace_log_path = Path(__file__).parent / "strace.log"
            # with open(strace_log_path, "wt") as f:
            #     f.write("\n".join(strace_outputs))
            # logging.info(f"Saved strace log to {strace_log_path}")
            # logging.info("Search potential missing files")
            # potential_missing_files = _get_potential_missing_files(
            #     strace_outputs, make_error, src_tree, output_tree, ignore=missing_sources_in_cmd_graph
            # )

            # without strace
            logging.info("Search potential missing files")
            potential_missing_files = _get_potential_missing_files_without_strace(
                make_error, src_tree, output_tree, ignore=missing_sources_in_cmd_graph
            )

            if len(potential_missing_files) == 0:
                raise RuntimeError("No potential files found to fix the make error")
            logging.info(f"Found potential missing files: {potential_missing_files}")
            potential_missing_files_iterator = iter(potential_missing_files)
            previous_make_error_message = make_error.message
        elif potential_missing_file:
            # delete previously copied file which did not fix the make error
            logging.info(f"Failed to fix make error with: {potential_missing_file}")
            (cmd_src_tree / potential_missing_file).unlink()

        # copy new candidate if there are any remaining
        potential_missing_file = next(potential_missing_files_iterator, None)
        if potential_missing_file is None:
            raise RuntimeError("Found no file in the source tree that could fix the build error.")
        logging.info(f"Attempting to fix make error with: {potential_missing_file}")
        shutil.copy2(src_tree / potential_missing_file, cmd_src_tree / potential_missing_file)


def _run_command(cmd: list[str], cwd: Path, live_output: bool = False) -> tuple[int, list[str]]:
    process = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    output_lines = []
    if process.stdout is None:
        raise RuntimeError("Failed to capture output from subprocess")
    for line in process.stdout:
        if live_output:
            print(line, end="")
        output_lines.append(line.rstrip())
    returncode = process.wait()
    return returncode, output_lines


def _get_potential_missing_files(
    strace_outputs: list[str],
    make_error: MakeError,
    src_tree: Path,
    output_tree: Path,
    ignore: list[Path] = [],
) -> list[Path]:
    rule_based_candidates: list[Path] = []
    # Manual rules that are typically not in the strace output
    if "include/generated/uapi/asm" in str(make_error.missing_file_path) or "include/generated/asm" in str(
        make_error.missing_file_path
    ):
        rule_based_candidates += list(src_tree.rglob(f"include/**/asm-generic/{make_error.missing_file_path.name}"))
    suffix_replacements = [
        (".s", ".c"),
        (".o", ".c"),
        (".o", ".S"),
        (".lds", ".lds.S"),
    ]
    for suffix, suffix_replacement in suffix_replacements:
        if make_error.missing_file_path.name.endswith(suffix):
            rule_based_candidates.append(Path(str(make_error.missing_file_path).replace(suffix, suffix_replacement)))

    # Automatic extraction from strace output
    strace_candidates = re.findall(STRACE_POTENTIAL_MISSING_FILE_PATTERN, "".join(strace_outputs))
    strace_candidates_reversed = [Path(p) for p in reversed(strace_candidates)]
    potential_missing_files: list[Path] = []
    for path in rule_based_candidates + strace_candidates_reversed:
        try:
            if path.is_absolute() and path.exists():
                ...
            elif (src_tree / path).exists():
                path = (src_tree / path).resolve()
            elif (output_tree / path).exists():
                path = (output_tree / path).resolve()
            else:
                continue
        except OSError:
            continue

        if (
            path.is_file()
            and path.is_relative_to(src_tree)
            and not path.is_relative_to(output_tree)
            and path.relative_to(src_tree) not in (ignore + potential_missing_files)
            and path.name.split(".")[0] == make_error.missing_file_path.name.split(".")[0]
        ):
            potential_missing_files.append(path.relative_to(src_tree))

    return potential_missing_files


def _get_potential_missing_files_without_strace(
    make_error: MakeError,
    src_tree: Path,
    output_tree: Path,
    ignore: list[Path] = [],
) -> list[Path]:
    rule_based_candidates: list[Path] = []
    # Manual rules that are typically not in the strace output
    if "include/generated/uapi/asm" in str(make_error.missing_file_path) or "include/generated/asm" in str(
        make_error.missing_file_path
    ):
        rule_based_candidates += list(src_tree.rglob(f"include/**/asm-generic/{make_error.missing_file_path.name}"))

    # Automatic extraction from strace output
    suffix_replacements = [
        (".s", ".c"),
        (".o", ".c"),
        (".o", ".S"),
        (".lds", ".lds.S"),
    ]
    additional_candidates = list(src_tree.rglob(make_error.missing_file_path.name))
    for suffix, suffix_replacement in suffix_replacements:
        if make_error.missing_file_path.name.endswith(suffix):
            additional_candidates += list(
                src_tree.rglob(make_error.missing_file_path.name.replace(suffix, suffix_replacement))
            )

    potential_missing_files: list[Path] = []
    for path in rule_based_candidates + additional_candidates:
        try:
            if path.is_absolute() and path.exists():
                ...
            elif (src_tree / path).exists():
                path = (src_tree / path).resolve()
            elif (output_tree / path).exists():
                path = (output_tree / path).resolve()
            else:
                continue
        except OSError:
            continue

        if (
            path.is_file()
            and path.is_relative_to(src_tree)
            and not path.is_relative_to(output_tree)
            and path.relative_to(src_tree) not in (ignore + potential_missing_files)
        ):
            potential_missing_files.append(path.relative_to(src_tree))

    return sorted(
        potential_missing_files,
        key=lambda p: SequenceMatcher(None, str(p), str(make_error.reference_file)).ratio(),
        reverse=True,
    )


def find_candidates_for_fixing_make_error(make_error_path: Path, src_tree: Path, output_tree: Path) -> list[Path]:
    """
    This function searches for candidate files that potentially fix the make error

    make_error_path is the path that is mentioned in the make error message.

    Returns
    candidate_files (list[Path])   list of potential files that are missing and caused make to fail. paths are provided relative to src_tree
    """
    candidate_files: list[Path] = []
    _make_error_path = Path(*make_error_path.parts)
    while len(candidate_files) == 0:
        logging.info(f"Searching src_tree for {_make_error_path}")
        candidate_files = [
            Path(os.path.relpath(found_source, src_tree))
            for found_source in src_tree.rglob(str(_make_error_path))
            if not found_source.is_relative_to(output_tree)
        ]
        _make_error_path = Path(*_make_error_path.parts[1:])
        if len(_make_error_path.parts) == 0:
            break

    if len(candidate_files) > 0:
        return candidate_files

    suffix_replacements = [
        (".s", ".c"),
        (".o", ".c"),
        (".o", ".S"),
        (".lds", ".lds.S"),
    ]
    for suffix, replacement_suffix in suffix_replacements:
        if not make_error_path.name.endswith(suffix):
            continue
        replaced_path = make_error_path.parent / make_error_path.name.replace(suffix, replacement_suffix)
        candidate_files += find_candidates_for_fixing_make_error(replaced_path, src_tree, output_tree)
    return candidate_files
