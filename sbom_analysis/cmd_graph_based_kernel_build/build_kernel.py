# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH


from dataclasses import dataclass
from difflib import SequenceMatcher
import json
import logging
from pathlib import Path
import re
import shutil
import subprocess
from typing import Iterator


MAKE_ERROR_PATTERNS = [
    re.compile(
        r"(?P<full_error>No rule to make target '(?P<missing_file>[^']+)', needed by '(?P<reference_file>[^']+)')"
    ),
    re.compile(
        r"(?P<full_error>(?P<reference_file>\S+):\d+:\d+: fatal error: (?P<missing_file>\S+): No such file or directory)"
    ),
    re.compile(
        r"(?P<full_error>(AS|CALL)\s+(?P<reference_file>\S+)\n\S+: fatal error: (?P<missing_file>\S+): No such file or directory)"
    ),
    re.compile(
        r"(?P<full_error>LD\s+(?P<reference_file>\S+)\nld: cannot (find|open linker script file) (?P<missing_file>\S+): No such file or directory)"
    ),
    re.compile(r"(?P<full_error>\S+: \d+: cannot open (?P<missing_file>\S+): No such file)"),
]


@dataclass
class MakeError:
    message: str
    missing_file_path: Path
    reference_file: Path | None = None

    @staticmethod
    def from_log_outputs(log_outputs: list[str]) -> "MakeError":
        combined = "\n".join(log_outputs)
        for pattern in MAKE_ERROR_PATTERNS:
            match = pattern.search(combined)
            if match:
                return MakeError(
                    message=match.group("full_error"),
                    missing_file_path=Path(match.group("missing_file")),
                    reference_file=Path(match.group("reference_file"))
                    if ("reference_file" in match.re.groupindex)
                    else None,
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

    previous_make_error_missing_file_path: Path | None = None
    potential_missing_file: Path | None = None
    potential_missing_files_iterator: Iterator[Path] = iter([])
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

        is_new_error = make_error.missing_file_path != previous_make_error_missing_file_path
        if is_new_error:
            if potential_missing_file is not None:
                # potential missing file from last iteration did fix the previous error
                save_missing_file(potential_missing_file)
            logging.info(f"Build failed with: {make_error.message}")

            # Create new list of potential missing files
            logging.info("Search potential missing files")
            potential_missing_files = _get_potential_missing_files(
                make_error, src_tree, output_tree, cmd_src_tree, ignore=missing_sources_in_cmd_graph
            )

            if len(potential_missing_files) == 0:
                raise RuntimeError("No potential files found to fix the make error")
            logging.info(f"Found potential missing files: {potential_missing_files}")
            potential_missing_files_iterator = iter(potential_missing_files)
            previous_make_error_missing_file_path = make_error.missing_file_path
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
    output_lines: list[str] = []
    if process.stdout is None:
        raise RuntimeError("Failed to capture output from subprocess")
    for line in process.stdout:
        if live_output:
            print(line, end="")
        output_lines.append(line.rstrip())
    returncode = process.wait()
    return returncode, output_lines


def _get_potential_missing_files(
    make_error: MakeError,
    src_tree: Path,
    output_tree: Path,
    cmd_src_tree: Path,
    ignore: list[Path] = [],
) -> list[Path]:
    rule_based_candidates: list[Path] = []
    # Manual rules for cases that are difficult to infer from pure Make Error message
    if "include/generated/uapi/asm" in str(make_error.missing_file_path) or "include/generated/asm" in str(
        make_error.missing_file_path
    ):
        rule_based_candidates += list(src_tree.rglob(f"include/**/asm-generic/{make_error.missing_file_path.name}"))

    # Automatic search for potential missing files based on make error
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

    # filter out non promising candidates
    potential_missing_files: list[Path] = []
    for path in rule_based_candidates + additional_candidates:
        if not path.is_absolute():
            path = (src_tree / path).resolve()

        if (
            not path.is_file()
            or not path.exists()
            or not path.is_relative_to(src_tree)
            or path.is_relative_to(output_tree)
        ):
            # skip files in that do not exist of are outside the src tree
            continue

        if (cmd_src_tree / path.relative_to(src_tree)).exists():
            # skip files that are already in the cmd src tree
            continue

        if path.relative_to(src_tree) in (ignore + potential_missing_files):
            # skip files that are in the ignore list
            continue

        potential_missing_files.append(path.relative_to(src_tree))

    if make_error.reference_file is None:
        return potential_missing_files

    # Test those files first that are more similar to the reference file found in the make error.
    target_sequence = str(make_error.reference_file if make_error.reference_file else make_error.missing_file_path)
    return sorted(
        potential_missing_files,
        key=lambda p: SequenceMatcher(None, str(p), target_sequence).ratio(),
        reverse=True,
    )
