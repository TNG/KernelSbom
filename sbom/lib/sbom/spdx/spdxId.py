# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from itertools import count

SpdxId = str


class SpdxIdGenerator:
    _namespace: str | None = None
    _prefix: str | None = None
    _counter = count(0)

    @classmethod
    def initialize(cls, namespace: str, prefix: str | None = None) -> None:
        """
        Initialize the SPDX ID generator with a namespace.

        Args:
            namespace: The full namespace to use for generated IDs.
            prefix: Optional. If provided, generated IDs will use this prefix instead of the full namespace.
        """
        if cls._namespace is not None:
            raise RuntimeError("Already initialized")
        cls._namespace = namespace
        cls._prefix = prefix

    @classmethod
    def generate(cls) -> SpdxId:
        """generate spdxId"""
        if cls._namespace is None:
            raise RuntimeError("SpdxIdGenerator not initialized. Call initialize() first.")
        return f"{f'{cls._prefix}:' if cls._prefix else cls._namespace}{next(cls._counter)}"

    @classmethod
    def prefix(cls) -> str | None:
        """Get the current prefix."""
        if cls._namespace is None:
            raise RuntimeError("SpdxIdGenerator not initialized. Call initialize() first.")
        return cls._prefix

    @classmethod
    def namespace(cls) -> str:
        """Get the current namespace."""
        if cls._namespace is None:
            raise RuntimeError("SpdxIdGenerator not initialized. Call initialize() first.")
        return cls._namespace
