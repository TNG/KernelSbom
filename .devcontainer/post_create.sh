# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only

python3 -m venv .venv
source .venv/bin/activate
pip install pre-commit reuse ruff
pre-commit install
