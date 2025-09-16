# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH <info@tngtech.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import unittest

class TestHelloWorld(unittest.TestCase):
    def test_hello(self):
        greeting = "Hello, World!"
        self.assertEqual(greeting, "Hello, World!")

if __name__ == '__main__':
    unittest.main()
