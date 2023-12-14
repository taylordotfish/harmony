"""Harmony configuration management."""
# Copyright (C) 2021 taylor.fish <contact@taylor.fish>
#
# This file is part of Harmony.
#
# Harmony is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Harmony is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Harmony.  If not, see <https://www.gnu.org/licenses/>.

import os
import os.path
from configparser import DEFAULTSECT, ConfigParser
from io import StringIO

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".config", "harmony.conf")


class Config:
    """Harmony configuration."""

    def __init__(self):
        self._parser = ConfigParser()
        try:
            f = open(CONFIG_PATH, encoding="utf8")
        except FileNotFoundError:
            pass
        else:
            with f:
                self._parser.read_string(
                    f"[{DEFAULTSECT}]\n{f.read()}",
                )
        self._section = self._parser[DEFAULTSECT]

    @property
    def ask_to_save_passwords(self) -> bool:
        """Get ask_to_save_passwords property"""
        return self._section.getboolean("ask-to-save-passwords", True)

    @ask_to_save_passwords.setter
    def ask_to_save_passwords(self, value: bool):
        """Set ask_to_save_passwords property."""
        self._section["ask-to-save-passwords"] = str(value).lower()

    def save(self):
        """Write configuration in file."""
        out = StringIO()
        self._parser.write(out)
        text = out.getvalue().replace(f"[{DEFAULTSECT}]", "", 1)
        text = text.strip()
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf8") as f:
            if text:
                print(text, file=f)


# pylint: disable=C0103
_config = None


def get_config() -> Config:
    """Returns the configuration or initialize it."""
    global _config  # pylint: disable=global-statement
    if _config is None:
        _config = Config()
    return _config
