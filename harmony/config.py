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

from configparser import ConfigParser, DEFAULTSECT
from io import StringIO
import os
import os.path

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".config", "harmony.conf")


class Config:
    def __init__(self):
        self._parser = ConfigParser()
        try:
            f = open(CONFIG_PATH, encoding="utf8")
        except FileNotFoundError:
            pass
        else:
            with f:
                self._parser.read_string(
                    "[{}]\n{}".format(DEFAULTSECT, f.read()),
                )
        self._section = self._parser[DEFAULTSECT]

    @property
    def ask_to_save_passwords(self) -> bool:
        return self._section.getboolean("ask-to-save-passwords", True)

    @ask_to_save_passwords.setter
    def ask_to_save_passwords(self, value: bool):
        self._section["ask-to-save-passwords"] = str(value).lower()

    def save(self):
        out = StringIO()
        self._parser.write(out)
        text = out.getvalue().replace("[{}]".format(DEFAULTSECT), "", 1)
        text = text.strip()
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf8") as f:
            if text:
                print(text, file=f)


_config = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config()
    return _config
