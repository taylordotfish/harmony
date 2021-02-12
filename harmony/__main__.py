# Copyright (C) 2017-2018 taylor.fish <contact@taylor.fish>
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

from .config import get_config
from .harmony import DiscordCli, __version__
import os.path
import readline
import sys

USAGE = """\
Usage:
  harmony.py [--debug]
  harmony.py -h | --help | --version
"""


def main():
    args = sys.argv[1:]
    if "-h" in args or "--help" in args:
        print(USAGE, end="")
        return

    if "--version" in args:
        print(__version__)
        return

    debug = True
    try:
        args.pop(args.index("--debug"))
    except ValueError:
        debug = False

    if args:
        print(USAGE, file=sys.stderr, end="")
        sys.exit(1)

    cli = DiscordCli(debug=debug)
    readline.set_auto_history(True)
    history_path = os.path.join(os.path.expanduser("~"), ".harmony_history")

    try:
        readline.read_history_file(history_path)
    except FileNotFoundError:
        pass

    try:
        cli.command_loop()
    finally:
        readline.write_history_file(history_path)
        get_config().save()


if __name__ == "__main__":
    main()
