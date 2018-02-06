# Copyright (C) 2017-2018 nickolas360 <contact@nickolas360.com>
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
# along with Harmony.  If not, see <http://www.gnu.org/licenses/>.

from .harmony import InteractiveDiscord, __version__
import sys


def usage(exit=True):
    print("Usage:", file=sys.stderr)
    print("  harmony.py [--debug]", file=sys.stderr)
    print("  harmony.py -h | --help | --version", file=sys.stderr)
    if exit:
        sys.exit(1)


def main():
    args = sys.argv[1:]
    if len(args) == 1 and args[0] == "--version":
        print(__version__)
        return

    debug = True
    try:
        args.pop(args.index("--debug"))
    except ValueError:
        debug = False

    if args:
        usage()
    interactive = InteractiveDiscord(debug=debug)
    interactive.command_loop()


if __name__ == "__main__":
    main()
