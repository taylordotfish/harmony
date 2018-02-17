#!/usr/bin/env python3
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

import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
LIBRECAPTCHA_DIR = os.path.join(SCRIPT_DIR, "librecaptcha")


def download_librecaptcha():
    try:
        if os.listdir(LIBRECAPTCHA_DIR):
            return
    except FileNotFoundError:
        pass
    subprocess.check_call([
        "git", "-C", SCRIPT_DIR, "submodule", "update", "--init",
    ])


if __name__ == "__main__":
    sys.path.insert(0, LIBRECAPTCHA_DIR)
    download_librecaptcha()
    from harmony.__main__ import main
    main()
