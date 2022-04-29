#!/usr/bin/env python3
# Copyright (C) 2016-2018, 2021 taylor.fish <contact@taylor.fish>
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

from setuptools import setup
import os

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
REPO_URL = "https://github.com/taylordotfish/harmony"
DESC_REPLACEMENTS = {
    ".. _LICENSE: LICENSE":
    ".. _LICENSE: {}/blob/master/LICENSE".format(REPO_URL),
}


def long_description():
    with open(os.path.join(SCRIPT_DIR, "README.rst"), encoding='utf-8') as f:
        lines = f.read().splitlines()
    result = []
    for line in lines:
        result.append(DESC_REPLACEMENTS.get(line, line) + "\n")
    return "".join(result)


LICENSE = """\
License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)\
"""


setup(
    name="harmony-discord",
    version="0.7.2",
    description=(
        "A free/libre program for performing various tasks with Discord."
    ),
    long_description=long_description(),
    url="https://github.com/taylordotfish/harmony",
    author="taylor.fish",
    author_email="contact@taylor.fish",
    license="GNU General Public License v3 or later (GPLv3+)",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Internet", LICENSE,
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
    keywords="discord",
    packages=["harmony"],
    entry_points={
        "console_scripts": [
            "harmony=harmony:main",
        ],
    },
    install_requires=[
        "Pillow>=4.1.1",
        "requests>=2.18.1,<3",
        "librecaptcha[gtk]>=0.6.3,<1",
        "keyring>=17.0.0",
    ],
    python_requires=">=3.5",
)
