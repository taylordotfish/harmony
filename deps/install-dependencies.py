#!/usr/bin/env python3
import os, os.path
import sys

sys.argv.insert(1, "install")
os.chdir(os.path.dirname(__file__))
os.chdir(os.pardir)

from setuptools import setup
setup()
