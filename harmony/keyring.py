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

from typing import Optional
import keyring
import keyring.errors


Exception = keyring.errors.KeyringError


def get_saved_password(email: str) -> Optional[str]:
    return keyring.get_password("harmony", email)


def save_password(email: str, password: str):
    keyring.set_password("harmony", email, password)
