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

import random

# From <https://techblog.willshouse.com/2012/01/03/most-common-user-agents/>
USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
        "like Gecko) Chrome/63.0.3239.132 Safari/537.36",
        {"os": "Windows", "browser": "Chrome", "device": ""}
    ),
    (
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, "
        "like Gecko) Chrome/63.0.3239.132 Safari/537.36",
        {"os": "Windows", "browser": "Chrome", "device": ""}
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
        {"os": "Mac OS X", "browser": "Chrome", "device": ""}
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 "
        "Firefox/57.0",
        {"os": "Windows", "browser": "Firefox", "device": ""}
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
        {"os": "Mac OS X", "browser": "Chrome", "device": ""}
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/604.4.7 "
        "(KHTML, like Gecko) Version/11.0.2 Safari/604.4.7",
        {"os": "Mac OS X", "browser": "Safari", "device": ""}
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 "
        "Firefox/58.0",
        {"os": "Windows", "browser": "Firefox", "device": ""}
    ),
    (
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, "
        "like Gecko) Chrome/63.0.3239.132 Safari/537.36",
        {"os": "Windows", "browser": "Chrome", "device": ""}
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
        "like Gecko) Chrome/64.0.3282.140 Safari/537.36",
        {"os": "Windows", "browser": "Chrome", "device": ""}
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
        "Gecko) Chrome/63.0.3239.132 Safari/537.36",
        {"os": "Linux", "browser": "Chrome", "device": ""}
    ),
]


def random_user_agent():
    return random.choice(USER_AGENTS)
