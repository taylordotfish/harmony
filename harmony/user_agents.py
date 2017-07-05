# Copyright (C) 2017 nickolas360 <contact@nickolas360.com>
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
        "like Gecko) Chrome/58.0.3029.110 Safari/537.36",
        {"os": "Windows", "browser": "Chrome", "device": ""},
    ),
    (
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, "
        "like Gecko) Chrome/58.0.3029.110 Safari/537.36",
        {"os": "Windows", "browser": "Chrome", "device": ""},
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
        {"os": "Mac OS X", "browser": "Chrome", "device": ""},
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/603.2.4 "
        "(KHTML, like Gecko) Version/10.1.1 Safari/603.2.4",
        {"os": "Mac OS X", "browser": "Safari", "device": ""},
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 "
        "Firefox/53.0",
        {"os": "Windows", "browser": "Firefox", "device": ""},
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
        {"os": "Mac OS X", "browser": "Chrome", "device": ""},
    ),
    (
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, "
        "like Gecko) Chrome/58.0.3029.110 Safari/537.36",
        {"os": "Windows", "browser": "Chrome", "device": ""},
    ),
    (
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 "
        "Firefox/53.0",
        {"os": "Windows", "browser": "Firefox", "device": ""},
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
        {"os": "Mac OS X", "browser": "Chrome", "device": ""},
    ),
    (
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/58.0.3029.110 Safari/537.36",
        {"os": "Windows", "browser": "Chrome", "device": ""},
    ),
    (
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like "
        "Gecko",
        {"os": "Windows", "browser": "Internet Explorer", "device": ""},
    ),
    (
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:53.0) Gecko/20100101 "
        "Firefox/53.0",
        {"os": "Linux", "browser": "Firefox", "device": ""},
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
        "Gecko) Chrome/58.0.3029.110 Safari/537.36",
        {"os": "Linux", "browser": "Chrome", "device": ""},
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:54.0) Gecko/20100101 "
        "Firefox/54.0",
        {"os": "Windows", "browser": "Firefox", "device": ""},
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
        "like Gecko) Chrome/59.0.3071.86 Safari/537.36",
        {"os": "Windows", "browser": "Chrome", "device": ""},
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:53.0) "
        "Gecko/20100101 Firefox/53.0",
        {"os": "Mac OS X", "browser": "Firefox", "device": ""},
    ),
]


def random_user_agent():
    return random.choice(USER_AGENTS)
