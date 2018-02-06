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
# along with Harmony.  If not, see <http://www.gnu.org/licenses/>.

from requests.exceptions import HTTPError
import requests

import base64
import json
import sys

__version__ = "0.3.0"
BASE_URL = "https://discordapp.com/api/v6/"
PROJECT_URL = "https://github.com/taylordotfish/harmony"
USER_AGENT = "DiscordBot ({}, {})".format(PROJECT_URL, __version__)


def get_full_url(url):
    return BASE_URL.rstrip("/") + "/" + url


def patch_json_method(response):
    old_json = response.json

    def json(default=dict, **kwargs):
        if not response.text:
            return None if default is None else default()
        return old_json(**kwargs)

    response.json = json
    return response


class Discord:
    def __init__(self, browser_user_agent, super_properties,
                 user_agent=USER_AGENT, debug=False):
        self.user_agent = user_agent
        self.browser_user_agent = browser_user_agent
        self.super_properties = super_properties
        self._debug = debug

        self.super_properties.setdefault("referrer", "")
        self.super_properties.setdefault("referring_domain", "")

        self.token = None
        self.fingerprint = None

    def debug(self, *args, **kwargs):
        if self._debug:
            print(*args, file=sys.stderr, **kwargs)

    def get_headers(self, headers, auth, browser):
        if browser:
            self.ensure_browser_ua()

        headers = headers or {}
        user_agent = self.browser_user_agent if browser else self.user_agent
        headers.setdefault("User-Agent", user_agent)

        if auth and self.token:
            headers.setdefault("Authorization", self.token)

        if browser:
            if "X-Super-Properties" not in headers:
                headers["X-Super-Properties"] = base64.b64encode(json.dumps(
                    self.super_properties, separators=",:",
                ).encode()).decode()
            if "X-Fingerprint" not in headers:
                headers["X-Fingerprint"] = self.get_or_request_fingerprint()
            headers.setdefault("Origin", "https://discordapp.com")
        return headers

    def http_request(self, func, url, *, headers=None, allow_errors=None,
                     auth=False, browser=False, no_debug_response=False,
                     **kwargs):
        if browser:
            self.ensure_browser_ua()
        headers = self.get_headers(headers, auth, browser)

        method = func.__name__
        r = func(get_full_url(url), headers=headers, **kwargs)

        self.debug("[http] [{}] {}".format(method, r.url))
        self.debug("[http] [{}] [headers] {!r}".format(method, headers))
        if "data" in kwargs:
            data = kwargs["data"]
            self.debug("[http] [{}] [data] {!r}".format(method, data))
        if "json" in kwargs:
            json_data = kwargs["json"]
            self.debug("[http] [{}] [json] {!r}".format(method, json_data))
        self.debug("[http] [{}] [status code] {}".format(
            method, r.status_code,
        ))

        if not no_debug_response:
            self.debug("[http] [{}] [response] {}".format(method, r.text))

        if allow_errors is True or r.status_code in (allow_errors or {}):
            return r

        try:
            r.raise_for_status()
        except HTTPError as e:
            try:
                json_data = r.json()
            except ValueError:
                json_data = None

            args = list(e.args)
            message = (args[0] or "") if args else ""
            args[0] = message + "\nReceived data from server: {}".format(
                json.dumps(json_data, indent=4),
            )

            e.args = tuple(args)
            raise e
        return patch_json_method(r)

    def get(self, *args, **kwargs):
        return self.http_request(requests.get, *args, **kwargs)

    def post(self, *args, **kwargs):
        return self.http_request(requests.post, *args, **kwargs)

    def patch(self, *args, **kwargs):
        return self.http_request(requests.patch, *args, **kwargs)

    def ensure_browser_ua(self):
        if self.browser_user_agent is None or self.super_properties is None:
            raise TypeError(
                "Browser user-agent and super properties must be set.",
            )

    def request_fingerprint(self):
        r = self.get("experiments", headers={
            "X-Context-Properties": base64.b64encode(
                json.dumps({"location": "Login"}, separators=",:").encode(),
            ).decode(),
            "Referer": "https://discordapp.com/login",
            "X-Fingerprint": None,
        }, browser=True)
        self.fingerprint = r.json()["fingerprint"]

    def get_or_request_fingerprint(self):
        if self.fingerprint is None:
            self.request_fingerprint()
        return self.fingerprint

    @property
    def logged_in(self):
        return self.token is not None

    def log_in(self, email, password, captcha_key=None):
        r = self.post("auth/login", json={
            "email": email,
            "password": password,
            "captcha_key": captcha_key,
        }, allow_errors={400})

        if r.ok:
            self.token = r.json()["token"]
        # Returns form errors if invalid; {"token": "..."} otherwise
        return (r.ok, r.json())

    def log_out(self):
        self.token = None

    def register(self, username, password, email, captcha_key=None,
                 invite=None):
        headers = {"Referer": "https://discordapp.com/register"}
        r = self.post("auth/register", json={
            "fingerprint": self.get_or_request_fingerprint(),
            "email": email,
            "username": username,
            "password": password,
            "invite": invite,
            "captcha_key": captcha_key,
        }, headers=headers, allow_errors={400}, browser=True)
        # Returns form errors if invalid; {"token": "..."} otherwise
        return (r.ok, r.json())

    def verify_email(self, token, captcha_key=None):
        headers = {"Referer": "https://discordapp.com/verify?token=" + token}
        r = self.post("auth/verify", json={
            "token": token,
            "captcha_key": captcha_key,
        }, headers=headers, allow_errors={400}, browser=True)
        # Returns form errors if invalid; {"token": "..."} otherwise
        return (r.ok, r.json())

    def resend_verification_email(self):
        r = self.post("auth/verify/resend", auth=True)
        return (r.ok, None)

    def authorize_ip(self, token, captcha_key=None):
        headers = {
            "Referer": "https://discordapp.com/authorize-ip?token=" + token,
        }

        data = {"token": token}
        if captcha_key is not None:
            data["captcha_key"] = captcha_key

        r = self.post(
            "auth/authorize-ip", json=data, headers=headers,
            allow_errors={400}, browser=True,
        )
        return (r.ok, r.json())

    def get_account_details(self):
        r = self.get("users/@me", auth=True)
        return (r.ok, r.json())

    def set_account_details(
            self, username, email, avatar, password, new_password=None):
        r = self.patch("users/@me", auth=True, json={
            "username": username,
            "email": email,
            "avatar": avatar,
            "password": password,
            "new_password": new_password,
        }, allow_errors={400})
        # Returns form errors if invalid; new account details otherwise
        return (r.ok, r.json())

    def get_settings(self):
        r = self.get("users/@me/settings", auth=True)
        return (r.ok, r.json())

    def set_settings(
            self, explicit_filter, allow_dms, friend_all, friend_mutual,
            friend_mutual_guild):
        settings = {}
        if explicit_filter is not None:
            if not (0 <= explicit_filter <= 2):
                raise ValueError("Explicit filter must be from 0 to 2.")
            settings["explicit_content_filter"] = explicit_filter
        if allow_dms is not None:
            settings["default_guilds_restricted"] = not allow_dms
        if not (friend_all is friend_mutual is friend_mutual_guild):
            friend_all = friend_all and friend_mutual and friend_mutual_guild
            settings["friend_source_flags"] = {
                "all": bool(friend_all),
                "mutual_friends": bool(friend_mutual),
                "mutual_guilds": bool(friend_mutual_guild),
            }

        r = self.patch("users/@me/settings", auth=True, json=settings)
        # Returns form errors if invalid; new settings otherwise
        return (r.ok, r.json())
