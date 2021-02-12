# Copyright (C) 2017-2019 taylor.fish <contact@taylor.fish>
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

from requests.exceptions import HTTPError
import requests

import base64
import enum
import json
import re
import sys

BASE_URL = "https://discordapp.com/api/v8/"
CLIENT_BUILD_NUMBER = 75681


class GenericResponse:
    def __init__(self, http_response):
        self.success = http_response.ok
        self.status_code = http_response.status_code
        self.json = http_response.json()
        self.text = http_response.text

    @property
    def formatted_json(self):
        return json.dumps(self.json, indent=4)

    @property
    def needs_captcha(self):
        return not self.success and "captcha_key" in self.json

    @property
    def invalid_captcha(self):
        if self.success:
            return False
        try:
            return "incorrect-captcha-sol" in self.json["captcha_key"]
        except (AttributeError, IndexError, KeyError, TypeError):
            return False

    @property
    def ratelimited(self):
        return self.status_code == 429

    @property
    def retry_ms(self):
        return self.json["retry_after"]


class ResponseWithToken(GenericResponse):
    @property
    def token(self):
        return self.json["token"]

    @property
    def token_or_none(self):
        try:
            return self.token
        except KeyError:
            return None

    @property
    def has_token(self):
        return "token" in self.json


class LogInResponse(ResponseWithToken):
    @property
    def new_location(self):
        return bool(re.search(
            r"\b(account_login_verification_email|new login location)\b",
            self.text,
            re.I,
        ))

    @property
    def deletion_scheduled(self):
        return not self.success and self.json.get("code") == 20011


class AccountDetailsResponse(ResponseWithToken):
    @property
    def username(self):
        return self.json["username"]

    @property
    def discriminator(self):
        return self.json["discriminator"]

    @property
    def tag(self):
        return "{}#{}".format(self.username, self.discriminator)

    @property
    def email(self):
        return self.json["email"]

    @property
    def avatar(self):
        return self.json["avatar"]

    @property
    def verified_email(self):
        return self.json["verified"]

    @property
    def id(self):
        return self.json["id"]

    def to_params(self):
        params = AccountDetailsParams()
        params.username = self.username
        params.email = self.email
        params.avatar = self.avatar
        return params


class SettingsResponse(GenericResponse):
    @property
    def friend_policy(self):
        policy = FriendPolicy.NONE
        flags = self.json["friend_source_flags"]
        for name, value in flags.items():
            if not value:
                continue
            policy |= {
                "all": FriendPolicy.ALL,
                "mutual_friends": FriendPolicy.MUTUAL_FRIENDS,
                "mutual_guilds": FriendPolicy.SERVER_MEMBERS,
            }[name]
        return policy

    # Whether or not DMs from server members are allowed.
    # Affects only new servers.
    @property
    def allow_dms(self):
        return not self.json["default_guilds_restricted"]

    @property
    def explicit_filter(self):
        return ExplicitFilter(int(self.json["explicit_content_filter"]))


class InviteDetailsResponse(GenericResponse):
    @property
    def inviter_username(self):
        return self.json["inviter"]["username"]

    @property
    def inviter_discriminator(self):
        return self.json["inviter"]["discriminator"]

    @property
    def inviter_tag(self):
        return "{}#{}".format(
            self.inviter_username, self.inviter_discriminator,
        )

    @property
    def server_name(self):
        return self.json["guild"]["name"]

    @property
    def server_id(self):
        return self.json["guild"]["id"]

    @property
    def member_count(self):
        return self.json.get("approximate_member_count")

    @property
    def presence_count(self):
        return self.json.get("approximate_presence_count")


class SettingsParams:
    def __init__(self):
        self.explicit_filter = None
        self.allow_dms = None
        self.friend_policy = None


class ExplicitFilter(enum.IntEnum):
    NONE = 0
    ALL_BUT_FRIENDS = 1
    ALL = 2


class FriendPolicy(enum.IntEnum):
    NONE = 0
    MUTUAL_FRIENDS = 1
    SERVER_MEMBERS = 2
    ALL = 4 | MUTUAL_FRIENDS | SERVER_MEMBERS

    @classmethod
    def has_all(cls, policy):
        return policy & cls.ALL == cls.ALL

    @classmethod
    def has_mutual_friends(cls, policy):
        return bool(policy & cls.MUTUAL_FRIENDS)

    @classmethod
    def has_server_members(cls, policy):
        return bool(policy & cls.SERVER_MEMBERS)


class AccountDetailsParams:
    def __init__(self):
        self.username = None
        self.email = None
        self.avatar = None
        self.new_password = None


class ServerListResponse(GenericResponse):
    @property
    def servers(self):
        result = []
        for guild in self.json:
            result.append(ServerListItem(
                id=guild["id"], name=guild["name"], is_owner=guild["owner"],
            ))
        return result


class ServerListItem:
    def __init__(self, id, name, is_owner=False):
        self.id = id
        self.name = name
        self.is_owner = is_owner


class ServerMembersResponse(GenericResponse):
    @property
    def members(self):
        result = []
        for member in self.json:
            user = member["user"]
            result.append(ServerMemberListItem(
                username=user["username"], discriminator=user["discriminator"],
                id=user["id"],
            ))
        return result


class ServerMemberListItem:
    def __init__(self, username, discriminator, id):
        self.username = username
        self.discriminator = discriminator
        self.id = id

    @property
    def tag(self):
        return "{}#{}".format(self.username, self.discriminator)


class ServerDetailsResponse(GenericResponse):
    @property
    def id(self):
        return self.json["id"]

    @property
    def name(self):
        return self.json["name"]


class AccountDeletionResponse(GenericResponse):
    @property
    def servers_owned(self):
        return not self.success and self.json.get("code") == 40011


class RequestError(Exception):
    def __init__(self, response):
        self.response = response

    @property
    def status_code(self):
        return self.response.status_code


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
    def __init__(self, user_agent, super_properties, debug=False):
        self.user_agent = user_agent
        self.super_properties = super_properties
        self._debug = debug

        sprops = self.super_properties
        sprops.setdefault("browser_user_agent", user_agent)
        sprops.setdefault("referrer", "")
        sprops.setdefault("referring_domain", "")
        sprops.setdefault("referrer_current", "")
        sprops.setdefault("referring_domain_current", "")
        sprops.setdefault("release_channel", "stable")
        sprops.setdefault("client_build_number", CLIENT_BUILD_NUMBER)
        sprops.setdefault("client_event_source", None)

        self._token = None
        self.fingerprint = None
        self.details = None

    def debug(self, *args, **kwargs):
        if self._debug:
            print(*args, file=sys.stderr, **kwargs)

    def get_headers(self, headers, auth, referer):
        self.ensure_valid_ua()
        headers = headers or {}
        headers.setdefault("User-Agent", self.user_agent)

        if auth and self.token:
            headers.setdefault("Authorization", self.token)
        if referer is not None:
            full_referer = "https://discordapp.com/" + referer
            headers.setdefault("Referer", full_referer)

        if "X-Super-Properties" not in headers:
            headers["X-Super-Properties"] = base64.b64encode(json.dumps(
                self.super_properties, separators=",:",
            ).encode()).decode()
        if "X-Fingerprint" not in headers:
            headers["X-Fingerprint"] = self.get_or_request_fingerprint()
        headers.setdefault("Origin", "https://discordapp.com")
        return headers

    def http_request(
            self, func, url, *, headers=None, allow_errors=frozenset({400}),
            auth=False, no_debug_response=False, referer="", **kwargs):
        self.ensure_valid_ua()
        headers = self.get_headers(headers, auth, referer)

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

        r = patch_json_method(r)
        if allow_errors is True or r.status_code in (allow_errors or {}):
            return r

        try:
            r.raise_for_status()
        except HTTPError as e:
            json_data = r.json()
            args = list(e.args)
            message = (args[0] or "") if args else ""
            args[0] = message + "\nReceived data from server: {}".format(
                json.dumps(json_data, indent=4),
            )

            e.args = tuple(args)
            raise RequestError(GenericResponse(r)) from e
        return r

    def get(self, *args, **kwargs):
        return self.http_request(requests.get, *args, **kwargs)

    def post(self, *args, **kwargs):
        return self.http_request(requests.post, *args, **kwargs)

    def patch(self, *args, **kwargs):
        return self.http_request(requests.patch, *args, **kwargs)

    def put(self, *args, **kwargs):
        return self.http_request(requests.put, *args, **kwargs)

    def delete(self, *args, **kwargs):
        return self.http_request(requests.delete, *args, **kwargs)

    def ensure_valid_ua(self):
        if self.user_agent is None or self.super_properties is None:
            raise TypeError(
                "User-agent and super properties must be set.",
            )

    def request_fingerprint(self):
        r = self.get("experiments", headers={
            "X-Context-Properties": base64.b64encode(
                json.dumps({"location": "Login"}, separators=",:").encode(),
            ).decode(),
            "X-Fingerprint": None,
        }, allow_errors=None, referer="login?redirect=%2F")
        self.fingerprint = r.json()["fingerprint"]

    def get_or_request_fingerprint(self):
        if self.fingerprint is None:
            self.request_fingerprint()
        return self.fingerprint

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, value):
        self._token = value
        self.details = None

    @property
    def logged_in(self):
        return self.token is not None

    def log_in(self, email, password, captcha_key=None, undelete=False):
        r = self.post("auth/login", json={
            "login": email,
            "password": password,
            "undelete": undelete,
            "captcha_key": captcha_key,
            "login_source": None,
            "gift_code_sku_id": None,
        }, referer="login")

        resp = LogInResponse(r)
        if resp.success:
            self.token = resp.token
        return resp

    def log_out(self):
        self.token = None

    def register(self, username, password, email, birthday, captcha_key=None,
                 invite=None):
        r = self.post("auth/register", json={
            "fingerprint": self.get_or_request_fingerprint(),
            "email": email,
            "username": username,
            "password": password,
            "invite": invite,
            "consent": True,
            "date_of_birth": birthday,
            "gift_code_sku_id": None,
            "captcha_key": captcha_key,
        }, referer="register")

        resp = ResponseWithToken(r)
        if resp.success:
            self.token = resp.token_or_none
        return resp

    def verify_email(self, token, captcha_key=None):
        referer = "verify?token=" + token
        r = self.post("auth/verify", json={
            "token": token,
            "captcha_key": captcha_key,
        }, referer=referer)

        resp = ResponseWithToken(r)
        if resp.success:
            self.token = resp.token_or_none
        return resp

    def resend_verification_email(self):
        r = self.post("auth/verify/resend", auth=True)
        resp = GenericResponse(r)
        return resp

    def authorize_ip(self, token, captcha_key=None):
        referer = "authorize-ip"
        data = {"token": token}
        if captcha_key is not None:
            data["captcha_key"] = captcha_key

        r = self.post("auth/authorize-ip", json=data, referer=referer)
        resp = GenericResponse(r)
        return resp

    def get_account_details(self, cached=False):
        if cached and self.details is not None:
            return self.details
        r = self.get("users/@me", auth=True)
        resp = AccountDetailsResponse(r)
        if resp.success:
            self.details = resp
        return resp

    def set_account_details(self, params, password):
        r = self.patch("users/@me", auth=True, json={
            "username": params.username,
            "email": params.email,
            "avatar": params.avatar,
            "password": password,
            "new_password": params.new_password,
        })
        resp = AccountDetailsResponse(r)
        if resp.success and resp.has_token:
            self.token = resp.token
        return resp

    def get_settings(self):
        r = self.get("users/@me/settings", auth=True)
        resp = SettingsResponse(r)
        return resp

    def set_settings(self, params):
        settings = {}
        if params.explicit_filter is not None:
            settings["explicit_content_filter"] = int(params.explicit_filter)
        if params.allow_dms is not None:
            settings["default_guilds_restricted"] = not params.allow_dms
        if params.friend_policy is not None:
            policy = params.friend_policy
            settings["friend_source_flags"] = {
                "all": FriendPolicy.has_all(policy),
                "mutual_friends": FriendPolicy.has_mutual_friends(policy),
                "mutual_guilds": FriendPolicy.has_server_members(policy),
            }

        r = self.patch("users/@me/settings", auth=True, json=settings)
        resp = SettingsResponse(r)
        return resp

    def delete_account(self, password):
        r = self.post("users/@me/delete", json={
            "password": password,
        }, auth=True)
        resp = AccountDeletionResponse(r)
        if resp.success:
            self.log_out()
        return resp

    def invite_details(self, invite_id):
        r = self.get("invite/{}?with_counts=true".format(invite_id), auth=True)
        resp = InviteDetailsResponse(r)
        return resp

    def accept_invite(self, invite_id):
        r = self.post("invite/{}".format(invite_id), auth=True)
        resp = InviteDetailsResponse(r)
        return resp

    def servers(self):
        r = self.get("users/@me/guilds", auth=True)
        resp = ServerListResponse(r)
        return resp

    def server_details(self, server_id):
        r = self.get("guilds/{}".format(server_id), auth=True)
        resp = ServerDetailsResponse(r)
        return resp

    def leave_server(self, server_id):
        r = self.delete("users/@me/guilds/{}".format(server_id), auth=True)
        resp = GenericResponse(r)
        return resp

    def server_members(self, server_id, limit=1000):
        r = self.get(
            "guilds/{}/members?limit={}".format(server_id, limit), auth=True)
        resp = ServerMembersResponse(r)
        return resp

    def transfer_server(self, server_id, new_owner_id):
        r = self.patch("guilds/{}".format(server_id), json={
            "owner_id": new_owner_id,
        }, auth=True)
        resp = GenericResponse(r)
        return resp

    def delete_server(self, server_id):
        r = self.delete("guilds/{}".format(server_id), auth=True)
        resp = GenericResponse(r)
        return resp
