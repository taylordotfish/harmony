"""Discord API classes and methods."""
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

# pylint: disable=too-few-public-methods,too-many-public-methods,too-many-arguments,redefined-builtin,too-many-locals

import base64
import enum
import json
import re
import sys

import requests
from requests.exceptions import HTTPError

BASE_URL = "https://discordapp.com/api/v8/"
CLIENT_BUILD_NUMBER = 75681


class GenericResponse:
    """A generic Discord response."""

    def __init__(self, http_response):
        self.success = http_response.ok
        self.status_code = http_response.status_code
        self.json = http_response.json()
        self.text = http_response.text

    @property
    def formatted_json(self):
        """Return the response in JSON format."""
        return json.dumps(self.json, indent=4)

    @property
    def needs_captcha(self):
        """Returns if a captcha is needed."""
        return not self.success and "captcha_key" in self.json

    @property
    def invalid_captcha(self):
        """Return if captcha is not valid."""
        if self.success:
            return False
        try:
            return "incorrect-captcha-sol" in self.json["captcha_key"]
        except (AttributeError, IndexError, KeyError, TypeError):
            return False

    @property
    def ratelimited(self):
        """Return if API rate is limited."""
        return self.status_code == 429

    @property
    def retry_ms(self):
        """Return delay to wait before retrying."""
        return self.json["retry_after"]


class ResponseWithToken(GenericResponse):
    """A Discord API response when a token is included."""

    @property
    def token(self):
        """The API token."""
        return self.json["token"]

    @property
    def token_or_none(self):
        """Returns the token or None."""
        try:
            return self.token
        except KeyError:
            return None

    @property
    def has_token(self):
        """Check if response has a token."""
        return "token" in self.json


class LogInResponse(ResponseWithToken):
    """API response when logging-in to an account."""

    @property
    def new_location(self):
        """Checks if log-in needs verification."""
        return bool(
            re.search(
                r"\b(account_login_verification_email|new login location)\b",
                self.text,
                re.I,
            )
        )

    @property
    def deletion_scheduled(self):
        """Checks if the account is sheduled for deletion."""
        return not self.success and self.json.get("code") == 20011


class AccountDetailsResponse(ResponseWithToken):
    """Account details."""

    @property
    def username(self):
        """Account username."""
        return self.json["username"]

    @property
    def discriminator(self):
        """Account discriminator."""
        return self.json["discriminator"]

    @property
    def tag(self):
        """Account username, followed by dash character then its discriminator."""
        return f"{self.username}#{self.discriminator}"

    @property
    def email(self):
        """Associated E-mail address to the account."""
        return self.json["email"]

    @property
    def avatar(self):
        """Account avatar."""
        return self.json["avatar"]

    @property
    def verified_email(self):
        """Account verified E-mail."""
        return self.json["verified"]

    @property
    def id(self):
        """Account ID."""
        return self.json["id"]

    def to_params(self):
        """Returns a AccountDetailsParams with account username, e-mail and avatar."""
        params = AccountDetailsParams()
        params.username = self.username
        params.email = self.email
        params.avatar = self.avatar
        return params


class SettingsResponse(GenericResponse):
    """Account settings."""

    @property
    def friend_policy(self):
        """Account friend policy"""
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

    @property
    def allow_dms(self):
        """Whether or not DMs from server members are allowed.

        Affects only new servers."""
        return not self.json["default_guilds_restricted"]

    @property
    def explicit_filter(self):
        """Returns explicite filters are enabled or not."""
        return ExplicitFilter(int(self.json["explicit_content_filter"]))


class InviteDetailsResponse(GenericResponse):
    """Invit details."""

    @property
    def inviter_username(self):
        """The inviter's username"""
        return self.json["inviter"]["username"]

    @property
    def inviter_discriminator(self):
        """Inviter's discriminator"""
        return self.json["inviter"]["discriminator"]

    @property
    def inviter_tag(self):
        """Formated inviter's username and discriminator."""
        return f"{self.inviter_username}#{self.inviter_discriminator}"

    @property
    def server_name(self):
        """Server name."""
        return self.json["guild"]["name"]

    @property
    def server_id(self):
        """Server ID."""
        return self.json["guild"]["id"]

    @property
    def member_count(self):
        """Approximate number of members."""
        return self.json.get("approximate_member_count")

    @property
    def presence_count(self):
        """Approximate number of presents."""
        return self.json.get("approximate_presence_count")


class SettingsParams:
    """Account settings parameters."""

    def __init__(self):
        self.explicit_filter = None
        self.allow_dms = None
        self.friend_policy = None


class ExplicitFilter(enum.IntEnum):
    """Types of explicit filters."""

    NONE = 0
    ALL_BUT_FRIENDS = 1
    ALL = 2


class FriendPolicy(enum.IntEnum):
    """Types of friend policy."""

    NONE = 0
    MUTUAL_FRIENDS = 1
    SERVER_MEMBERS = 2
    ALL = 4 | MUTUAL_FRIENDS | SERVER_MEMBERS

    @classmethod
    def has_all(cls, policy):
        """If all filter is applied."""
        return policy & cls.ALL == cls.ALL

    @classmethod
    def has_mutual_friends(cls, policy):
        """Multual friends policy is applied."""
        return bool(policy & cls.MUTUAL_FRIENDS)

    @classmethod
    def has_server_members(cls, policy):
        """If server members filter is applied."""
        return bool(policy & cls.SERVER_MEMBERS)


class AccountDetailsParams:
    """Account details parameters."""

    def __init__(self):
        self.username = None
        self.email = None
        self.avatar = None
        self.new_password = None


class ServerListResponse(GenericResponse):
    """Server list."""

    @property
    def servers(self):
        """List of servers."""
        result = []
        for guild in self.json:
            result.append(
                ServerListItem(
                    id=guild["id"],
                    name=guild["name"],
                    is_owner=guild["owner"],
                )
            )
        return result


class ServerListItem:
    """An item of list of servers."""

    def __init__(self, id, name, is_owner=False):
        self.id = id
        self.name = name
        self.is_owner = is_owner


class ServerMembersResponse(GenericResponse):
    """Members of a server."""

    @property
    def members(self):
        """Members of the server."""
        result = []
        for member in self.json:
            user = member["user"]
            result.append(
                ServerMemberListItem(
                    username=user["username"],
                    discriminator=user["discriminator"],
                    id=user["id"],
                )
            )
        return result


class ServerMemberListItem:
    """A member of the server."""

    def __init__(self, username, discriminator, id):
        self.username = username
        self.discriminator = discriminator
        self.id = id

    @property
    def tag(self):
        """Member username and discriminator."""
        return f"{self.username}#{self.discriminator}"


class ServerDetailsResponse(GenericResponse):
    """Server details."""

    @property
    def id(self):
        """ID of the server."""
        return self.json["id"]

    @property
    def name(self):
        """Server name."""
        return self.json["name"]


class AccountDeletionResponse(GenericResponse):
    """Details when asking for account deletion."""

    @property
    def servers_owned(self):
        """Account owns a server."""
        return not self.success and self.json.get("code") == 40011


class RequestError(Exception):
    """A request error."""

    def __init__(self, response):
        self.response = response

    @property
    def status_code(self):
        """HTTP response code."""
        return self.response.status_code


def get_full_url(url):
    """Returns a complete API URL."""
    return BASE_URL.rstrip("/") + "/" + url


def patch_json_method(response):
    """Patch the JSON response."""
    old_json = response.json

    def json(default=dict, **kwargs):  # pylint: disable=redefined-outer-name
        """Format the JSON response."""
        if not response.text:
            return None if default is None else default()
        return old_json(**kwargs)

    response.json = json
    return response


class Discord:
    """Discord API base class."""

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
        """Print debug message if debug is enabled."""
        if self._debug:
            print(*args, file=sys.stderr, **kwargs)

    def get_headers(self, headers, auth, referer):
        """Gets API response headers."""
        self.ensure_valid_ua()
        headers = headers or {}
        headers.setdefault("User-Agent", self.user_agent)

        if auth and self.token:
            headers.setdefault("Authorization", self.token)
        if referer is not None:
            full_referer = "https://discordapp.com/" + referer
            headers.setdefault("Referer", full_referer)

        if "X-Super-Properties" not in headers:
            headers["X-Super-Properties"] = base64.b64encode(
                json.dumps(
                    self.super_properties,
                    separators=",:",
                ).encode()
            ).decode()
        if "X-Fingerprint" not in headers:
            headers["X-Fingerprint"] = self.get_or_request_fingerprint()
        headers.setdefault("Origin", "https://discordapp.com")
        return headers

    def http_request(
        self,
        func,
        url,
        *,
        headers=None,
        allow_errors=frozenset({400}),
        auth=False,
        no_debug_response=False,
        referer="",
        **kwargs,
    ):
        """Makes a HTTP API request."""
        self.ensure_valid_ua()
        headers = self.get_headers(headers, auth, referer)

        method = func.__name__
        r = func(get_full_url(url), headers=headers, **kwargs)

        self.debug(f"[http] [{method}] {r.url}")
        self.debug(f"[http] [{method}] [headers] {headers}")
        if "data" in kwargs:
            data = kwargs["data"]
            self.debug(f"[http] [{method}] [data] {data}")
        if "json" in kwargs:
            json_data = kwargs["json"]
            self.debug(f"[http] [{method}] [json] {json_data}")
        self.debug(f"[http] [{method}] [status code] {r.status_code}")

        if not no_debug_response:
            self.debug(f"[http] [{method}] [response] {r.text}")

        r = patch_json_method(r)
        if allow_errors is True or r.status_code in (allow_errors or {}):
            return r

        try:
            r.raise_for_status()
        except HTTPError as e:
            json_data = r.json()
            args = list(e.args)
            message = (args[0] or "") if args else ""
            args[0] = (
                message
                + f"\nReceived data from server: {json.dumps(json_data, indent=4)}"
            )

            e.args = tuple(args)
            raise RequestError(GenericResponse(r)) from e
        return r

    def get(self, *args, **kwargs):
        """Send a a HTTP get request."""
        return self.http_request(requests.get, *args, **kwargs)

    def post(self, *args, **kwargs):
        """Send a HTTP post request."""
        return self.http_request(requests.post, *args, **kwargs)

    def patch(self, *args, **kwargs):
        """Send a HTTP patch request."""
        return self.http_request(requests.patch, *args, **kwargs)

    def put(self, *args, **kwargs):
        """Send a HTTP put request."""
        return self.http_request(requests.put, *args, **kwargs)

    def delete(self, *args, **kwargs):
        """Send a HTTP delete request."""
        return self.http_request(requests.delete, *args, **kwargs)

    def ensure_valid_ua(self):
        """Ensures user-agent is valid."""
        if self.user_agent is None or self.super_properties is None:
            raise TypeError(
                "User-agent and super properties must be set.",
            )

    def request_fingerprint(self):
        """Gets fingerprint."""
        r = self.get(
            "experiments",
            headers={
                "X-Context-Properties": base64.b64encode(
                    json.dumps(
                        {"location": "Login"}, separators=",:"
                    ).encode(),
                ).decode(),
                "X-Fingerprint": None,
            },
            allow_errors=None,
            referer="login?redirect=%2F",
        )
        self.fingerprint = r.json()["fingerprint"]

    def get_or_request_fingerprint(self):
        """Get or request for a fingerprint."""
        if self.fingerprint is None:
            self.request_fingerprint()
        return self.fingerprint

    @property
    def token(self):
        """Returns the token."""
        return self._token

    @token.setter
    def token(self, value):
        """Set the token."""
        self._token = value
        self.details = None

    @property
    def logged_in(self):
        """Check if logged in."""
        return self.token is not None

    def log_in(self, email, password, captcha_key=None, undelete=False):
        """Log-in to an account."""
        r = self.post(
            "auth/login",
            json={
                "login": email,
                "password": password,
                "undelete": undelete,
                "captcha_key": captcha_key,
                "login_source": None,
                "gift_code_sku_id": None,
            },
            referer="login",
        )

        resp = LogInResponse(r)
        if resp.success:
            self.token = resp.token
        return resp

    def log_out(self):
        """Disconnect the account."""
        self.token = None

    def register(
        self,
        username,
        password,
        email,
        birthday,
        captcha_key=None,
        invite=None,
    ):
        """Register a new Discord account."""
        r = self.post(
            "auth/register",
            json={
                "fingerprint": self.get_or_request_fingerprint(),
                "email": email,
                "username": username,
                "password": password,
                "invite": invite,
                "consent": True,
                "date_of_birth": birthday,
                "gift_code_sku_id": None,
                "captcha_key": captcha_key,
            },
            referer="register",
        )

        resp = ResponseWithToken(r)
        if resp.success:
            self.token = resp.token_or_none
        return resp

    def verify_email(self, token, captcha_key=None):
        """Verify an e-mail address."""
        referer = "verify?token=" + token
        r = self.post(
            "auth/verify",
            json={
                "token": token,
                "captcha_key": captcha_key,
            },
            referer=referer,
        )

        resp = ResponseWithToken(r)
        if resp.success:
            self.token = resp.token_or_none
        return resp

    def resend_verification_email(self):
        """Resend the e-mail verification."""
        r = self.post("auth/verify/resend", auth=True)
        resp = GenericResponse(r)
        return resp

    def authorize_ip(self, token, captcha_key=None):
        """Authorize a new IP address to connect to the account."""
        referer = "authorize-ip"
        data = {"token": token}
        if captcha_key is not None:
            data["captcha_key"] = captcha_key

        r = self.post("auth/authorize-ip", json=data, referer=referer)
        resp = GenericResponse(r)
        return resp

    def get_account_details(self, cached=False):
        """Get account details."""
        if cached and self.details is not None:
            return self.details
        r = self.get("users/@me", auth=True)
        resp = AccountDetailsResponse(r)
        if resp.success:
            self.details = resp
        return resp

    def set_account_details(self, params, password):
        """Modify account details."""
        r = self.patch(
            "users/@me",
            auth=True,
            json={
                "username": params.username,
                "email": params.email,
                "avatar": params.avatar,
                "password": password,
                "new_password": params.new_password,
            },
        )
        resp = AccountDetailsResponse(r)
        if resp.success and resp.has_token:
            self.token = resp.token
        return resp

    def get_settings(self):
        """Get account settings."""
        r = self.get("users/@me/settings", auth=True)
        resp = SettingsResponse(r)
        return resp

    def set_settings(self, params):
        """Modify account settings."""
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
        """Ask for account deletion."""
        r = self.post(
            "users/@me/delete",
            json={
                "password": password,
            },
            auth=True,
        )
        resp = AccountDeletionResponse(r)
        if resp.success:
            self.log_out()
        return resp

    def invite_details(self, invite_id):
        """Gets details of an invite."""
        r = self.get(f"invite/{invite_id}?with_counts=true", auth=True)
        resp = InviteDetailsResponse(r)
        return resp

    def accept_invite(self, invite_id):
        """Accept an invite."""
        r = self.post(f"invite/{invite_id}", auth=True)
        resp = InviteDetailsResponse(r)
        return resp

    def servers(self):
        """Get account servers."""
        r = self.get("users/@me/guilds", auth=True)
        resp = ServerListResponse(r)
        return resp

    def server_details(self, server_id):
        """Gets details for a server."""
        r = self.get(f"guilds/{server_id}", auth=True)
        resp = ServerDetailsResponse(r)
        return resp

    def leave_server(self, server_id):
        """Leave a server."""
        r = self.delete(f"users/@me/guilds/{server_id}", auth=True)
        resp = GenericResponse(r)
        return resp

    def server_members(self, server_id, limit=1000):
        """Get members of a server."""
        r = self.get(f"guilds/{server_id}/members?limit={limit}", auth=True)
        resp = ServerMembersResponse(r)
        return resp

    def transfer_server(self, server_id, new_owner_id):
        """Transfert a server."""
        r = self.patch(
            f"guilds/{server_id}",
            json={
                "owner_id": new_owner_id,
            },
            auth=True,
        )
        resp = GenericResponse(r)
        return resp

    def delete_server(self, server_id):
        """Delete a server."""
        r = self.delete(f"guilds/{server_id}", auth=True)
        resp = GenericResponse(r)
        return resp
