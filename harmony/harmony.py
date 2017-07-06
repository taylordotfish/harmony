# Copyright (C) 2017 taylor.fish <contact@taylor.fish>
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

from .user_agents import random_user_agent
from librecaptcha import get_token

from PIL import Image
from requests.exceptions import HTTPError
import requests

from io import BytesIO
import base64
import getpass as getpass_module
import json
import math
import os.path
import re
import sys
import traceback

__version__ = "0.2.1"

BASE_URL = "https://discordapp.com/api/v6/"
RECAPTCHA_API_KEY = "6Lef5iQTAAAAAKeIvIY-DeexoO3gj7ryl9rLMEnn"
RECAPTCHA_SITE_URL = "https://discordapp.com:443"

PROJECT_URL = "https://github.com/taylordotfish/harmony"
USER_AGENT = "DiscordBot ({}, {})".format(PROJECT_URL, __version__)

INTERACTIVE_HELP = """\
Commands:
  help          Print this help message.
  quit          Quit the program.
  log-in        Log in.
  log-out       Log out.
  register      Register a new account.
  verify        Verify your email address.
  resend        Resend the verification email.
  tag           Get your account tag.
  get-details   Get your current account details.
  set-details   Update account username, email, password, or avatar.
  get-settings  Get account settings.
  set-settings  Update account settings. (Not all settings are supported.)
"""


def get_full_url(url):
    return BASE_URL.rstrip("/") + "/" + url


def getpass(prompt="Password: ", stream=None):
    if sys.stdin.isatty():
        return getpass_module.getpass(prompt, stream)
    return input(prompt)


def print_errors(response, message=None, file=sys.stdout):
    if message is not None:
        print(message, file=file)

    if response is None:
        print("(no errors)", file=file)
        return

    if isinstance(response, list):
        for message in response:
            print(message, file=file)
        return

    if not isinstance(response, dict):
        print(response, file=file)
        return

    if not all(isinstance(value, list) for value in response.values()):
        print(json.dumps(response, indent=4))
        return

    for i, (name, errors) in enumerate(response.items()):
        print(" " * 4 + "{}:".format(name), file=file)
        for error in errors:
            print(" " * 8 + error, file=file)


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
        return r

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

    def log_in(self, email, password):
        r = self.post("auth/login", json={
            "email": email,
            "password": password,
        }, allow_errors={400})
        # Returns form errors if invalid; {"token": "..."} otherwise
        return (r.ok, r.json())

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


class InteractiveDiscord:
    def __init__(self, discord=None, debug=False):
        self.dc = discord
        self.debug = debug
        if not self.dc:
            browser_ua, super_properties = random_user_agent()
            self.dc = Discord(browser_ua, super_properties, debug=debug)

    def ensure_auth(self):
        if not self.dc.token:
            print("You are not logged in.")
            return False
        return True

    def get_command_function(self, command):
        try:
            command = command.split(None, 1)[0]
        except IndexError:
            return None

        return {
            "help": self.print_help,
            "quit": sys.exit,
            "log-in": self.log_in,
            "log-out": self.log_out,
            "register": self.register,
            "verify": self.verify_email,
            "tag": self.get_tag,
            "resend": self.resend_verification_email,
            "get-details": self.get_account_details,
            "set-details": self.set_account_details,
            "get-settings": self.get_settings,
            "set-settings": self.set_settings,
        }.get(command)

    def print_help(self, file=sys.stdout):
        print(INTERACTIVE_HELP, end="", file=file)
        return True

    def command_loop(self):
        print('Type "help" for a list of commands.', file=sys.stderr)
        while True:
            try:
                self.exec_single_command()
            except EOFError:
                print(file=sys.stderr)
                sys.exit()
            except KeyboardInterrupt:
                print(file=sys.stderr)

    def exec_single_command(self):
        print("> ", end="", file=sys.stderr, flush=True)
        command = input()
        func = self.get_command_function(command)
        if func is None:
            print('Unknown command. Type "help" for help.', file=sys.stderr)
            return False

        try:
            success = func()
        except EOFError:
            raise
        except Exception as e:
            print("\nError encountered while running the command:\n",
                  file=sys.stderr)

            if isinstance(e, HTTPError) and e.response.status_code == 429:
                print("Request to server was blocked due to rate limiting.",
                      file=sys.stderr)
                print("Try again in {} seconds.\n".format(
                    math.ceil(e.response.json()["retry_after"] / 1000),
                ), file=sys.stderr)
                return False

            traceback.print_exc()
            print(file=sys.stderr)
            return False

        print(file=sys.stderr)
        return success

    def get_captcha_key(self):
        print("You must solve a CAPTCHA challenge.")
        print("You will be guided through the steps necessary to complete the "
              "challenge.")
        print("Press enter to start the challenge...")
        input()

        while True:
            try:
                token = get_token(
                    RECAPTCHA_API_KEY, RECAPTCHA_SITE_URL, debug=self.debug,
                )
            except Exception:
                print("\nError encountered while solving the CAPTCHA:\n",
                      file=sys.stderr)
                traceback.print_exc()
                print(file=sys.stderr)
                answer = input("Try another captcha? [y/N] ")
                if not answer.lower().startswith("y"):
                    print("CAPTCHA challenge failed.")
                    return None
                continue
            print("Successfully solved the CAPTCHA challenge.")
            return token

    def log_in(self):
        if self.dc.token:
            print("Note: You are already logged in.")
            answer = input("Continue with the login process? [y/N] ")
            if not answer.lower.startswith("y"):
                return False

        email = input("Email address: ")
        password = getpass()
        success, response = self.dc.log_in(email, password)
        if not success:
            print_errors(response, "Login failed. Errors:")
            return False

        self.dc.token = response["token"]
        print("You are now logged in.")
        return True

    def log_out(self):
        if not self.dc.token:
            print("You are already logged out.")
            return False

        self.dc.token = None
        print("You are now logged out.")
        return True

    def register(self):
        email = input("Email address: ")
        username = input("Username: ")

        while True:
            password = getpass()
            password2 = getpass("Password (again): ")
            if password == password2:
                break
            print("Passwords do not match.")

        success, response = self.dc.register(
            email=email, username=username, password=password,
        )

        print()
        if not success and "captcha_key" not in response:
            print_errors(response, "Registration failed. Errors:")
            return False

        if not success:
            captcha_key = self.get_captcha_key()
            print()
            if captcha_key is None:
                print("Registration failed.")
                return False

            success, response = self.dc.register(
                email=email, username=username, password=password,
                captcha_key=captcha_key,
            )

            if not success:
                print_errors(response, "Registration failed. Errors:")
                return False

        print("You have successfully registered.")
        print('You should verify your email address with the "verify" '
              "command.")
        return True

    def verify_email(self):
        print("Enter the verification link you received by email.")
        print("The email should contain a link that looks like this:")
        print("https://discordapp.com/verify?token=<token>")
        link = input("Enter this link: ")

        match = re.search(r"token=([A-Za-z0-9_\.\-\+]+)", link)
        if match is None:
            print("Could not extract token from link.")
            return False
        token = match.group(1)

        success, response = self.dc.verify_email(token)
        print()

        if not success and "captcha_key" not in response:
            print_errors(response, "Verification failed. Errors:")
            return False

        if not success:
            captcha_key = self.get_captcha_key()
            print()
            if captcha_key is None:
                print("Verification failed.")
                return False

            success, response = self.dc.verify_email(token, captcha_key)
            if not success:
                print_errors(response, "Verification failed. Errors:")
                return False

        print("Your email address is now verified.")
        return True

    def resend_verification_email(self):
        if not self.ensure_auth():
            return False
        success, response = self.dc.resend_verification_email()
        if not success:
            print_errors(
                response, "Could not resend verification email. Errors:")
            return False

        print("Resent verification email.")
        return True

    def get_tag(self):
        if not self.ensure_auth():
            return False
        success, response = self.dc.get_account_details()
        if not success:
            print_errors(response, "Could not get account tag. Errors:")
            return False

        print("{}#{}".format(response["username"], response["discriminator"]))
        return True

    def get_account_details(self):
        if not self.ensure_auth():
            return False
        success, response = self.dc.get_account_details()
        if not success:
            print_errors(response, "Could not get account details. Errors:")
            return False

        print("Account details: {}".format(json.dumps(response, indent=4)))
        return True

    def set_account_details(self):
        if not self.ensure_auth():
            return False
        print("First, getting current account details...")
        success, response = self.dc.get_account_details()
        if not success:
            print_errors(response, "Could not get account details. Errors:")
            print("\nAccount update failed.")
            return False

        print("Got current account details.")
        print()

        username = response["username"]
        email = response["email"]
        avatar = response["avatar"]
        new_password = None

        answer = input("Change password? [y/N] ")
        if answer.lower().startswith("y"):
            while True:
                new_password = getpass("New password: ")
                new_password2 = getpass("New password (again): ")
                if new_password == new_password2:
                    break
                print("Passwords do not match.")

        answer = input("Change email address? [y/N] ")
        if answer.lower().startswith("y"):
            email = input("New email address: ")

        answer = input("Change avatar? [y/N] ")
        if answer.lower().startswith("y"):
            while True:
                avatar_path = input("Path to new avatar image: ")
                avatar_path = os.path.expanduser(avatar_path)
                try:
                    image = Image.open(avatar_path)
                except OSError as e:
                    print("Could not load image: {}: {}".format(
                        type(e).__name__, e,
                    ))
                    continue
                image_data = BytesIO()
                image.save(image_data, "PNG")
                avatar = "data:image/png;base64,{}".format(
                    base64.b64encode(image_data.getvalue()).decode(),
                )
                break

        password = getpass("Current password: ")
        success, response = self.dc.set_account_details(
            username=username, email=email, avatar=avatar, password=password,
            new_password=new_password,
        )

        print()
        if not success:
            print_errors(response, "Account update failed. Errors:")
            return False

        print("Account details updated. New account details: {}".format(
            json.dumps(response, indent=4),
        ))

        if not response["verified"]:
            print("\nYour email address is not verified. You can verify it "
                  'with the "verify" command.')
        return True

    def get_settings(self):
        if not self.ensure_auth():
            return False
        success, response = self.dc.get_settings()
        if not success:
            print_errors(response, "Could not get settings. Errors:")
            return False

        print("Settings: {}".format(json.dumps(response, indent=4)))
        return True

    def set_settings(self):
        if not self.ensure_auth():
            return False

        explicit_filter = None
        allow_dms = None
        friend_all = None
        friend_mutual = None
        friend_mutual_guild = None

        answer = input("Change explicit message filter? [y/N] ")
        if answer.lower().startswith("y"):
            print("Options:")
            print("[0] Don't scan messages from anyone.")
            print("[1] Scan messages from everyone except friends.")
            print("[2] Scan messages from everyone.")
            while True:
                try:
                    choice = int(input("Enter a choice: "))
                except ValueError:
                    pass
                if 0 <= choice <= 2:
                    break
            explicit_filter = choice

        answer = input("Change default direct message policy? [y/N] ")
        if answer.lower().startswith("y"):
            answer = input("Allow DMs from members of new servers? [y/N] ")
            allow_dms = answer.lower().startswith("y")

        answer = input("Change who can add you as a friend? [y/N] ")
        if answer.lower().startswith("y"):
            answer = input("Allow friends of friends to add you? [y/N] ")
            friend_mutual = answer.lower().startswith("y")
            answer = input("Allow server members to add you? [y/N] ")
            friend_mutual_guild = answer.lower().startswith("y")
            answer = input("Allow everyone to add you? [y/N] ")
            friend_all = answer.lower().startswith("y")

        success, response = self.dc.set_settings(
            explicit_filter=explicit_filter, allow_dms=allow_dms,
            friend_all=friend_all, friend_mutual=friend_mutual,
            friend_mutual_guild=friend_mutual_guild,
        )

        print()
        if not success:
            print_errors(response, "Settings update failed. Errors:")
            return False

        print("Settings updated. New settings: {}".format(
            json.dumps(response, indent=4),
        ))
        return True
