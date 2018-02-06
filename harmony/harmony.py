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

from .discord import Discord, __version__
from .user_agents import random_user_agent
from librecaptcha import get_token

from PIL import Image
from requests.exceptions import HTTPError

from io import BytesIO
import base64
import getpass as getpass_module
import json
import math
import os.path
import re
import sys
import traceback

assert __version__

RECAPTCHA_API_KEY = "6Lef5iQTAAAAAKeIvIY-DeexoO3gj7ryl9rLMEnn"
RECAPTCHA_SITE_URL = "https://discordapp.com:443"

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


class InteractiveDiscord:
    def __init__(self, discord=None, debug=False):
        self.dc = discord
        self.debug = debug
        if not self.dc:
            browser_ua, super_properties = random_user_agent()
            self.dc = Discord(browser_ua, super_properties, debug=debug)

    def ensure_auth(self):
        if not self.dc.logged_in:
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
            "authorize-ip": self.authorize_ip,
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
                if not answer[:1].lower() == "y":
                    print("CAPTCHA challenge failed.")
                    return None
                continue
            print("Successfully solved the CAPTCHA challenge.")
            return token

    def try_with_captcha(self, error_message, func, *args, **kwargs):
        success, response = func(*args, **kwargs)
        if success:
            return True, response

        if "captcha_key" not in response:
            if error_message is not None:
                print_errors("{} Errors:".format(error_message))
            return False, response

        captcha_key = self.get_captcha_key()
        print()
        if captcha_key is None:
            if error_message is not None:
                print(error_message)
            return False, response

        success, response = func(*args, **kwargs)
        if not success:
            if error_message is not None:
                print_errors("{} Errors:".format(error_message))
            return False, response
        return True, response

    def log_in(self):
        if self.dc.logged_in:
            print("Note: You are already logged in.")
            answer = input("Continue with the login process? [y/N] ")
            if not answer[:1].lower() == "y":
                return False

        email = input("Email address: ")
        password = getpass()
        success, response = self.try_with_captcha(
            "Login failed.", self.dc.log_in, email, password,
        )

        if success:
            print("You are now logged in.")
        elif isinstance(response.get("email"), list):
            ip_needs_auth = any(
                re.search("new login location", error, re.I)
                for error in response["email"])
            if ip_needs_auth:
                print("You must authorize this new login location.")
                print('Check your email and use the "authorize-ip" command.')
        return success

    def log_out(self):
        if not self.dc.logged_in:
            print("You are already logged out.")
            return False

        self.dc.log_out()
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

        success, response = self.try_with_captcha(
            "Registration failed.", self.dc.register, email=email,
            username=username, password=password,
        )
        print()

        if success:
            print("You have successfully registered.")
            print('You should verify your email address with the "verify" '
                  "command.")
        return success

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

        success, response = self.try_with_captcha(
            "Verification failed.", self.dc.verify_email, token,
        )
        print()

        if success:
            print("Your email address is now verified.")
        return success

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

    def authorize_ip(self):
        print("Enter the new location verification link you received by "
              "email.")
        print("The email should contain a link that looks like this:")
        print("https://discordapp.com/authorize-ip?token=<token>")
        link = input("Enter this link: ")

        match = re.search(r"token=([A-Za-z0-9_\.\-\+]+)", link)
        if match is None:
            print("Could not extract token from link.")
            return False
        token = match.group(1)

        success, response = self.try_with_captcha(
            "Verification failed.", self.dc.authorize_ip, token,
        )
        print()

        if success:
            print("New location verified. You may now log in.")
        return success

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
        if answer[:1].lower() == "y":
            while True:
                new_password = getpass("New password: ")
                new_password2 = getpass("New password (again): ")
                if new_password == new_password2:
                    break
                print("Passwords do not match.")

        answer = input("Change email address? [y/N] ")
        if answer[:1].lower() == "y":
            email = input("New email address: ")

        answer = input("Change avatar? [y/N] ")
        if answer[:1].lower() == "y":
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
        if answer[:1].lower() == "y":
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
        if answer[:1].lower() == "y":
            answer = input("Allow DMs from members of new servers? [y/N] ")
            allow_dms = answer[:1].lower() == "y"

        answer = input("Change who can add you as a friend? [y/N] ")
        if answer[:1].lower() == "y":
            answer = input("Allow friends of friends to add you? [y/N] ")
            friend_mutual = answer[:1].lower() == "y"
            answer = input("Allow server members to add you? [y/N] ")
            friend_mutual_guild = answer[:1].lower() == "y"
            answer = input("Allow everyone to add you? [y/N] ")
            friend_all = answer[:1].lower() == "y"

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
