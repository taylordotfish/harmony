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

from . import discord
from .discord import Discord, FriendPolicy
from .user_agents import random_user_agent
from librecaptcha import get_token

from PIL import Image

from io import BytesIO
import base64
import functools
import getpass as getpass_module
import json
import math
import os.path
import re
import sys
import traceback

__version__ = "0.5.0"
RECAPTCHA_API_KEY = "6Lef5iQTAAAAAKeIvIY-DeexoO3gj7ryl9rLMEnn"
RECAPTCHA_SITE_URL = "https://discordapp.com"

INTERACTIVE_HELP = """\
Commands:
  help          Print this help message.
  quit          Quit the program.
  log-in        Log in.
  log-out       Log out.
  register      Register a new account.
  verify        Verify your email address.
  authorize-ip  Authorize a new login location.
  resend        Resend the verification email.
  tag           Get your account tag.
  get-details   Get your current account details.
  set-details   Update account username, email, password, or avatar.
  get-settings  Get account settings.
  set-settings  Update account settings. (Not all settings are supported.)
  delete        Delete your account.
  undelete      Undelete an account marked for deletion.
  show-invite   Show and optionally accept a server invite.
  servers       List the servers you're in.
  members       List the members of a server.
  transfer      Transfer a server to another user.
  rm-server     Delete a server.
"""


def getpass(prompt="Password: ", stream=None):
    if sys.stdin.isatty():
        return getpass_module.getpass(prompt, stream)
    return input(prompt)


def input_nb(*args, **kwargs):
    response = input(*args, **kwargs)
    if not response:
        raise CommandFailure
    return response


def ask_yn(question, print_options=True, default_yes=False):
    if print_options:
        question += " [{}] ".format("Y/n" if default_yes else "y/N")
    answer = input(question)
    if default_yes:
        return not answer[:1].lower() == "n"
    return answer[:1].lower() == "y"


def to_yn(value):
    return "yes" if value else "no"


def pluralize(number, singular, plural=None):
    if number == 1:
        return singular
    return singular + "s" if plural is None else plural


def print_errors(response, message=None, file=sys.stdout):
    def _print(*args, **kwargs):
        print(*args, file=file, **kwargs)

    if response is None or response.success:
        _print(message, "(no errors)")
        return

    if response.ratelimited:
        retry_sec = math.ceil(response.retry_ms / 1000)
        _print(message)
        _print("  Request to server was blocked due to rate limiting.")
        _print("  Try again in {} seconds.".format(retry_sec))
        return

    if response.json is None:
        _print(message)
        _print("  Unknown error (status code {})".format(response.status_code))
        return

    data = response.json
    if isinstance(data, list):
        _print(message)
        for message in data:
            _print(" " * 2 + str(message))
        return

    if not isinstance(data, dict):
        _print(message)
        _print(data)
        return

    if not all(isinstance(value, list) for value in data.values()):
        _print(message, json.dumps(data, indent=2))
        return

    for i, (name, errors) in enumerate(data.items()):
        _print(message)
        _print(" " * 2 + "{}:".format(name))
        for error in errors:
            _print(" " * 4 + str(error))


class CommandFailure(Exception):
    pass


def needs_auth(func):
    @functools.wraps(func)
    def result(self, *args, **kwargs):
        if not self.dc.logged_in:
            print("You are not logged in.")
            raise CommandFailure
        return func(self, *args, **kwargs)
    return result


def warn_if_logged_in(func):
    @functools.wraps(func)
    def result(self, *args, **kwargs):
        if self.dc.logged_in:
            print("Note: You are already logged in.")
            if not ask_yn("Would you like to continue?"):
                return
            print()
        return func(self, *args, **kwargs)
    return result


def explicit_filter_to_str(explicit_filter):
    explicit_filter = discord.ExplicitFilter(explicit_filter)
    return {
        discord.ExplicitFilter.NONE:
            "Don't scan messages from anyone.",
        discord.ExplicitFilter.ALL_BUT_FRIENDS:
            "Scan messages from everyone except friends.",
        discord.ExplicitFilter.ALL:
            "Scan messages from everyone.",
    }.get(explicit_filter, explicit_filter.name)


class InteractiveDiscord:
    def __init__(self, discord=None, debug=False):
        self.dc = discord
        self.debug = debug
        if not self.dc:
            browser_ua, super_properties = random_user_agent()
            self.dc = Discord(browser_ua, super_properties, debug=debug)

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
            "delete": self.delete_account,
            "undelete": self.undelete,
            "show-invite": self.show_invite,
            "servers": self.servers,
            "members": self.server_members,
            "transfer": self.transfer_server,
            "rm-server": self.delete_server,
            "show-token": self.show_token,
            "use-token": self.use_token,
        }.get(command)

    def print_help(self, file=sys.stdout):
        print(INTERACTIVE_HELP, end="", file=file)

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
        if not command:
            return False
        func = self.get_command_function(command)
        if func is None:
            print('Unknown command. Type "help" for help.\n', file=sys.stderr)
            return False

        success = True
        try:
            func()
        except CommandFailure:
            success = False
        except EOFError:
            raise
        except Exception as e:
            print("\nError encountered while running the command:\n",
                  file=sys.stderr)
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
                if not ask_yn("Try another captcha?"):
                    print("CAPTCHA challenge failed.")
                    return None
                continue
            print("Successfully solved the CAPTCHA challenge.")
            return token

    def try_with_captcha(
            self, error_message, func, *args, throw=True, forward_exc=False,
            **kwargs):
        response, exception = self.try_request(func, *args, **kwargs)
        if not response.needs_captcha:
            self.handle_response(
                error_message, response, exception, throw, forward_exc)
            return response

        captcha_key = self.get_captcha_key()
        if captcha_key is None:
            if error_message is not None:
                print()
                print(error_message)
            return response

        return self.try_or_error(
            error_message, func, *args, throw=throw, forward_exc=forward_exc,
            captcha_key=captcha_key, **kwargs,
        )

    def try_or_error(
            self, error_message, func, *args, throw=True, forward_exc=False,
            **kwargs):
        response, exception = self.try_request(func, *args, **kwargs)
        self.handle_response(
            error_message, response, exception, throw, forward_exc)
        return response

    def try_request(self, func, *args, **kwargs):
        try:
            return func(*args, **kwargs), None
        except discord.RequestError as e:
            return e.response, e

    def handle_response(
            self, error_message, response, exception, throw, forward_exc):
        if response.success:
            return
        if error_message is not None:
            print()
            print_errors(response, "{} Errors:".format(error_message))
        if exception is not None:
            if forward_exc:
                raise exception
            raise CommandFailure
        if throw:
            raise CommandFailure

    @warn_if_logged_in
    def log_in(self, undelete=False):
        email = input_nb("Email address: ")
        password = getpass()
        response = self.try_with_captcha(
            "Login failed.", self.dc.log_in, email, password,
            undelete=undelete, throw=False,
        )

        if response.success:
            print("You are now logged in.")
            return
        if response.new_location:
            print("\nYou must authorize this new login location.")
            print('Check your email and use the "authorize-ip" command.')
        elif response.deletion_scheduled:
            print("\nThis account is scheduled for deletion.")
            print('You can cancel this with the "undelete" command.')
        raise CommandFailure

    def log_out(self):
        if not self.dc.logged_in:
            print("You are already logged out.")
            raise CommandFailure

        self.dc.log_out()
        print("You are now logged out.")

    @warn_if_logged_in
    def register(self):
        email = input_nb("Email address: ")
        username = input_nb("Username: ")

        while True:
            password = getpass()
            password2 = getpass("Password (again): ")
            if password == password2:
                break
            print("Passwords do not match.")

        self.try_with_captcha(
            "Registration failed.", self.dc.register, email=email,
            username=username, password=password)
        print("You have successfully registered.")
        print('You should verify your email address with the "verify" '
              "command.")

    @warn_if_logged_in
    def verify_email(self):
        print("Enter the verification link you received by email.")
        print("The email should contain a link that looks like this:")
        print("https://discordapp.com/verify?token=<token>")
        link = input_nb("Enter the link: ")

        match = re.search(r"token=([A-Za-z0-9_\.\-\+]+)", link)
        if match is None:
            print("Could not extract token from link.")
            raise CommandFailure
        token = match.group(1)

        self.try_with_captcha(
            "Verification failed.", self.dc.verify_email, token)
        print("Your email address is now verified.")
        print("You are now logged in.")

    @needs_auth
    def resend_verification_email(self):
        self.try_or_error(
            "Could not send verification email.",
            self.dc.resend_verification_email)
        print("Resent verification email.")

    @warn_if_logged_in
    def authorize_ip(self):
        print("Enter the new location verification link you received by "
              "email.")
        print("The email should contain a link that looks like this:")
        print("https://discordapp.com/authorize-ip?token=<token>")
        link = input_nb("Enter the link: ")

        match = re.search(r"token=([A-Za-z0-9_\.\-\+]+)", link)
        if match is None:
            print("Could not extract token from link.")
            raise CommandFailure
        token = match.group(1)

        self.try_with_captcha(
            "Verification failed.", self.dc.authorize_ip, token)
        print("New location verified. You may now log in.")

    @needs_auth
    def get_tag(self):
        response = self.try_or_error(
            "Could not get account tag.", self.dc.get_account_details,
            cached=True)
        print(response.tag)

    @needs_auth
    def get_account_details(self):
        response = self.try_or_error(
            "Could not get account details.", self.dc.get_account_details)
        print("Raw account details: {}\n".format(response.formatted_json))
        print("Username:", response.username)
        print("Discriminator:", response.discriminator)
        print("Tag:", response.tag)
        print("Email address:", response.email)
        print("Verified email:", to_yn(response.verified_email))

    @needs_auth
    def set_account_details(self):
        response = self.try_or_error(
            "Could not get account details.", self.dc.get_account_details)
        params = response.to_params()
        if ask_yn("Change password?"):
            while True:
                new_password = getpass("New password: ")
                new_password2 = getpass("New password (again): ")
                if new_password == new_password2:
                    break
                print("Passwords do not match.")
            params.new_password = new_password

        if ask_yn("Change email address?"):
            params.email = input_nb("New email address: ")

        if ask_yn("Change avatar?"):
            while True:
                avatar_path = input_nb("Path to new avatar image: ")
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
                params.avatar = "data:image/png;base64,{}".format(
                    base64.b64encode(image_data.getvalue()).decode(),
                )
                break

        password = getpass("Current password: ")
        response = self.try_or_error(
            "Account update failed.", self.dc.set_account_details,
            params=params, password=password)

        print("Account details updated.")
        if not response.verified_email:
            print("\nYour email address is not verified. You can verify it "
                  'with the "verify" command.')

    @needs_auth
    def get_settings(self):
        response = self.try_or_error(
            "Could not get settings.", self.dc.get_settings)
        print("Raw settings: {}\n".format(response.formatted_json))
        print("Explicit message filter:",
              explicit_filter_to_str(response.explicit_filter))
        print("Allow DMs from members of new servers?",
              to_yn(response.allow_dms))

        policy = response.friend_policy
        print("Who can add you as a friend:")
        print("  Friends of friends:",
              to_yn(FriendPolicy.has_mutual_friends(policy)))
        print("  Server members:",
              to_yn(FriendPolicy.has_server_members(policy)))
        print("  Everyone:", to_yn(FriendPolicy.has_all(policy)))

    @needs_auth
    def set_settings(self):
        params = discord.SettingsParams()
        if ask_yn("Change explicit message filter?"):
            print("Options:")
            for option in discord.ExplicitFilter:
                description = explicit_filter_to_str(option)
                print("  [{}] {}".format(option.value, description))
            while True:
                try:
                    choice = int(input("Enter a choice: "))
                    params.explicit_filter = discord.ExplicitFilter(choice)
                except ValueError:
                    continue
                break

        if ask_yn("Change default direct message policy?"):
            answer = ask_yn("Allow DMs from members of new servers?")
            params.allow_dms = answer

        if ask_yn("Change who can add you as a friend?"):
            params.friend_policy = FriendPolicy.NONE
            if ask_yn("Allow friends of friends to add you?"):
                params.friend_policy |= FriendPolicy.MUTUAL_FRIENDS
            if ask_yn("Allow server members to add you?"):
                params.friend_policy |= FriendPolicy.SERVER_MEMBERS
            if ask_yn("Allow everyone to add you?"):
                params.friend_policy |= FriendPolicy.ALL

        self.try_or_error(
            "Settings update failed.", self.dc.set_settings, params)
        print("Settings updated.")

    @needs_auth
    def delete_account(self):
        if not ask_yn("Are you sure you want to delete your account?"):
            return False
        password = getpass("Account password: ")
        response = self.try_or_error(
            "Account deletion failed.", self.dc.delete_account, password,
            throw=False)

        if response.success:
            print("Account scheduled for deletion.")
            print('You can cancel this with the "undelete" command.')
            return
        if response.servers_owned:
            print("\nYou must transfer or delete the servers you own.")
            print('Use the "transfer" and "rm-server" commands.')
        raise CommandFailure

    def undelete(self):
        print("Logging in to cancel deletion...")
        self.log_in(undelete=True)
        print("Account no longer scheduled for deletion.")

    @needs_auth
    def show_invite(self):
        print("Enter the invite link.")
        print("It should look like this: https://discord.gg/<id>")
        link = input_nb("Enter the link: ")

        match = re.search(r"/([A-Za-z0-9_\.\-\+]+)/*$", link)
        if match is None:
            print("Could not extract invite ID from link.")
            return False
        invite_id = match.group(1)
        invite = self.try_or_error(
            "Could not get invite details.", self.dc.invite_details, invite_id)

        print('\n{} has invited you to join the server "{}".'.format(
            invite.inviter_tag, invite.server_name))
        if invite.member_count is not None:
            print("The server has approximately {} {}.".format(
                invite.member_count, pluralize(invite.member_count, "member")))
        if not ask_yn("Accept invite?"):
            return

        self.try_or_error(
            "Could not accept invite.", self.dc.accept_invite, invite_id)
        print("Invite accepted.")

    @needs_auth
    def servers(self):
        response = self.try_or_error(
            "Could not get servers.", self.dc.servers)
        if not response.servers:
            print("You are not in any servers.")
            return
        for i, server in enumerate(response.servers):
            i > 0 and print()
            print(server.name)
            print("  ID: {}".format(server.id))
            print("  Owner? {}".format(to_yn(server.is_owner)))

    def print_servers(self, owned=False, prefix=""):
        servers_resp = self.try_or_error(
            prefix + "Could not get servers.", self.dc.servers)
        print(prefix, end="")

        servers = servers_resp.servers
        if owned:
            servers = [s for s in servers_resp.servers if s.is_owner]
        if not servers:
            print("You don't own any servers." if owned else
                  "You're not in any servers.")
            return False

        print("Your servers:" if owned else
              "Servers you're in:")
        for server in servers:
            print("  {} [ID: {}]".format(server.name, server.id))
        return True

    def print_members(self, server_id, prefix=""):
        members_resp = self.try_or_error(
            prefix + "Could not get server members.", self.dc.server_members,
            server_id)
        print(prefix + "Members in this server:")
        for member in members_resp.members:
            print("  {} [ID: {}]".format(member.tag, member.id))

    @needs_auth
    def server_members(self):
        if not self.print_servers(owned=False):
            return
        server_id = input_nb('\nServer ID: ')
        self.print_members(server_id, prefix="\n")

    @needs_auth
    def transfer_server(self):
        if not self.print_servers(owned=True):
            return
        server_id = input_nb("\nEnter the ID of the server to transfer: ")
        self.print_members(server_id, prefix="\n")

        owner_id = input_nb("\nEnter the ID of the new server owner: ")
        self.try_or_error(
            "Could not transfer server.", self.dc.transfer_server,
            server_id, owner_id)
        print("Server transferred.")

    @needs_auth
    def delete_server(self):
        if not self.print_servers(owned=True):
            return
        server_id = input_nb("\nEnter the ID of the server to delete: ")

        details = self.try_or_error(
            "Could not get server details.", self.dc.server_details, server_id)
        print('You are about to delete the server "{}".'.format(details.name))
        if not ask_yn("Are you sure you want to delete this server?"):
            return

        self.try_or_error(
            "Could not delete server.", self.dc.delete_server, server_id)
        print("Server deleted.")

    @needs_auth
    def show_token(self):
        print(self.dc.token)

    def use_token(self):
        token = input_nb("Token: ")
        self.dc.token = token
