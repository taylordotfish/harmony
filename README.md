Harmony
=======

Version 0.4.0

Harmony is a free/libre program that allows you to perform various actions with
the messaging service [Discord]. Currently, it allows you to:

* Create an account
* Verify your email address
* View your account tag
* Change your username, email address, password, and avatar
* Change safety and privacy settings
* List servers you’re in and members in those servers
* Transfer and delete servers you own
* Accept server invites
* Delete your account

Actions that require you to complete a CAPTCHA (often required when logging in
from a new location, for example) are automatically supported by using
[librecaptcha].

For free/libre software that allows you to send and receive messages with
Discord, check out [purple-discord].

[Discord]: https://en.wikipedia.org/wiki/Discord_(software)
[librecaptcha]: https://github.com/taylordotfish/librecaptcha
[purple-discord]: https://github.com/EionRobb/purple-discord


Installation
------------

Run the following commands (you will need to have [Git] installed):

```
git clone https://github.com/taylordotfish/harmony
cd harmony
git submodule update --init
```

Then, to install the required Python packages, you can either run:

```
sudo pip3 install -r requirements.txt
```

to install the packages globally, or you can run:

```
pip3 install --user -r requirements.txt
```

to install them locally.

[Git]: https://git-scm.com


Usage
-----

Simply run ``./harmony.py``, or see ``./harmony.py -h`` for more options.

For better text editing support, install [rlwrap] and run
``rlwrap ./harmony.py``.

[rlwrap]: https://github.com/hanslub42/rlwrap


Dependencies
------------

* [Python] ≥ 3.4
* The following Python packages (these can be installed from
  [requirements.txt](requirements.txt); see the [Installation] section):
  - [Pillow] ≥ 4.1.1
  - [requests] ≥ 2.18.1
  - [slimit] ≥ 0.8.1

[Installation]: #installation
[Python]: https://www.python.org/
[Pillow]: https://pypi.python.org/pypi/Pillow/
[requests]: https://pypi.python.org/pypi/requests/
[slimit]: https://pypi.python.org/pypi/slimit/


What’s new
----------

Version 0.4.0:

* You can now list servers you’re in with the ``servers`` command.
* You can now list members in a server with the ``members``.
* You can now display and accept invites with the ``show-invite`` command.
* You can now transfer servers with the ``transfer`` command.
* You can now delete servers with the ``rm-server`` command.
* You can now delete your account with the ``delete`` command.
* You can now undelete an account scheduled for deletion with the ``undelete``
  command.
* The ``get-details`` and ``get-settings`` commands now provide more
  information.
* Updated the user-agent list.
* Fixed some miscellaneous bugs.
* Improved separation between the frontend and backend.

Version 0.3.x:

* Fixed automatic librecaptcha downloading in harmony.py.
* Login attempts that require CAPTCHA tokens are now supported.
* The verification process when logging in from a new location is now
  supported.
* Fixed some miscellaneous bugs.


License
-------

Harmony is licensed under the GNU General Public License, version 3 or any
later version. See [LICENSE].

This README file has been released to the public domain using [CC0].

[LICENSE]: LICENSE
[CC0]: https://creativecommons.org/publicdomain/zero/1.0/
