Harmony
=======

Version 0.7.1

Harmony is a free/libre program that allows you to perform various actions with
the messaging service `Discord`_. Currently, it allows you to:

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
from a new location, for example) are supported by using `librecaptcha`_.

For free/libre software that allows you to send and receive messages with
Discord, check out `purple-discord`_.

.. _Discord: https://en.wikipedia.org/wiki/Discord_(software)
.. _librecaptcha: https://github.com/taylordotfish/librecaptcha
.. _purple-discord: https://github.com/EionRobb/purple-discord


Installation
------------

From PyPI
~~~~~~~~~

Install with `pip`_::

    sudo pip3 install harmony-discord

To install locally, run without ``sudo`` and add the ``--user`` option.


From the Git repository
~~~~~~~~~~~~~~~~~~~~~~~

Clone the repository with the following commands (you’ll need to have `Git`_
installed)::

    git clone https://github.com/taylordotfish/harmony
    cd harmony

Then install with `pip`_::

    sudo pip3 install .

To install locally, run without ``sudo`` and add the ``--user`` option.


Run without installing
~~~~~~~~~~~~~~~~~~~~~~

Run the first set of commands in the previous section to clone the repository.
Then, install the required dependencies by running::

    sudo pip3 install -r requirements.txt

To install the dependencies locally, run without ``sudo`` and add ``--user``.

.. _pip: https://pip.pypa.io
.. _Git: https://git-scm.com


Usage
-----

If you installed Harmony, simply run ``harmony``, or see ``harmony -h`` for
more options. If you didn’t install it, use ``./harmony.py`` instead of
``harmony``.

If an action requires you to solve a CAPTCHA, Harmony will use
`librecaptcha`_’s GTK 3 GUI, if available, unless the environment variable
``LIBRECAPTCHA_NO_GUI`` is set to a non-empty string.

.. _librecaptcha: https://github.com/taylordotfish/librecaptcha


What’s new
----------

Version 0.7.1:

* Harmony now works with newer versions of librecaptcha.
* Harmony now won’t use the librecaptcha GUI if the environment variable
  ``LIBRECAPTCHA_NO_GUI`` is non-empty.
* Updated the user-agent list.

Version 0.7.0:

* Harmony can now save passwords in the system keyring.

Version 0.6.x:

* Harmony now uses Readline for input.
* Harmony should now work again (as of 2021-02-04).
* Fixed registration.
* The librecaptcha GUI is now used when available.

Version 0.5.x:

* Harmony can now be installed from PyPI, or from the Git repository with pip
  or ``setup.py``.
* Fixed possible encoding issue in ``setup.py``.

Version 0.4.x:

* `librecaptcha`_ is now loaded from Python’s default path if available;
  otherwise, the corresponding submodule is cloned.
* You can now list servers you’re in with the ``servers`` command.
* You can now list members in a server with the ``members`` command.
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


Dependencies
------------

* `Python`_ ≥ 3.5
* The following Python packages:

  - `Pillow`_
  - `requests`_
  - `librecaptcha[gtk] <librecaptcha-pkg_>`_
  - `keyring`_

The installation instructions above handle installing the Python packages.
Alternatively, running ``pip3 install -r requirements.freeze.txt`` will install
specific versions of the dependencies that have been confirmed to work.

.. _Python: https://www.python.org/
.. _Pillow: https://pypi.org/project/Pillow/
.. _requests: https://pypi.org/project/requests/
.. _librecaptcha-pkg: https://pypi.org/project/librecaptcha/
.. _keyring: https://pypi.org/project/keyring/


License
-------

Harmony is licensed under the GNU General Public License, version 3 or any
later version. See `LICENSE`_.

This README file has been released to the public domain using `CC0`_.

.. _LICENSE: LICENSE
.. _CC0: https://creativecommons.org/publicdomain/zero/1.0/
