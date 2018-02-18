Harmony
=======

Version 0.5.0

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
from a new location, for example) are automatically supported by using
`librecaptcha`_.

For free/libre software that allows you to send and receive messages with
Discord, check out `purple-discord`_.

.. _Discord: https://en.wikipedia.org/wiki/Discord_(software)
.. _librecaptcha: https://github.com/nickolas360/librecaptcha
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

    git clone https://github.com/nickolas360/harmony
    cd harmony

Then install with `pip`_::

    sudo pip3 install .

Alternatively, you can run::

    sudo ./setup.py install

With either command, to install locally, run without ``sudo`` and add the
``--user`` option.

Run without installing
~~~~~~~~~~~~~~~~~~~~~~

Run the first set of commands in the previous section to clone the repository.
Then, install the required dependencies by running::

    sudo pip3 install -r requirements.txt

To install the dependencies locally, run without ``sudo`` and add the
``--user`` option.

.. _pip: https://pip.pypa.io
.. _Git: https://git-scm.com


Usage
-----

If you installed Harmony, simply run ``harmony``, or see ``harmony -h`` for
more options. If you didn’t install it, use ``./harmony.py`` instead of
``harmony``.

For better text editing support, install `rlwrap`_ and run
``rlwrap harmony`` or ``rlwrap ./harmony.py``.

.. _rlwrap: https://github.com/hanslub42/rlwrap


What’s new
----------

Version 0.5.0:

* Harmony can now be installed from PyPI, or from the Git repository with pip
  or ``setup.py``.

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

* `Python`_ ≥ 3.4
* The following Python packages (the installation instructions above handle
  installing these):

  - `Pillow`_ ≥ 4.1.1
  - `requests`_ ≥ 2.18.1
  - `librecaptcha <librecaptcha-pkg_>`_ ≥ 0.3.0

.. _Python: https://www.python.org/
.. _Pillow: https://pypi.python.org/pypi/Pillow/
.. _requests: https://pypi.python.org/pypi/requests/
.. _librecaptcha-pkg: https://pypi.python.org/pypi/librecaptcha/


License
-------

Harmony is licensed under the GNU General Public License, version 3 or any
later version. See `LICENSE`_.

This README file has been released to the public domain using `CC0`_.

.. _LICENSE: LICENSE
.. _CC0: https://creativecommons.org/publicdomain/zero/1.0/
