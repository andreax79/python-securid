python-securid - RSA SecurID 128-bit Token Library
==================================================

python-securid is a Python library for generating RSA SecurID 128-bit compatible token codes.

Installation
------------
::

    pip install securid

Usage
-----

Stdin File
~~~~~~~~~~
::

    import securid
    from securid.stdin import StdinFile

    # Read stdin file
    stdin = StdinFile('filename.sdtid')
    # Decrypt token with password
    token = stdin.get_token(password='000123456789')
    # Generate OTP
    token.now() #=> '123456'


Stoken File
~~~~~~~~~~~
::

    import securid
    from securid.stoken import StokenFile

    # Read ~/.stokenrc file
    stoken = StokenFile()
    # Get token
    token = stdin.get_token()
    # Generate OTP
    token.now() #=> '123456'


Generating a new Token
~~~~~~~~~~~~~~~~~~~~~~
::

    import securid

    token = securid.Token.random(exp_date=date(2030,1,1))
    str(token) # =>  digits: 6 exp_date: 2030-01-01 interval: 60 seed: 34b7e942eb6fb35bbf81579dcd9b0522 serial: 922729241304
    # Generate OTP
    token.now() #=> '755546'


Links
~~~~~

* `Project home page (GitHub) <https://github.com/andreax79/python-securid>`_
* `Documentation (Read the Docs) <https://python-securid.readthedocs.io/en/latest/>`_
* `stoken - Software Token for Linux/UNIX <https://github.com/cernekee/stoken>`_
* `PyOTP - Python One-Time Password Library <https://github.com/pyauth/pyotp>`_

