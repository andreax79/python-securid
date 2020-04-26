python-securid - RSA SecurID 128-bit Token Library
==================================================

python-securid is a Python library for generating RSA SecurID 128-bit compatible token codes.
(Python port of `stoken <https://github.com/cernekee/stoken>`_).
This project is not affiliated with or endorsed by RSA Security.

Installation
------------
::

    pip install securid

Usage
-----

Shell
~~~~~

Generate token from a password protected sdtid file.

.. code:: bash

  $ securid --filename my.sdtid --password very_secret
  24848935

Convert a sdtid file into an unprotected JSON file and generate token from the JSON file.

.. code:: bash

  $ securid --filename my.sdtid --password very_secret --export > my.json
  $ securid --filename my.json
  24848935
  $ cat my.json
  {"digits": 8, "exp_date": "2025-04-13", "period": 60, "secret": [15, 63, 116, 57, 194, 241, 34, 224, 68, 60, 168, 234, 155, 194, 99, 167], "serial": "530965299048", "type": "SecurID"}


Sdtid File
~~~~~~~~~~
::

    import securid
    from securid.sdtid import SdtidFile

    # Read sdtid file
    sdtid = SdtidFile('filename.sdtid')
    # Decrypt token with password
    token = sdtid.get_token(password='000123456789')
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
    token = stoken.get_token()
    # Generate OTP
    token.now() #=> '123456'


Generating a new Token
~~~~~~~~~~~~~~~~~~~~~~
::

    import securid

    token = securid.Token.random(exp_date=date(2030,1,1))
    str(token) # =>  digits: 6 exp_date: 2030-01-01 interval: 60 issuer:  label:  seed: 34b7e942eb6fb35bbf81579dcd9b0522 serial: 922729241304
    # Generate OTP
    token.now() #=> '755546'


Links
~~~~~

* `Project home page (GitHub) <https://github.com/andreax79/python-securid>`_
* `Documentation (Read the Docs) <https://python-securid.readthedocs.io/en/latest/>`_
* `stoken - Software Token for Linux/UNIX <https://github.com/cernekee/stoken>`_
* `PyOTP - Python One-Time Password Library <https://github.com/pyauth/pyotp>`_
