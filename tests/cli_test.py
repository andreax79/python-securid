#!/usr/bin/env python

from securid import cli
from securid.sdtid import SdtidFile


def test_show_version():
    assert cli.show_version("securid") == 0


def test_expot():
    f = SdtidFile(filename="./tests/random.sdtid")
    t = f.get_token()
    assert cli.export(t) == 0


def test_show_token():
    f = SdtidFile(filename="./tests/random.sdtid")
    t = f.get_token()
    assert cli.show_token(t) == 0
    assert cli.show_token(t, verbose=True) == 0


def test_interactive():
    f = SdtidFile(filename="./tests/random.sdtid")
    t = f.get_token()
    assert cli.interactive(t, test=True) == 0


def test_main():
    assert cli.main(["-V"]) == 0
    assert cli.main(["-f", "./tests/random.sdtid"]) == 0
    assert cli.main(["-f", "./tests/random.sdtid", "--password", "x"]) == 1
    assert cli.main(["-f", "./tests/random.sdtid", "--export"]) == 0
    assert cli.main(["-f", "./tests/random.sdtid", "--pin", "1234"]) == 0
    assert cli.main(["--help"]) == 2
    assert cli.main(["--invalid_option"]) == 2
    assert cli.main(["-f", "./tests/missing.sdtid"]) == 1


def test_pin():
    f = SdtidFile(filename="./tests/random.sdtid")
    t = f.get_token()
    assert cli.show_token(t) == 0
    assert cli.show_token(t, pin=1234, verbose=True) == 0
