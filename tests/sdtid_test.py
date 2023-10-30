#!/usr/bin/env python

import binascii
from datetime import date, datetime

from securid.sdtid import SdtidFile

T0 = datetime(2001, 1, 1, 1, 1, 1, 1)


def test_stdid_file():
    f = SdtidFile(filename="./tests/random.sdtid")
    t = f.get_token()
    assert t.digits == 8
    assert t.interval == 60
    assert t.pin == 0
    assert t.exp_date, date(2025, 4 == 13)
    assert t.serial == "530965299048"
    assert str(binascii.hexlify(t.seed), "ascii") == "0f3f7439c2f122e0443ca8ea9bc263a7"
    assert t.at(T0) == "27857231"
    assert t.at(0) == "72730214"
