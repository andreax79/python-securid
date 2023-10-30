#!/usr/bin/env python

from datetime import date, datetime, timedelta

import securid
from securid.stoken import StokenFile

T0 = datetime(2001, 1, 1, 1, 1, 1, 1)
T1 = datetime(2010, 10, 10, 10, 10, 10, 10)
T2 = datetime(2020, 2, 2, 2, 2, 2, 2)
s1 = timedelta(seconds=1)
s30 = timedelta(seconds=30)
s60 = timedelta(seconds=60)


def test_stoken_file():
    f = StokenFile(filename="./tests/stokenrc")
    print(f.get_token())
    print(f.get_token().now())


def test__numinput_to_bits():
    data = b"234231272577213035237547203121302447410465225375115521144150107256772170000036371"
    n_bits = 15
    offset = 76
    d_ok = b"y\xf2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    d = StokenFile._numinput_to_bits(data, n_bits, offset)
    assert d == d_ok
    d1 = StokenFile._bits_to_numoutput(d, n_bits)
    assert data[offset : offset + len(d1)] == d1

    n_bits = 189
    offset = 13
    d = StokenFile._numinput_to_bits(data, n_bits, offset)
    d2 = StokenFile._bits_to_numoutput(d, n_bits)
    assert data[offset : offset + len(d2)] == d2


def test_get_bits():
    data = b"]OZXO\x18\x9e\xde\x11\xf9fZ\x86\xab\xfb\xb6v\xa6|\xadZ\xe6\xe5\xb4\xee@\x90\xe4m\xf3\xecJ\xf5"
    start = 0
    n_bits = 15
    d1 = StokenFile._get_bits(data, start, n_bits)
    assert d1 == 11943
    test1 = bytearray(data)
    StokenFile._set_bits(test1, start, n_bits, d1)
    assert data == test1

    d2 = d1 + 1
    test2 = bytearray(data)
    StokenFile._set_bits(test2, start, n_bits, d2)
    assert data != test2

    start3 = 159
    n_bits3 = 15
    d3 = StokenFile._get_bits(data, start3, n_bits3)
    assert d3 == 22201
    test3 = bytearray(data)
    StokenFile._set_bits(test3, start3, n_bits3, d3)
    assert data == test3

    start4 = 128
    n_bits4 = 16
    d4 = StokenFile._get_bits(data, start4, n_bits4)
    assert d4 == 30374
    test4 = bytearray(data)
    StokenFile._set_bits(test4, start4, n_bits4, d4)
    assert data == test4

    start5 = 13
    n_bits5 = 32
    d5 = StokenFile._get_bits(data, start5, n_bits5)
    assert d5 == 3947563491
    test5 = bytearray(data)
    StokenFile._set_bits(test5, start5, n_bits5, d5)
    assert data == test5


def test_v2_encode_token():
    token = securid.Token.random(exp_date=date(2050, 1, 1))
    seed = token.seed
    serial = token.serial
    digits = token.digits
    interval = token.interval
    exp_date = token.exp_date

    token1 = securid.Token(
        seed=seed,
        serial=serial,
        digits=digits,
        interval=interval,
        exp_date=exp_date,
    )
    sf1 = StokenFile(token=token1)
    sf1.v2_encode_token()
    assert token1.serial == serial
    assert token1.seed == seed
    assert token1.digits == digits
    assert token1.interval == interval

    sf2 = StokenFile(data=sf1.data)
    assert sf2.get_token().serial == serial
    assert sf2.get_token().seed == seed
    assert sf2.get_token().digits == digits
    assert sf2.get_token().interval == interval

    for i in range(0, 10):
        assert sf2.get_token().at(i * 1000) == token.at(i * 1000)
