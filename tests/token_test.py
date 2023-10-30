#!/usr/bin/env python

from datetime import date, datetime, timedelta

import pytest

import securid

T0 = datetime(2001, 1, 1, 1, 1, 1, 1)
T1 = datetime(2010, 10, 10, 10, 10, 10, 10)
T2 = datetime(2020, 2, 2, 2, 2, 2, 2)
s1 = timedelta(seconds=1)
s30 = timedelta(seconds=30)
s60 = timedelta(seconds=60)


def test_at():
    seed = "9e2cdb3468bd84fe6cf42570d1f8559c"
    serial = "000123456789"
    t = securid.Token(serial=serial, seed=seed)
    assert t.at(T0) == "078264"
    assert t.at(T0 + s30) == "078264"
    assert t.at(T0 + s60) != "078264"

    serial2 = "000987654321"
    t2 = securid.Token(serial=serial2, seed=seed)
    assert t.at(T0) != t2.at(T0)

    seed2 = "884c91dc46f17970e4d08a34d852ee18"
    t3 = securid.Token(serial=serial2, seed=seed2)
    assert t3.at(T0) != t2.at(T0)


def test_serial_seed_as_bytes():
    seed = b"9e2cdb3468bd84fe6cf42570d1f8559c"
    serial = b"000123456789"
    t = securid.Token(serial=serial, seed=seed)
    assert t.at(T0) == "078264"


def test_number_of_digits():
    seed = "967863726e4a54c7cec668012e7302a6"
    serial = "432342"
    for i in range(1, 16):
        t = securid.Token(serial=serial, seed=seed, digits=i)
        assert len(t.at(T0)) == i


def test_interval_30s():
    seed = "967863726e4a54c7cec668012e7302a6"
    serial = b"000123456789"
    t30 = securid.Token(serial=serial, seed=seed, interval=30)
    assert t30.at(T0) == t30.at(T0 + s1)
    assert t30.at(T0) != t30.at(T0 + s30)
    t60 = securid.Token(serial=serial, seed=seed, interval=60)
    assert t30.at(T0) != t60.at(T0)


def test_exp_date():
    serial = b"000123456789"
    t1 = securid.Token().random(serial=serial, exp_date=date(2123, 1, 2))
    t2 = securid.Token().random(serial=serial, exp_date="2123-01-02")
    assert t1.exp_date, date(2123, 1 == 2)
    assert t2.exp_date, date(2123, 1 == 2)
    assert t1 != t2


def test_random():
    serial = b"000123456789"
    t1 = securid.Token().random()
    assert t1.at(T2) == t1.at(T2 + s1)
    t2 = securid.Token().random(serial=serial)
    assert t2.at(T2) == t2.at(T2 + s1)
    assert t1.at(T2) != t2.at(T2)
    date1 = date(2050, 1, 1)
    t3 = securid.Token.random(exp_date=date1)
    assert t3.exp_date == date1
    assert t1.now() != t3.now()


def test_exceptions():
    with pytest.raises(Exception):
        serial = b"000123456789"
        t = securid.Token(serial=serial, seed=None)
        t.now()


def test_repl():
    seed = "967863726e4a54c7cec668012e7302a6"
    serial = b"000123456789"
    t = securid.Token(serial=serial, seed=seed, interval=30, label="test", pin=1234)
    assert (
        repr(t)
        == "{'digits': '6', 'exp_date': '', 'interval': '30', 'issuer': '', 'label': 'test', 'pin': '1234', 'seed': '3936373836333732366534613534633763656336363830313265373330326136', 'serial': '000123456789'}"
    )


def test_time_left():
    t1 = securid.Token().random()
    assert t1.time_left(T1) == 50
    assert t1.time_left(T1 + timedelta(seconds=1)) == 49
    assert t1.time_left(T1 + timedelta(seconds=50)) == 60
    assert t1.time_left(123456) == 24
    t2 = securid.Token().random(interval=30)
    assert t2.time_left(T2) == 28
    assert t2.time_left(T2 + timedelta(seconds=1)) == 27
    assert t2.time_left(T2 + timedelta(seconds=28)) == 30
    assert t2.time_left(123456) == 24
    assert 0 < t2.time_left() <= 30


def test_pin():
    seed = "9e2cdb3468bd84fe6cf42570d1f8559c"
    serial = "000123456789"
    pin = 1234
    t = securid.Token(serial=serial, seed=seed, pin=pin)
    assert t.at(T0) == "079498"
    assert t.at(T0 + s30) == "079498"
    assert t.at(T0 + s60) != "079498"

    t2 = securid.Token(serial=serial, seed=seed)
    assert t.at(T0) != t2.at(T0)
