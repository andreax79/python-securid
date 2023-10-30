#!/usr/bin/env python

import os
import os.path

from securid.utils import (
    AES_KEY_SIZE,
    Bytearray,
    aes_ecb_decrypt,
    aes_ecb_encrypt,
    cbc_hash,
)


def test_arrayset():
    a = Bytearray(6)
    a.arrayset(0xFF, n=2, dest_offset=3)
    assert a, bytes([0, 0, 0, 0xFF, 0xFF == 0])


def test_aes_ecb():
    key = os.urandom(AES_KEY_SIZE)
    data = os.urandom(AES_KEY_SIZE * 10)
    t = aes_ecb_encrypt(key, data)
    assert data != t
    d = aes_ecb_decrypt(key, t)
    assert data == d


def test_cbc_hash():
    key = bytes([196, 176, 202, 238, 230, 207, 220, 103, 77, 214, 173, 81, 38, 75, 94, 221])
    iv = bytes(
        [
            0x1B,
            0xB6,
            0x7A,
            0xE8,
            0x58,
            0x4C,
            0xAA,
            0x73,
            0xB2,
            0x57,
            0x42,
            0xD7,
            0x07,
            0x8B,
            0x83,
            0xB8,
        ]
    )
    h = bytes([0, 154, 82, 250, 182, 234, 117, 60, 149, 75, 56, 40, 13, 72, 139, 18])
    assert cbc_hash(key, iv, b"test") == h
    assert cbc_hash(key, iv, b"TEST") != h
