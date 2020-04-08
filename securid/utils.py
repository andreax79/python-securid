#!/usr/bin/env python

from typing import Union, Optional
from Crypto.Cipher import AES
try:  # pragma: no cover
    from secrets import SystemRandom  # (Python >= 3.6) type: ignore
except ImportError:  # pragma: no cover
    from random import SystemRandom


__all__ = [
    'AES_BLOCK_SIZE',
    'AES_KEY_SIZE',
    'Bytes',
    'BytesStr',
    'random',
    'arrayset',
    'arraycpy',
    'aes_ecb_encrypt',
    'aes_ecb_decrypt',
    'xor_block',
    'cbc_hash',
]

AES_BLOCK_SIZE = 16
AES_KEY_SIZE = 16

Bytes = Union[bytes, bytearray]
BytesStr = Union[bytes, bytearray, str]


random = SystemRandom()


def arrayset(dest: bytearray, c: int, n: int, dest_offset: int = 0) -> None:
    dest[dest_offset:dest_offset + n] = [c] * n


def arraycpy(dest: bytearray, src: BytesStr, n: Optional[int] = None, dest_offset: int = 0) -> None:
    if isinstance(src, str):
        src = bytes(src, 'ascii')
    if n is None:
        n = len(src)
    n = min(n, len(dest) - dest_offset, len(src))
    dest[dest_offset:dest_offset + n] = src[0:n]


def aes_ecb_encrypt(key: Bytes, data: Bytes) -> bytes:
    """
        Encrypt data with the key using AES-128 ECB
    """
    return AES.new(bytes(key), AES.MODE_ECB).encrypt(bytes(data))


def aes_ecb_decrypt(key: Bytes, data: Bytes) -> bytes:
    """
        Decrypt data with the key using AES-128 ECB
    """
    return AES.new(bytes(key), AES.MODE_ECB).decrypt(bytes(data))


def xor_block(a: Bytes, b: Bytes) -> bytes:
    return bytes(a[i] ^ (b[i] if i < len(b) else 0) for i in range(0, len(a)))


def cbc_hash(key: Bytes, iv: Bytes, data: Bytes) -> bytes:
    """
        Calculate cipher block chaining message authentication code
    """
    result = bytes(iv)
    while len(data) > 0:
        result = aes_ecb_encrypt(key, xor_block(result, data))
        data = data[AES_BLOCK_SIZE:]
    return bytes(result)
