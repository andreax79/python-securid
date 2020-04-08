#!/usr/bin/env python

import binascii
import string
from datetime import datetime, date
from typing import Any, Union, Optional
from .utils import (
    AES_KEY_SIZE,
    BytesStr,
    random,
    arrayset,
    arraycpy,
    aes_ecb_encrypt,
)
from .exceptions import (
    InvalidSeed
)

__all__ = [
    'Token',
    'SERIAL_LENGTH'
]

DEFAULT_DIGITS = 6
DEFAULT_INTERVAL = 60
SERIAL_LENGTH = 12
BCD_TIME_BYTES = [2, 3, 4, 5, 8]


class Token(object):
    """
    Handler for RSA SecurID 128-bit compatible token codes.
    """

    serial: str               # serial number
    seed: Optional[bytes]     # decoded AES key
    interval: int             # interval in seconds (30 or 60)
    digits: int               # tokencode digits
    exp_date: Optional[date]  # expiration date

    def __init__(self,
                 serial: BytesStr = '',
                 seed: Union[Optional[bytes], Optional[str]] = None,
                 interval: int = DEFAULT_INTERVAL,
                 digits: int = DEFAULT_DIGITS,
                 exp_date: Union[Optional[date], Optional[str]] = None) -> None:
        """
            :param serial: token serial number
            :param seed: token seed
            :param interval: time interval in seconds for OTP (default: 60)
            :param digits: number of digits (default: 6)
            :param exp_date: expiration date
        """
        if not isinstance(serial, str):
            serial = str(serial, 'ascii')
        self.serial = serial.zfill(SERIAL_LENGTH)
        if isinstance(seed, str):
            seed = bytes(seed, 'ascii')
        if isinstance(exp_date, str):
            exp_date = date.fromisoformat(exp_date)
        self.seed = seed
        self.interval = interval
        self.digits = digits
        self.exp_date = exp_date

    def generate_otp(self, input: datetime) -> str:
        """
            Generate OTP

            :param input: the time to generate an OTP for
            :returns: OTP code
        """
        if not self.seed:
            raise InvalidSeed('Missing seed')
        key = self.seed
        bcd_time = self._compute_bcd_time(input)
        for bcd_time_bytes in BCD_TIME_BYTES:
            key = aes_ecb_encrypt(key, self._key_from_time(bcd_time, bcd_time_bytes, self.serial))
        return self._output_code(input, key)

    def at(self, for_time: Union[int, datetime]) -> str:
        """
            Generate OTP for the given time
            (accepts either a Unix timestamp integer or a datetime object)

            :param for_time: the time to generate an OTP for
            :returns: OTP code
        """
        if not isinstance(for_time, datetime):
            for_time = datetime.fromtimestamp(int(for_time))
        return self.generate_otp(for_time)

    def now(self) -> str:
        """
            Generate the current time OTP

            :returns: OTP value
        """
        return self.generate_otp(datetime.utcnow())

    def _compute_bcd_time(self, input: datetime) -> bytes:
        """
            Compute BCD time for the given time
        """
        t = input.replace(minute=input.minute & (-2 if self.interval == 30 else -4))
        return binascii.unhexlify(t.strftime('%Y%m%d%H%M0000'))

    def _output_code(self, input: datetime, key: bytes) -> str:
        """
            OTP code output

            :param input: the time to generate an OTP for
            :returns: OTP code
        """
        # key contains 4 consecutive codes
        if self.interval == 30:
            i = ((input.minute & 0x01) << 3) | ((input.second >= 30) << 2)
        else:
            i = (input.minute & 0x03) << 2
        tokencode = (key[i + 0] << 24) | (key[i + 1] << 16) | (key[i + 2] << 8) | key[i + 3]
        return ('0' * self.digits + str(tokencode))[-self.digits:]

    @classmethod
    def _key_from_time(cls, bcd_time: bytes, bcd_time_bytes: int, serial: str) -> bytes:
        key = bytearray(AES_KEY_SIZE)
        arrayset(key, 0xaa, 8)
        arraycpy(key, bcd_time, n=bcd_time_bytes)
        arrayset(key, 0xbb, 4, dest_offset=12)
        # write BCD-encoded partial serial number
        for i, p in enumerate(range(4, 12, 2)):
            key[i + 8] = ((ord(serial[p]) - ord('0')) << 4) | (ord(serial[p + 1]) - ord('0'))
        return bytes(key)

    @classmethod
    def random(cls,
               serial: BytesStr = '',
               interval: int = DEFAULT_INTERVAL,
               digits: int = DEFAULT_DIGITS,
               exp_date: Optional[date] = None) -> 'Token':
        seed = bytes([random.randint(0, 255) for _ in range(0, AES_KEY_SIZE)])
        """
            Generate a new random token

            :param serial: optional token serial number
            :param interval: time interval in seconds for OTP (default: 60)
            :param digits: number of digits (default: 6)
            :param exp_date: expiration date
            :returns: the generated Token instance
        """
        if not serial:
            serial = ''.join([random.choice(string.digits) for _ in range(0, SERIAL_LENGTH)])
        return Token(serial=serial, seed=seed, interval=interval, digits=digits, exp_date=exp_date)

    @classmethod
    def _fmt(cls, k: str, v: Any) -> Any:
        return str(binascii.hexlify(v), 'ascii') if cls.__annotations__[k] in [bytes, Optional[bytes]] else str(v)

    def __repr__(self) -> str:
        return str(dict([(k, self._fmt(k, v)) for k, v in sorted(self.__dict__.items())]))

    def __str__(self) -> str:
        return ' '.join('%s: %s' % (k, self._fmt(k, v)) for k, v in sorted(self.__dict__.items()))
