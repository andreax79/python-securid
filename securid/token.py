#!/usr/bin/env python

import binascii
import string
from abc import ABC, abstractmethod
from datetime import datetime, date
from typing import Any, Union, Optional

from .exceptions import InvalidSeed
from .utils import (
    AES_KEY_SIZE,
    BytesStr,
    random,
    Bytearray,
    aes_ecb_encrypt,
    fromisoformat,
)

__all__ = ['Token', 'AbstractTokenFile', 'SERIAL_LENGTH']

DEFAULT_DIGITS = 6
DEFAULT_INTERVAL = 60
SERIAL_LENGTH = 12
BCD_TIME_BYTES = [2, 3, 4, 5, 8]


class Token(object):
    """
    Handler for RSA SecurID 128-bit compatible token codes.
    """

    serial: str  # serial number
    seed: Optional[bytes]  # decoded AES key
    interval: int  # interval in seconds (30 or 60)
    digits: int  # tokencode digits
    exp_date: Optional[date]  # expiration date
    issuer: Optional[str]  # issuer (origin)
    label: Optional[str]  # label (userlogin, serial)
    pin: Optional[int]  # PIN

    def __init__(
        self,
        serial: BytesStr = '',
        seed: Union[Optional[bytes], Optional[str]] = None,
        interval: int = DEFAULT_INTERVAL,
        digits: int = DEFAULT_DIGITS,
        exp_date: Union[Optional[date], Optional[str]] = None,
        issuer: Optional[str] = None,
        label: Optional[str] = None,
        pin: Optional[int] = 0,
    ) -> None:
        """
        :param serial: token serial number
        :param seed: token seed
        :param interval: time interval in seconds for OTP (default: 60)
        :param digits: number of digits (default: 6)
        :param exp_date: expiration date
        :param issuer: issuer
        :param label: label
        :param pin: PIN (default: 0)
        """
        if not isinstance(serial, str):
            serial = str(serial, 'ascii')
        self.serial = serial.zfill(SERIAL_LENGTH)
        if isinstance(seed, str):
            seed = bytes(seed, 'ascii')
        if isinstance(exp_date, str):
            exp_date = fromisoformat(exp_date)
        self.seed = seed
        self.interval = interval
        self.digits = digits
        self.exp_date = exp_date
        self.issuer = issuer
        self.label = label
        self.pin = pin

    def generate_otp(self, input: datetime, pin: Optional[int] = None) -> str:
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
            key = aes_ecb_encrypt(
                key, self._key_from_time(bcd_time, bcd_time_bytes, self.serial)
            )

        return self._token_pin(self._output_code(input, key), pin)

    def at(self, for_time: Union[int, datetime], pin: Optional[int] = None) -> str:
        """
        Generate OTP for the given time
        (accepts either a Unix timestamp integer or a datetime object)

        :param for_time: the time to generate an OTP for
        :returns: OTP code
        """
        if not isinstance(for_time, datetime):
            for_time = datetime.utcfromtimestamp(int(for_time))
        return self.generate_otp(for_time, pin)

    def now(self, pin: Optional[int] = None) -> str:
        """
        Generate the current time OTP

        :returns: OTP value
        """
        return self.generate_otp(datetime.utcnow(), pin)

    def time_left(self, for_time: Union[int, datetime, None] = None) -> int:
        """
        Time until next token

        :returns: seconds
        """
        if for_time is None:
            for_time = datetime.utcnow()
        elif not isinstance(for_time, datetime):
            for_time = datetime.utcfromtimestamp(int(for_time))
        result = (self.interval - for_time.second) % self.interval
        if result == 0:
            result = self.interval
        return result

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
        tokencode = (
            (key[i + 0] << 24) | (key[i + 1] << 16) | (key[i + 2] << 8) | key[i + 3]
        )
        return ('0' * self.digits + str(tokencode))[-self.digits :]

    def _token_pin(self, token: str, pin: Optional[int] = None) -> str:
        """
        Support for RSA PIN

        :param token: the generated OTP token
        :param pin: the RSA PIN to integrate
        :returns: OTP code
        """
        pin = pin if pin is not None else self.pin
        if pin is None:
            return token
        else:
            resolved_token = ""
            for i in range(0, len(token)):
                c = int(token[-1])
                token = token[0:-1]
                c += pin % 10
                pin = int(pin / 10)
                resolved_token = "{}{}".format(int(c % 10), resolved_token)
            return resolved_token

    @classmethod
    def _key_from_time(cls, bcd_time: bytes, bcd_time_bytes: int, serial: str) -> bytes:
        key = Bytearray(AES_KEY_SIZE)
        key.arrayset(0xAA, 8)
        key.arraycpy(bcd_time, n=bcd_time_bytes)
        key.arrayset(0xBB, 4, dest_offset=12)
        # write BCD-encoded partial serial number
        for i, p in enumerate(range(4, 12, 2)):
            key[i + 8] = ((ord(serial[p]) - ord('0')) << 4) | (
                ord(serial[p + 1]) - ord('0')
            )
        return bytes(key)

    @classmethod
    def random(
        cls,
        serial: BytesStr = '',
        interval: int = DEFAULT_INTERVAL,
        digits: int = DEFAULT_DIGITS,
        exp_date: Optional[date] = None,
        issuer: Optional[str] = None,
        label: Optional[str] = None,
        pin: Optional[int] = None,
    ) -> 'Token':
        seed = bytes([random.randint(0, 255) for _ in range(0, AES_KEY_SIZE)])
        """
            Generate a new random token

            :param serial: optional token serial number
            :param interval: time interval in seconds for OTP (default: 60)
            :param digits: number of digits (default: 6)
            :param exp_date: expiration date
            :param issuer: issuer
            :param label: label
            :param pin: PIN
            :returns: the generated Token instance
        """
        if not serial:
            serial = ''.join(
                [random.choice(string.digits) for _ in range(0, SERIAL_LENGTH)]
            )
        return Token(
            serial=serial,
            seed=seed,
            interval=interval,
            digits=digits,
            exp_date=exp_date,
            issuer=issuer,
            label=label,
            pin=pin,
        )

    @classmethod
    def _fmt(cls, k: str, v: Any) -> str:
        if v is None:
            return ''
        elif cls.__annotations__[k] in [bytes, Optional[bytes]]:
            return str(binascii.hexlify(v), 'ascii')
        else:
            return str(v)

    def __repr__(self) -> str:
        return str(
            dict([(k, self._fmt(k, v)) for k, v in sorted(self.__dict__.items())])
        )

    def __str__(self) -> str:
        return ' '.join(
            '%s: %s' % (k, self._fmt(k, v)) for k, v in sorted(self.__dict__.items())
        )

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Token) and self.__dict__ == other.__dict__

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)


class AbstractTokenFile(ABC):
    """
    Abstract token files handler
    """

    @abstractmethod
    def get_token(self, password: Optional[str] = None) -> Token:  # pragma: no cover
        """
        Return the Token instance

        :param password: optional password for decrypting the token
        """
        raise NotImplementedError
