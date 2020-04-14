#!/usr/bin/env python

import os
import os.path
import json
from datetime import date
from typing import Any, Dict, Optional, Union
from .utils import Bytes
from .token import (
    SERIAL_LENGTH,
    Token,
    AbstractTokenFile
)
from .exceptions import (
    ParseException,
    InvalidSeed,
    InvalidSerial
)

__all__ = [
    'JSONTokenFile',
]


class JSONTokenFile(AbstractTokenFile):
    """
    Handler for JSON file format

    Example:

    {
        "digits": 6,
        "exp_date": "2035-12-31",
        "period": 60,
        "secret": [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25],
        "serial": "000512377827",
        "type": "SecurID"
    }

    """

    filename: Optional[str]
    token: Token

    def __init__(self,
                 filename: Optional[str] = None,
                 data: Union[bytes, bytearray, str, Dict[str, Any], None] = None,
                 token: Optional[Token] = None) -> None:
        """
            :param filename: JSON file path
            :param data: token as string in JSON format or as a dictionary
            :param token: Token instance
        """
        if token is not None:
            self.filename = None
            self.token = token
        elif data is not None:
            if isinstance(data, str):
                data = bytes(data, 'ascii')
            self.filename = None
            self.token = self.json_decode_token(data)
        elif filename is not None:
            self.filename = os.path.expanduser(filename)
            data = self.parse_file(self.filename)
            self.token = self.json_decode_token(data)

    @classmethod
    def parse_file(cls, filename: str) -> bytes:
        """
            Parse JSON file, return content as string

            :param filename: JSON file path
        """
        with open(filename, 'rb') as f:
            return f.read()

    @classmethod
    def json_decode_token(cls, data: Union[Bytes, Dict[str, Any]]) -> Token:
        try:
            if isinstance(data, dict):
                dct = data
            else:
                dct = json.loads(data)
            token = Token(
                digits=dct['digits'],
                interval=dct['period'],
                exp_date=date.fromisoformat(dct['exp_date']) if dct.get('exp_date') else None,
                seed=bytes(dct['secret']),
                serial=dct['serial']
            )
            return token
        except json.decoder.JSONDecodeError as ex:
            raise ParseException(ex)

    def get_token(self, password: Optional[str] = None) -> Token:
        """
            Return the Token instance

            :param password: optional password for decrypting the token
        """
        return self.token

    def export_token(self) -> bytes:
        """
            Export token as JSON
        """
        if not self.token.seed:
            raise InvalidSeed('Missing seed')
        if not self.token.serial:
            raise InvalidSerial('Missing serial')
        if len(self.token.serial) != SERIAL_LENGTH:
            raise InvalidSerial('Serial length != {}'.format(SERIAL_LENGTH))
        j = json.dumps({
            'digits': self.token.digits,
            'period': self.token.interval,
            'exp_date': self.token.exp_date.isoformat() if self.token.exp_date else '',
            'secret': [x for x in self.token.seed],
            'serial': self.token.serial,
            'type': 'SecurID'
        }, sort_keys=True)
        return bytes(j, 'ascii')
