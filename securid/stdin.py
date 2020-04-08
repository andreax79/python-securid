#!/usr/bin/env python

import base64
from datetime import date
from typing import Any, Optional, Dict
from collections import OrderedDict
from xml.etree import cElementTree as ET
from .token import Token
from .utils import (
    AES_BLOCK_SIZE,
    AES_KEY_SIZE,
    BytesStr,
    arrayset,
    arraycpy,
    aes_ecb_encrypt,
    xor_block,
    cbc_hash
)
from .exceptions import (
    ParseException,
    InvalidSignature
)

__all__ = [
    'StdinFile',
]

TOKEN_ENC_IV  = bytes([0x16, 0xa0, 0x9e, 0x66, 0x7f, 0x3b, 0xcc, 0x90,
                       0x8b, 0x2f, 0xb1, 0x36, 0x6e, 0xa9, 0x57, 0xd3])
BATCH_MAC_IV  = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
TOKEN_MAC_IV  = bytes([0x1b, 0xb6, 0x7a, 0xe8, 0x58, 0x4c, 0xaa, 0x73,
                       0xb2, 0x57, 0x42, 0xd7, 0x07, 0x8b, 0x83, 0xb8])
MAX_HASH_DATA = 65536


class StdinFile(object):
    """
    Handler for RSA SecurID stdin XML file format.
    """

    filename: str
    values: Dict[str, Any]  # stdin values as OrderedDict
    token: Token

    def __init__(self, filename: str):
        self.filename = filename
        self.parse_file(filename)

    def parse_file(self, filename) -> None:
        try:
            xml = ET.XML(open(filename, 'r').read())
        except ET.ParseError:
            raise ParseException('Error parsing {}'.format(filename))
        self.values = self.xml_to_dict(xml)
        serial = self.get('SN')
        interval = self.get('Interval', default=60, kind='int')
        digits = self.get('Digits', default=6, kind='int')
        exp_date = self.get('Death', kind='date')
        self.token = Token(serial=serial, interval=interval, digits=digits, exp_date=exp_date)

    def get_token(self, password: Optional[str] = None) -> Token:
        """
            Return the Token instance

            :param password: optional password for decrypting the token
        """
        if self.token.seed is None:
            self.token.seed = self.decrypt_seed(password)
        return self.token

    def decrypt_seed(self, password: Optional[str] = None) -> bytes:
        secret = self.get('Secret', kind='base64')
        dest = self.get('Dest')
        name = self.get('Name')
        if password is None:
            password = self.get('Origin')
        key = self.decrypt_secret(secret, name, self.hash_password(password, dest, name))
        self.verify_mac('Header', 'BatchMAC', self.get('Name'), 'HeaderMAC', 'TKNHeader', key, BATCH_MAC_IV)
        self.verify_mac('Token', 'TokenMAC', self.get('SN'), 'TokenMAC', 'TKN', key, TOKEN_MAC_IV)
        enc_seed = self.get('Seed', kind='base64')
        token_enc_key = self.calc_key('TokenEncrypt', self.token.serial, key, TOKEN_ENC_IV)
        return self.decrypt_enc_seed(enc_seed, self.token.serial, token_enc_key)

    def verify_mac(self, kind: str, str0: str, str1: str, node: str, section: str, key1: bytes, iv: bytes) -> None:
        mac_key = self.calc_key(str0, str1, key1, iv)
        mac = self.get(node, kind='base64')
        hs = SessionHash()
        hs.recursive_hash(section, self.values['TKNBatch'][section])
        mac_calc = hs.compute_hash(mac_key, iv)
        if mac != mac_calc:
            raise InvalidSignature('{} MAC check failed'.format(kind))

    @classmethod
    def hash_password(cls, password: str, salt0: str, salt1: str) -> bytes:
        key = bytearray(AES_KEY_SIZE)
        arraycpy(key, salt1)

        data = bytearray(0x50)
        arraycpy(data, password, n=0x20)
        arraycpy(data, salt0, n=0x20, dest_offset=0x20)

        result = bytes(AES_KEY_SIZE)
        iv = bytes(AES_BLOCK_SIZE)
        for i in range(0, 1000):
            data[0x4f] = (i >> 0) % 256
            data[0x4e] = (i >> 8) % 256
            result = xor_block(result, cbc_hash(key, iv, data))
        return bytes(result)

    @classmethod
    def decrypt_secret(cls, enc_bin: bytes, str0: bytes, key: bytes) -> bytes:
        result = bytearray(AES_KEY_SIZE)
        arraycpy(result, 'Secret', n=8)
        arraycpy(result, str0, n=8, dest_offset=8)
        return xor_block(aes_ecb_encrypt(key, result), enc_bin)

    @classmethod
    def decrypt_enc_seed(cls, enc_bin: bytes, str0: str, key: bytes) -> bytes:
        result = bytearray(AES_KEY_SIZE)
        arraycpy(result, str0, n=8)
        arraycpy(result, 'Seed', n=8, dest_offset=8)
        return xor_block(aes_ecb_encrypt(key, result), enc_bin)

    @classmethod
    def calc_key(cls, str0: str, str1: str, key: bytes, iv: bytes) -> bytes:
        data = bytearray(64)
        arraycpy(data, str0, n=32)
        arraycpy(data, str1, n=32, dest_offset=32)
        return cbc_hash(key, iv, data)

    @classmethod
    def xml_to_dict(cls, xml: ET.Element) -> Dict[str, Any]:
        """
            Convert XML to nested OrderDict
        """
        if xml:
            dd: Dict[str, Any] = OrderedDict()
            for dc in map(cls.xml_to_dict, list(xml)):
                for k, v in dc.items():
                    if k in dd:
                        if not isinstance(dd[k], list):
                            dd[k] = [dd[k]]
                        dd[k].append(v)
                    else:
                        dd[k] = v
            return OrderedDict({xml.tag: dd})
        else:
            return OrderedDict({xml.tag: (xml.text or '').strip()})

    def get(self, name: str, default: Any = None, kind: Optional[str] = None) -> Any:
        value = self.values['TKNBatch']['TKN'].get(name)
        if value is None:
            value = self.values['TKNBatch']['TKNHeader'].get(name)
        if value is None:
            value = self.values['TKNBatch']['TKNHeader'].get('Def' + name)
        if value is None:
            value = default
        if kind == 'base64':
            if value[0] == '=':
                value = value[1:]
            value = base64.b64decode(value)
        elif kind == 'int':
            value = int(value)
        elif kind == 'date':
            value = date.fromisoformat(value.replace('/', '-'))
        return value


class SessionHash(object):
    pos: int = 0
    padding: int = 0
    data: bytearray

    def __init__(self) -> None:
        self.data = bytearray(MAX_HASH_DATA)

    def recursive_hash(self, name: str, node: Dict[str, Any]) -> None:
        for k, v in node.items():
            if k.endswith('MAC'):
                continue
            longname = '%s.%s' % (name, k)
            remain = MAX_HASH_DATA - self.pos
            if isinstance(v, dict):
                self.recursive_hash(longname, v)
            else:
                if not v:
                    # An empty string is valid XML but it might violate
                    # the sdtid format.  We'll handle it the same bizarre
                    # way as RSA just to be safe.
                    data = '%s </%s>\n' % (longname, name)
                    self._append_data(data)
                else:
                    data = '%s %s\n' % (longname, v)
                    self._append_data(data)
                    length = len(data) + self.padding
                    if length <= 16 and length < remain:
                        self.pos = self.pos & ~0xf
                        self._append_data(data, n=min(len(data), remain))
                        arrayset(self.data, 0, dest_offset=self.pos + len(data), n=self.padding)
                #  This doesn't really make sense but it's required for compatibility
                self.pos = self.pos + len(data) + self.padding
                self.padding = self.pos & 0xf or 0x10

    def _append_data(self, data: BytesStr, n: Optional[int] = None) -> None:
        if isinstance(data, str):
            data = bytes(data, 'ascii')
        if n is None:
            n = len(data)
        self.data[self.pos:self.pos + n] = data[:n]

    def compute_hash(self, key: bytes, iv: bytes) -> bytes:
        return cbc_hash(key, iv, self.data[0:self.pos])
