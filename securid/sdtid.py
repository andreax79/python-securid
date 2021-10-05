#!/usr/bin/env python

import base64
from datetime import date
from typing import Any, Optional, Dict
from collections import OrderedDict
from xml.etree import cElementTree as ET
from .token import Token, AbstractTokenFile
from .utils import (
    AES_BLOCK_SIZE,
    AES_KEY_SIZE,
    BytesStr,
    Bytearray,
    aes_ecb_encrypt,
    xor_block,
    cbc_hash,
    fromisoformat,
)
from .exceptions import ParseException, InvalidSignature

__all__ = [
    'SdtidFile',
]

TOKEN_ENC_IV = bytes(
    [
        0x16,
        0xA0,
        0x9E,
        0x66,
        0x7F,
        0x3B,
        0xCC,
        0x90,
        0x8B,
        0x2F,
        0xB1,
        0x36,
        0x6E,
        0xA9,
        0x57,
        0xD3,
    ]
)
BATCH_MAC_IV = bytes(
    [
        0x2B,
        0x7E,
        0x15,
        0x16,
        0x28,
        0xAE,
        0xD2,
        0xA6,
        0xAB,
        0xF7,
        0x15,
        0x88,
        0x09,
        0xCF,
        0x4F,
        0x3C,
    ]
)
TOKEN_MAC_IV = bytes(
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
MAX_HASH_DATA = 65536


class SdtidFile(AbstractTokenFile):
    """
    Handler for RSA SecurID sdtid XML file format.
    """

    filename: str
    values: Dict[str, Any]  # sdtid file as OrderedDict
    token: Token

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.parse_file(filename)

    def parse_file(self, filename: str) -> None:
        """
        Parse sdtid file

        :param filename: sdtid file path
        """
        try:
            with open(filename, 'r') as f:
                xml = ET.XML(f.read())
        except ET.ParseError:
            raise ParseException('Error parsing {}'.format(filename))
        self.values = self.xml_to_dict(xml)
        serial = self.get('SN')
        interval = self.get('Interval', default=60, kind='int')
        digits = self.get('Digits', default=6, kind='int')
        exp_date = self.get('Death', kind='date')
        issuer = self.get('Origin')
        label = self.get('UserLogin') or serial
        self.token = Token(
            serial=serial,
            interval=interval,
            digits=digits,
            exp_date=exp_date,
            issuer=issuer,
            label=label,
        )

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
        key = self.decrypt_secret(
            secret, name, self.hash_password(password, dest, name)
        )
        self.verify_mac(
            'Header',
            'BatchMAC',
            self.get('Name'),
            'HeaderMAC',
            'TKNHeader',
            key,
            BATCH_MAC_IV,
        )
        self.verify_mac(
            'Token', 'TokenMAC', self.get('SN'), 'TokenMAC', 'TKN', key, TOKEN_MAC_IV
        )
        enc_seed = self.get('Seed', kind='base64')
        token_enc_key = self.calc_key(
            'TokenEncrypt', self.token.serial, key, TOKEN_ENC_IV
        )
        return self.decrypt_enc_seed(enc_seed, self.token.serial, token_enc_key)

    def verify_mac(
        self,
        kind: str,
        str0: str,
        str1: str,
        node: str,
        section: str,
        key1: bytes,
        iv: bytes,
    ) -> None:
        mac_key = self.calc_key(str0, str1, key1, iv)
        mac = self.get(node, kind='base64')
        hs = SessionHash()
        hs.recursive_hash(section, self.values['TKNBatch'][section])
        mac_calc = hs.compute_hash(mac_key, iv)
        if mac != mac_calc:
            raise InvalidSignature('{} MAC check failed'.format(kind))

    @classmethod
    def hash_password(cls, password: str, salt0: str, salt1: str) -> bytes:
        key = Bytearray(AES_KEY_SIZE)
        key.arraycpy(salt1)

        data = Bytearray(0x50)
        data.arraycpy(password, n=0x20)
        data.arraycpy(salt0, n=0x20, dest_offset=0x20)

        result = bytes(AES_KEY_SIZE)
        iv = bytes(AES_BLOCK_SIZE)
        for i in range(0, 1000):
            data[0x4F] = (i >> 0) % 256
            data[0x4E] = (i >> 8) % 256
            result = xor_block(result, cbc_hash(key, iv, data))
        return bytes(result)

    @classmethod
    def decrypt_secret(cls, enc_bin: bytes, str0: bytes, key: bytes) -> bytes:
        buf = Bytearray(AES_KEY_SIZE)
        buf.arraycpy('Secret', n=8)
        buf.arraycpy(str0, n=8, dest_offset=8)
        return xor_block(aes_ecb_encrypt(key, buf), enc_bin)

    @classmethod
    def decrypt_enc_seed(cls, enc_bin: bytes, str0: str, key: bytes) -> bytes:
        buf = Bytearray(AES_KEY_SIZE)
        buf.arraycpy(str0, n=8)
        buf.arraycpy('Seed', n=8, dest_offset=8)
        return xor_block(aes_ecb_encrypt(key, buf), enc_bin)

    @classmethod
    def calc_key(cls, str0: str, str1: str, key: bytes, iv: bytes) -> bytes:
        buf = Bytearray(64)
        buf.arraycpy(str0, n=32)
        buf.arraycpy(str1, n=32, dest_offset=32)
        return cbc_hash(key, iv, buf)

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
            return OrderedDict({xml.tag: (xml.text or '')})

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
            value = fromisoformat(value.replace('/', '-'))
        return value


class SessionHash(object):
    pos: int = 0
    padding: int = 0
    data: Bytearray

    def __init__(self) -> None:
        self.data = Bytearray(MAX_HASH_DATA)

    def recursive_hash(self, name: str, node: Dict[str, Any]) -> None:
        # from https://github.com/cernekee/stoken
        for k, v in node.items():
            if k.endswith('MAC'):
                continue
            longname = '%s.%s' % (name, k)
            remain = MAX_HASH_DATA - self.pos
            if isinstance(v, dict):
                self.recursive_hash(longname, v)
            else:
                if not v:
                    # "An empty string is valid XML but it might violate
                    # the sdtid format.  We'll handle it the same bizarre
                    # way as RSA just to be safe."
                    data = '%s </%s>\n' % (longname, name)
                    self._append_data(data)
                else:
                    data = '%s %s\n' % (longname, v)
                    self._append_data(data)
                    length = len(data) + self.padding
                    if length <= 16 and length < remain:
                        self.pos = self.pos & ~0xF
                        self._append_data(data, n=min(len(data), remain))
                        self.data.arrayset(
                            0, dest_offset=self.pos + len(data), n=self.padding
                        )
                #  This doesn't really make sense but it's required for compatibility
                self.pos = self.pos + len(data) + self.padding
                self.padding = self.pos & 0xF or 0x10

    def _append_data(self, data: BytesStr, n: Optional[int] = None) -> None:
        if isinstance(data, str):
            data = bytes(data, 'ascii')
        if n is None:
            n = len(data)
        self.data[self.pos : self.pos + n] = data[:n]

    def compute_hash(self, key: bytes, iv: bytes) -> bytes:
        return cbc_hash(key, iv, self.data[0 : self.pos])
