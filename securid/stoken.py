#!/usr/bin/env python

import os
import os.path
import math
from datetime import date
from typing import Union, Optional
from .token import SERIAL_LENGTH, Token, AbstractTokenFile
from .utils import AES_KEY_SIZE, Bytes, aes_ecb_encrypt, aes_ecb_decrypt, Bytearray
from .exceptions import (
    ParseException,
    InvalidToken,
    InvalidSignature,
    InvalidSeed,
    InvalidSerial,
)

__all__ = ['DEFAULT_STOKEN_FILENAME', 'StokenFile']

DEFAULT_STOKEN_FILENAME = '~/.stokenrc'
FL_128BIT = 1 << 14
FL_PASSPROT = 1 << 13
FL_SNPROT = 1 << 12
FL_APPSEEDS = 1 << 11
FL_FEAT4 = 1 << 10
FL_TIMESEEDS = 1 << 9
FLD_DIGIT_SHIFT = 6
FLD_DIGIT_MASK = 0x07 << FLD_DIGIT_SHIFT
FLD_PINMODE_SHIFT = 3
FLD_PINMODE_MASK = 0x03 << FLD_PINMODE_SHIFT
FLD_NUMSECONDS_SHIFT = 0
FLD_NUMSECONDS_MASK = 0x03 << FLD_NUMSECONDS_SHIFT
TOKEN_BITS_PER_CHAR = 3
STOKEN_MAGIC = bytes([0xD8, 0xF5, 0x32, 0x53, 0x82, 0x89])
VER_LENGTH = 1
CHECKSUM_BITS = 15
CHECKSUM_LENGTH = int(CHECKSUM_BITS / TOKEN_BITS_PER_CHAR)
BINENC_BITS = 189
BINENC_OFS = VER_LENGTH + SERIAL_LENGTH
MIN_TOKEN_BITS = 189
MAX_TOKEN_BITS = 255
MAX_TOKEN_LENGTH = int(MAX_TOKEN_BITS / TOKEN_BITS_PER_CHAR)
MIN_TOKEN_LENGTH = int(
    (MIN_TOKEN_BITS / TOKEN_BITS_PER_CHAR)
    + SERIAL_LENGTH
    + VER_LENGTH
    + CHECKSUM_LENGTH
)
SECURID_EPOCH = 730120  # 2000/01/01 proleptic Gregorian ordinal


class StokenFile(AbstractTokenFile):
    """
    Handler for stokenrc file format
    """

    filename: Optional[str]
    data: Optional[bytes]
    token: Token

    def __init__(
        self,
        filename: Optional[str] = DEFAULT_STOKEN_FILENAME,
        data: Union[Optional[bytes], Optional[bytearray], Optional[str]] = None,
        token: Optional[Token] = None,
    ) -> None:
        """
        :param filename: stokenrc file path
        :param data: token as string in stokenrc format
        :param token: Token instance
        """
        if token is not None:
            self.filename = None
            self.token = token
        elif data is not None:
            if isinstance(data, str):
                data = bytes(data, 'ascii')
            self.filename = None
            self.data = data
            self.token = self.v2_decode_token(self.data)
        elif filename is not None:
            self.filename = os.path.expanduser(filename)
            self.data = self.parse_file(self.filename)
            self.token = self.v2_decode_token(self.data)
            self.token.pin = self.parse_file_pin(self.filename)

    @classmethod
    def parse_file(cls, filename: str) -> bytes:
        """
        Parse stokenrc file, return token as string

        :param filename: stokenrc file path
        """
        with open(filename, 'rb') as f:
            for line in f.readlines():
                line = line.strip()
                if b' ' in line:
                    k, v = line.split(b' ', 1)
                    if k == b'token':
                        return v
        raise ParseException('Error parsing {}'.format(filename))

    @classmethod
    def parse_file_pin(cls, filename: str) -> int:
        """
        Parse stokenrc file, return pin as int or 0 if not found

        :param filename: stokenrc file path
        """
        with open(filename, 'rb') as f:
            for line in f.readlines():
                line = line.strip()
                if b' ' in line:
                    k, v = line.split(b' ', 1)
                    if k == b'pin':
                        return int(v)
        return 0

    @classmethod
    def v2_decode_token(cls, data: Bytes) -> Token:
        if len(data) < MIN_TOKEN_LENGTH or len(data) > MAX_TOKEN_LENGTH:
            raise InvalidToken('Invalid token length')
        cls._verify_checksum(data)
        # version = data[0] - ord('0')
        d = cls._numinput_to_bits(data, BINENC_BITS, offset=BINENC_OFS)
        enc_seed = d[0:AES_KEY_SIZE]
        flags = cls._get_bits(d, 128, 16)
        seed_hash = cls._get_bits(d, 159, 15)
        exp_date = date.fromordinal(cls._get_bits(d, 144, 14) + SECURID_EPOCH)
        serial = str(data[VER_LENGTH : VER_LENGTH + SERIAL_LENGTH], 'ascii')
        interval = 60 if ((flags & FLD_NUMSECONDS_MASK) >> FLD_NUMSECONDS_SHIFT) else 30
        digits = ((flags & FLD_DIGIT_MASK) >> FLD_DIGIT_SHIFT) + 1
        seed = cls.v2_decrypt_seed(enc_seed, seed_hash)
        return Token(
            serial=serial,
            seed=seed,
            interval=interval,
            digits=digits,
            exp_date=exp_date,
        )

    def v2_encode_token(self) -> None:
        if not self.token.seed:
            raise InvalidSeed('Missing seed')
        if not self.token.serial:
            raise InvalidSerial('Missing serial')
        if len(self.token.serial) != SERIAL_LENGTH:
            raise InvalidSerial('Serial length != {}'.format(SERIAL_LENGTH))
        flags = FL_TIMESEEDS | FL_128BIT
        flags |= (self.token.digits - 1 << FLD_DIGIT_SHIFT) & FLD_DIGIT_MASK
        flags |= (1 << FLD_NUMSECONDS_SHIFT) if self.token.interval == 60 else 0

        key_hash = self._securid_mac(STOKEN_MAGIC)
        enc_seed = aes_ecb_encrypt(key_hash, self.token.seed)
        seed_hash = self._short_hash(self._securid_mac(self.token.seed))

        d = Bytearray(int(MAX_TOKEN_BITS / 8 + 2))
        d.arraycpy(enc_seed, n=AES_KEY_SIZE, dest_offset=0)
        self._set_bits(d, 128, 16, flags)
        self._set_bits(d, 159, 15, seed_hash)
        self._set_bits(
            d,
            144,
            14,
            (self.token.exp_date.toordinal() - SECURID_EPOCH)
            if self.token.exp_date
            else 0,
        )

        data = Bytearray(81)
        data.arraycpy(b'2', dest_offset=0)  # version
        data.arraycpy(self._bits_to_numoutput(d, BINENC_BITS), dest_offset=BINENC_OFS)
        data.arraycpy(self.token.serial, n=SERIAL_LENGTH, dest_offset=VER_LENGTH)

        d = Bytearray(int(MAX_TOKEN_BITS / 8 + 2))
        computed_mac = self._securid_shortmac(data[: len(data) - CHECKSUM_LENGTH])
        self._set_bits(d, 0, 15, computed_mac)
        t = self._bits_to_numoutput(d, 15)
        data.arraycpy(t, dest_offset=len(data) - CHECKSUM_LENGTH)

        self._verify_checksum(data)
        self.data = bytes(data)

    @classmethod
    def _verify_checksum(cls, data: Bytes) -> None:
        d = cls._numinput_to_bits(data, 15, offset=len(data) - CHECKSUM_LENGTH)
        token_mac = cls._get_bits(d, 0, 15)
        computed_mac = cls._securid_shortmac(data[: len(data) - CHECKSUM_LENGTH])
        if token_mac != computed_mac:
            raise InvalidSignature('Invalid checksum')

    @classmethod
    def _numinput_to_bits(cls, data: Bytes, n_bits: int, offset: int = 0) -> bytes:
        bitpos = 13
        out = bytearray(int(MAX_TOKEN_BITS / 8 + 2))
        pos = 0
        for t in data[offset:]:
            decoded = (t - ord('0')) & 0x07
            decoded = decoded << bitpos
            out[0 + pos] = out[0 + pos] | decoded >> 8
            out[1 + pos] = out[1 + pos] | decoded & 0xFF
            bitpos = bitpos - TOKEN_BITS_PER_CHAR
            if bitpos < 0:
                bitpos = bitpos + 8
                pos = pos + 1
            n_bits = n_bits - TOKEN_BITS_PER_CHAR
            if not n_bits:
                break
        return bytes(out)

    @classmethod
    def _bits_to_numoutput(cls, data: Bytes, n_bits: int) -> bytes:
        bitpos = 13
        out = bytearray()
        pos = 0
        for i in range(n_bits, 0, -TOKEN_BITS_PER_CHAR):
            binary = (data[pos] << 8) | data[pos + 1]
            out.append(((binary >> bitpos) & 0x07) + ord('0'))
            bitpos -= TOKEN_BITS_PER_CHAR
            if bitpos < 0:
                bitpos = bitpos + 8
                pos = pos + 1
        return bytes(out)

    @classmethod
    def _get_bits(cls, data: Bytes, start: int, n_bits: int) -> int:
        pos = int(math.floor(start / 8))
        start = start % 8
        val = 0
        for i in range(n_bits, 0, -1):
            val = val << 1
            if (data[pos] << start) & 0x80:
                val = val | 0x01
            start = start + 1
            if start == 8:
                start = 0
                pos = pos + 1
        return val

    @classmethod
    def _set_bits(cls, out: bytearray, start: int, n_bits: int, val: int) -> None:
        pos = int(math.floor(start / 8))
        start = start % 8
        val = val << (32 - n_bits)
        for i in range(n_bits, 0, -1):
            if val & (1 << 31):
                out[pos] = out[pos] | (1 << (7 - start))
            else:
                out[pos] = out[pos] & ~(1 << (7 - start))
            val = val << 1
            start = start + 1
            if start == 8:
                start = 0
                pos = pos + 1

    @classmethod
    def _encrypt_then_xor(cls, key: Bytes, work: bytes) -> bytes:
        out = aes_ecb_encrypt(key, work)
        return bytes([a ^ b for a, b in zip(work, out)])

    @classmethod
    def _securid_mac(cls, data: Bytes) -> bytes:
        # padding
        pad = bytearray(AES_KEY_SIZE)
        p = AES_KEY_SIZE - 1
        i = len(data) * 8
        while i > 0:
            pad[p] = i % 256
            p = p - 1
            i = i >> 8
        # handle the bulk of the input data here
        odd = False
        t = data
        work = bytes([0xFF] * AES_KEY_SIZE)
        while len(t) > AES_KEY_SIZE:
            work = cls._encrypt_then_xor(t[:AES_KEY_SIZE], work)
            t = t[AES_KEY_SIZE:]
            odd = not odd
        # final 0-16 bytes of input data
        work = cls._encrypt_then_xor(t + bytes(AES_KEY_SIZE - len(t)), work)
        # hash an extra block of zeroes, for certain input lengths
        if odd:
            zero = bytearray(AES_KEY_SIZE)
            work = cls._encrypt_then_xor(zero, work)
        # always hash the padding
        work = cls._encrypt_then_xor(pad, work)
        # run hash over current hash value, then return
        return cls._encrypt_then_xor(work, work)

    @classmethod
    def _short_hash(cls, hash_: Bytes) -> int:
        return (hash_[0] << 7) | (hash_[1] >> 1)

    @classmethod
    def _securid_shortmac(cls, data: Bytes) -> int:
        return cls._short_hash(cls._securid_mac(data))

    @classmethod
    def v2_decrypt_seed(cls, enc_seed: Bytes, seed_hash: int) -> bytes:
        key_hash = cls._securid_mac(STOKEN_MAGIC)
        seed = aes_ecb_decrypt(key_hash, enc_seed)
        calc_seed_hash = cls._short_hash(cls._securid_mac(seed))
        if calc_seed_hash != seed_hash:
            raise InvalidSignature('Seed decryption failed')
        return seed

    def get_token(self, password: Optional[str] = None) -> Token:
        """
        Return the Token instance
        """
        return self.token
