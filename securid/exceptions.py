#!/usr/bin/env python

__all__ = [
    'ParseException',
    'InvalidToken',
    'InvalidSignature',
    'InvalidSeed',
    'InvalidSerial',
]


class ParseException(Exception):
    """
    This is raised in case of error parsing file
    """

    pass


class InvalidToken(Exception):
    """
    This is raised in case of invalid token
    """

    pass


class InvalidSignature(Exception):
    """
    This is raised when signature verification fails.
    This can occur when password is required for decrypting the token.
    """


class InvalidSeed(Exception):
    """
    This is raised when the seed is missing or invalid.
    """


class InvalidSerial(Exception):
    """
    This is raised when the serial is missing or invalid.
    """
