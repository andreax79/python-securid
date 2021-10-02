#!/usr/bin/env python

import os
import sys
import time
from datetime import datetime
import argparse
from typing import Optional, List, NoReturn
from .token import AbstractTokenFile, Token
from .stoken import StokenFile, DEFAULT_STOKEN_FILENAME
from .sdtid import SdtidFile
from .jsontoken import JSONTokenFile
from .exceptions import ParseException, InvalidSignature

__all__ = ['show_token', 'export', 'interactive', 'show_version', 'main']

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_PARSER_ERROR = 2


def show_token(token: Token, pin: Optional[int] = None, verbose: bool = False) -> int:
    "Show token"
    if verbose:
        for_time = datetime.utcnow()
        print(token)
        print('{} {:2}s'.format(token.at(for_time, pin=pin), token.time_left(for_time)))
    else:
        print(token.now(pin=pin))
    return EXIT_SUCCESS


def export(token: Token) -> int:
    "Export token into JSON"
    f = JSONTokenFile(token=token)
    sys.stdout.buffer.write(f.export_token())
    sys.stdout.buffer.write(b'\n')
    return EXIT_SUCCESS


def interactive(token: Token, test: bool = False, pin: Optional[int] = None) -> int:
    "Show the code every second until interrupted"
    try:
        while True:
            for_time = datetime.utcnow()
            left = token.time_left(for_time)
            bar = ('#' * left) + ('.' * (token.interval - left))
            print('{} {:2}s [{}]'.format(token.at(for_time, pin=pin), left, bar))
            if test:
                raise KeyboardInterrupt
            time.sleep(1)
            sys.stdout.write("\033[F\033[K")
    except KeyboardInterrupt:
        pass
    return EXIT_SUCCESS


def show_version(prog: str) -> int:
    "Show version"
    from . import __version__

    print("{} {}".format(prog, __version__))
    return EXIT_SUCCESS


class ArgumentParserException(Exception):
    pass


class ArgumentParser(argparse.ArgumentParser):
    def exit(self, status: int = 0, message: Optional[str] = None) -> NoReturn:
        if message:
            self._print_message(message, sys.stderr)
        raise ArgumentParserException()


def main(args: Optional[List[str]] = None) -> int:
    prog = os.path.basename(sys.argv[0])
    parser = ArgumentParser()
    parser.add_argument(
        '-f',
        '--filename',
        help="token file (sdtid, stokenrc or json)",
        dest='filename',
        default=DEFAULT_STOKEN_FILENAME,
    )
    parser.add_argument('--password', dest='password')
    parser.add_argument('--pin', type=int, dest='pin')
    parser.add_argument(
        '--export', help="export token into JSON", action='store_true', dest='export'
    )
    parser.add_argument(
        '-i',
        '--interactive',
        help="show the code every second until interrupted",
        action='store_true',
        dest='interactive',
    )
    parser.add_argument(
        '-v', '--verbose', help="verbose output", action='store_true', dest='verbose'
    )
    parser.add_argument(
        '-V',
        '--version',
        help="show version and exit",
        action='store_true',
        dest='version',
    )
    try:
        cli_args = parser.parse_args(args=args)
        if cli_args.version:
            return show_version(prog)
        try:
            f: AbstractTokenFile = JSONTokenFile(cli_args.filename)
        except (FileNotFoundError, ParseException):
            try:
                f = StokenFile(cli_args.filename)
            except (FileNotFoundError, ParseException):
                f = SdtidFile(cli_args.filename)
        token = f.get_token(cli_args.password)
        if cli_args.export:
            return export(token)
        elif cli_args.interactive:
            return interactive(token, pin=cli_args.pin)
        else:
            return show_token(token, pin=cli_args.pin, verbose=cli_args.verbose)
    except ArgumentParserException:
        return EXIT_PARSER_ERROR
    except InvalidSignature:
        if cli_args.password:
            message = "Incorrect password"
        else:
            message = "Error decrypting token - please provide a password"
        print("{}: error: {}".format(prog, message), file=sys.stderr)
        return EXIT_FAILURE
    except Exception as ex:
        print("{}: error: {}".format(prog, ex), file=sys.stderr)
        return EXIT_FAILURE
