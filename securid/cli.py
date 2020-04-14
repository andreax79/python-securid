#!/usr/bin/env python

import sys
import argparse
from .token import AbstractTokenFile
from .stoken import StokenFile, DEFAULT_STOKEN_FILENAME
from .sdtid import SdtidFile
from .jsontoken import JSONTokenFile
from .exceptions import (
    ParseException,
    InvalidSignature
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--filename',
                        help="token file (sdtid, stokenrc or json)",
                        dest='filename',
                        default=DEFAULT_STOKEN_FILENAME)
    parser.add_argument('--password',
                        dest='password')
    parser.add_argument('-v', '--verbose',
                        help="verbose output",
                        action='store_true',
                        dest='verbose')
    parser.add_argument('--export',
                        help="export token into JSON",
                        action='store_true',
                        dest='export')
    args = parser.parse_args()

    try:
        try:
            f: AbstractTokenFile = JSONTokenFile(args.filename)
            token = f.get_token()
        except (FileNotFoundError, ParseException):
            try:
                f = StokenFile(args.filename)
                token = f.get_token()
            except (FileNotFoundError, ParseException):
                f = SdtidFile(args.filename)
        token = f.get_token(args.password)
        if args.export:
            f = JSONTokenFile(token=token)
            sys.stdout.buffer.write(f.export_token())
            sys.stdout.buffer.write(b'\n')
        else:
            if args.verbose:
                print(token)
            print(token.now())
            sys.exit(0)
    except InvalidSignature:
        if args.password:
            print("Incorrect password", file=sys.stderr)
        else:
            print("Error decrypting token - please provide a password", file=sys.stderr)
        sys.exit(1)
    except Exception as ex:
        print(ex, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
