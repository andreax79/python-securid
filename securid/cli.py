#!/usr/bin/env python

import sys
import argparse
from .stoken import StokenFile, DEFAULT_STOKEN_FILENAME
from .stdin import StdinFile
from .exceptions import (
    ParseException,
    InvalidSignature
)

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--filename',
            dest='filename',
            default=DEFAULT_STOKEN_FILENAME)
    parser.add_argument('--password',
            dest='password')
    parser.add_argument('-v', '--verbose',
            help="verbose output",
            action='store_true',
            dest='verbose')
    args = parser.parse_args()

    try:
        try:
            f = StokenFile(args.filename)
            token = f.get_token()
        except (FileNotFoundError, ParseException):
            f = StdinFile(args.filename)
        token = f.get_token(args.password)
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
