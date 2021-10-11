#!/usr/bin/env python

from dataclasses import dataclass
from secrets import choice

import argparse
import sys

LETTERS_LC = 'abcdefghijklmnoprqstuvwxyz'
LETTERS_UC = LETTERS_LC.upper()
NUMBERS = '0123456789'


def main():
    options = get_options()
    chars = LETTERS_UC + LETTERS_LC + NUMBERS

    password = ''.join(choice(chars) for _ in range(options.length))

    if options.newline:
        print(password)
    else:
        sys.stdout.write(password)


@dataclass
class Options:
    """Command line options"""

    length: int
    newline: bool


def get_options(*args) -> Options:
    """Get the options for execution"""

    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--length", type=int, default=63)

    newline_group = parser.add_mutually_exclusive_group()

    newline_group.add_argument("--newline",
                               action="store_const",
                               const=True,
                               dest="newline")

    newline_group.add_argument("--no-newline",
                               action="store_const",
                               const=False,
                               dest="newline")

    args = parser.parse_args(*args)

    length = args.length
    newline = args.newline

    if newline is None:
        if sys.stdout.isatty():
            newline = True
        else:
            newline = False

    return Options(length=length, newline=newline)


if __name__ == "__main__":
    main()
