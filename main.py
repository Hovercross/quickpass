#!/usr/bin/env python

from dataclasses import dataclass
from secrets import choice
from functools import cached_property

import argparse
import sys
import string


def main():
    options = read_arguments()
    password = options.generate()

    sys.stdout.write(password)
    if options.newline:
        sys.stdout.write("\n")


@dataclass
class Generator:
    """Password generator"""

    length: int
    newline: bool
    lowercase: bool
    uppercase: bool
    numbers: bool
    symbols: bool

    def generate(self) -> str:
        while True:
            candidate = self._generate_unchecked()
            if not self._should_check_passwords:
                return candidate

            if self._password_is_ok(candidate):
                return candidate

    def _password_is_ok(self, candidate: str) -> bool:
        if candidate[0] not in self.start_end_characters:
            return False

        if candidate[-1] not in self.start_end_characters:
            return False

        letters_used = set(candidate)

        # Make sure we have some overlap with the password and each of the
        # character sets
        for character_set in self.all_character_sets:
            character_set_characters = set(character_set)
            if not character_set_characters & letters_used:
                return False

        return True

    @property
    def _should_check_passwords(self) -> bool:
        # We are going to skip all checks if we are working with super short passwords
        return self.length >= len(self.all_character_sets)

    @cached_property
    def all_character_sets(self) -> set[str]:
        out: set[str] = set()

        if self.lowercase:
            out.add(string.ascii_lowercase)

        if self.uppercase:
            out.add(string.ascii_uppercase)

        if self.numbers:
            out.add(string.digits)

        if self.symbols:
            out.add(string.punctuation)

        return out

    @cached_property
    def all_characters(self) -> str:
        return "".join(self.all_character_sets)

    @cached_property
    def start_end_characters(self) -> str:
        """Get the characters that are applicable
        for the start or end of the password"""

        if self.lowercase and self.uppercase:
            return string.ascii_letters

        if self.lowercase:
            return string.ascii_lowercase

        if self.uppercase:
            return string.ascii_uppercase

        if self.numbers:
            return string.digits

        if self.symbols:
            return string.punctuation

        return ""

    def _generate_unchecked(self) -> str:
        """Return a password that might not have the appropriate character sets"""

        working = [choice(self.all_characters) for _ in range(self.length)]

        return "".join(working)


def read_arguments() -> Generator:
    """Get the options for execution"""

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-n",
        "--num-characters",
        type=int,
        default=63,
        dest="length",
        help="The length of the password to generate",
    )

    parser.add_argument(
        "-nl",
        "--no-lowercase",
        action="store_const",
        const=False,
        dest="lowercase",
        default=True,
        help="Do not include lowercase letters",
    )

    parser.add_argument(
        "-nu",
        "--no-uppercase",
        action="store_const",
        const=False,
        dest="uppercase",
        default=True,
        help="Do not include uppercase letters",
    )

    parser.add_argument(
        "-nd",
        "--no-digits",
        action="store_const",
        const=False,
        dest="digits",
        default=True,
        help="Do not include digits",
    )

    parser.add_argument(
        "-s",
        "--symbols",
        action="store_const",
        const=True,
        dest="symbols",
        default=False,
        help="Include symbols in password",
    )

    newline_group = parser.add_mutually_exclusive_group()

    newline_group.add_argument(
        "--newline",
        action="store_const",
        const=True,
        dest="newline",
    )

    newline_group.add_argument(
        "--no-newline",
        action="store_const",
        const=False,
        dest="newline",
    )

    args = parser.parse_args()

    length: int = args.length  # type: ignore
    newline: bool | None = args.newline  # type: ignore
    lowercase: bool = args.lowercase  # type: ignore
    uppercase: bool = args.uppercase  # type: ignore
    digits: bool = args.digits  # type: ignore
    symbols: bool = args.symbols  # type: ignore

    if newline is None:
        if sys.stdout.isatty():
            newline = True
        else:
            newline = False

    return Generator(
        length=length,
        newline=newline,
        lowercase=lowercase,
        uppercase=uppercase,
        numbers=digits,
        symbols=symbols,
    )


if __name__ == "__main__":
    main()
