
import argparse
import shlex

from stix2validator.scripts import stix2_validator

from elevator import elevate_file
from elevator.version import __version__


def _get_arg_parser():
    """Create and return an ArgumentParser for this application."""

    desc = "stix-elevator v{0}".format(__version__)

    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument(
        "--input",
        help="The input STIX document to be elevated.",
        default=""
    )

    parser.add_argument(
        "--log-level",
        help="The logging output level.",
        choices=["INFO", "WARN", "ERROR"],
        action="store",
        default="INFO"
    )

    parser.add_argument(
        "--no-incidents",
        help="No incident will be included in the conversion.",
        dest="no_incidents",
        action="store_false",
        default=True
    )

    parser.add_argument(
        "--infrastructure",
        help="Infrastructure will be included in the conversion.",
        dest="infrastructure",
        action="store_true",
        default=False
    )

    parser.add_argument(
        "--no-squirrel-gaps",
        help="Do not include STIX 1.x content that cannot be represented directly in STIX 2.0 using the description property.",
        dest="squirrel_gaps",
        action="store_false",
        default=True
    )

    parser.add_argument(
        "--default-identifier",
        help="Use the provided identifier for the created_by_ref",
        dest="identifier",
        action="store",
        default=""
    )

    parser.add_argument(
        "--default-timestamp",
        help="Use the provided timestamp for properties that require one instead of generating a new timestamp.",
        dest="timestamp",
        action="store",
        default=""
    )

    parser.add_argument(
        "--validator-args",
        help="Arguments to pass stix-validator. DO NOT provide \"files\" arg.",
        dest="validator_args",
        action="store",
        default=""
    )

    parser.add_argument(
        "--indent-level",
        help="Indentation of output. Default 4.",
        dest="indent",
        action="store",
        default=4
    )

    parser.add_argument(
        "--no-sort-keys",
        help="Sort properties alphabetically.",
        dest="sort_keys",
        action="store_false",
        default=True
    )

    return parser


def main():
    # Parse stix-elevator command-line args
    elevator_parser = _get_arg_parser()
    elevator_args = elevator_parser.parse_args()

    # Parse stix-validator command-line args
    validator_parser = stix2_validator._get_arg_parser(is_script=False)
    validator_args = validator_parser.parse_args(
        shlex.split(elevator_args.validator_args))

    print(elevate_file(elevator_args.input))


if __name__ == '__main__':
    main()
