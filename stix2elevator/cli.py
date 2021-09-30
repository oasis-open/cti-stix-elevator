#!/usr/bin/env python

"""The stix2-elevator is a work-in-progress. It should be used to explore how
existing STIX 1.x would potentially be represented in STIX 2.x. Using the
current version of the stix2-elevator will provide insight to issues that might
need to be mitigated to convert your STIX 1.x content.
"""

# Standard Library
import argparse
import sys

# internal
from stix2elevator import elevate
from stix2elevator.options import initialize_options
from stix2elevator.utils import NewlinesHelpFormatter
from stix2elevator.version import __version__

CODE_TABLE = """
Refer to elevator_log_messages.rst for all stix2-elevator messages. Use the
associated code number to --enable or --disable a message. By default, the
stix2-elevator displays all messages. Note: disabling the message does not
disable the functionality.
"""


def _get_arg_parser(is_script=True):
    """Create and return an ArgumentParser for this application."""

    desc = "stix2-elevator v{0}\n\n".format(__version__)

    parser = argparse.ArgumentParser(
        description=desc + __doc__,
        formatter_class=NewlinesHelpFormatter,
        epilog=CODE_TABLE
    )

    if is_script:
        parser.add_argument(
            "file_",
            help="The input STIX 1.x document to be elevated.",
            metavar="file"
        )

    parser.add_argument(
        "--missing-policy",
        help="Policy for including STIX 1.x content that cannot be represented "
             "directly in STIX 2.x.  The default is 'add-to-description'.",
        choices=["use-custom-properties", "add-to-description", "ignore", "use-extensions"],
        dest="missing_policy",
        action="store",
        default="add-to-description"
    )

    parser.add_argument(
        "--custom-property-prefix",
        help="Prefix to use for custom property names when missing policy is 'use-custom-properties'. The default is 'elevator'.",
        dest="custom_property_prefix",
        action="store",
        default="elevator"
    )

    parser.add_argument(
        "--infrastructure",
        help="Infrastructure will be included in the conversion. Default for version 2.1 is true.",
        dest="infrastructure",
        action="store_true",
        default=False
    )

    parser.add_argument(
        "--incidents",
        help="Incidents will be included in the conversion.  Default for version 2.1 is true.",
        dest="incidents",
        action="store_true",
        default=False
    )

    parser.add_argument(
        "--acs",
        help="Process ACS data markings",
        dest="acs",
        action="store_true",
        default=False
    )

    parser.add_argument(
        "--package-created-by-id",
        help="Use provided identifier for \"created_by_ref\" properties. "
             "Example: --package-created-by-id \"identity--1234abcd-1a12-42a3-0ab4-1234abcd5678\"",
        dest="package_created_by_id",
        action="store",
        default=None
    )

    parser.add_argument(
        "--default-timestamp",
        help="Use provided timestamp for properties that require a timestamp. "
             "\n\nExample: --default-timestamp \"2016-11-15T13:10:35.053000Z\"",
        dest="default_timestamp",
        action="store",
        default=None
    )

    parser.add_argument(
        "--validator-args",
        help="Arguments to pass to stix2-validator. Default: --strict-types\n\n"
             "Example: stix2_elevator.py <file> --validator-args=\"-v --strict-types -d 212\"",
        dest="validator_args",
        action="store",
        default=""
    )

    parser.add_argument(
        "-e",
        "--enable",
        help="A comma-separated list of the stix2-elevator messages to enable. "
             "If the --disable option is not used, no other messages will be "
             "shown. \n\nExample: stix2_elevator.py <file> --enable 250",
        dest="enabled",
        default=None
    )

    parser.add_argument(
        "-d",
        "--disable",
        help="A comma-separated list of the stix2-elevator messages to disable. \n\n"
             "Example: stix2_elevator.py <file> --disable 212,220",
        dest="disabled",
        default=None
    )

    parser.add_argument(
        "-s",
        "--silent",
        help="If this flag is set, all stix2-elevator messages will be disabled.",
        dest="silent",
        action="store_true",
        default=False
    )

    parser.add_argument(
        "--message-log-directory",
        help="If this flag is set, all stix2-elevator messages will be saved to "
             "file. The name of the file will be the input file with "
             "extension .log in the specified directory. Note, make sure "
             "the directory already exists.\n\n"
             "Example: stix2_elevator.py <file> --message-log-directory \"../logs\"",
        dest="message_log_directory",
        action="store",
        default=None
    )

    parser.add_argument(
        "--log-level",
        default="INFO",
        help="The logging output level.",
        choices=["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"]
    )

    parser.add_argument(
        "-m",
        "--markings-allowed",
        help="Avoid an error exit, if these markings are in the content, but not supported by the elevator.  \n\n"
             "Specify as a comma-separated list"
             "Example: stix2_elevator.py < file > --markings-allowed \"ISAMarkingsAssertion,ISAMarkings\"",

        dest="markings_allowed",
        action="store",
        default=""
    )

    parser.add_argument(
        "-p",
        "--error-policy",
        "--policy",     # deprecated
        help="The policy to deal with errors.  The default is 'no_policy'.",
        dest="policy",
        choices=["no_policy", "strict_policy"],
        action="store",
        default="no_policy"
    )

    parser.add_argument(
        "-v",
        "--version",
        help="The version of stix 2 to be produced.  The default is 2.1",
        dest="spec_version",
        choices=["2.0", "2.1"],
        action="store",
        default="2.1"
    )
    return parser


def main():
    # Parse stix2-elevator command-line args
    elevator_parser = _get_arg_parser()
    elevator_args = elevator_parser.parse_args()
    sys.setrecursionlimit(3000)
    initialize_options(options=elevator_args)
    result = elevate(elevator_args.file_)
    if result:
        sys.stdout.write(result + "\n")
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
