import shlex
from six import text_type

from stix2validator.scripts import stix2_validator
from stix2validator import ValidationOptions
from elevator.utils import *

ALL_OPTIONS = None


class ElevatorOptions(object):
    """Collection of elevator options which can be set via command line or
    programmatically in a script.

    It can be initialized either by passing in the result of parse_args() from
    argparse to the cmd_args parameter, or by specifying individual options
    with the other parameters.

    Attributes:
        cmd_args: An instance of ``argparse.Namespace`` containing options
            supplied on the command line.
        verbose: True if informational notes and more verbose error messages
            should be printed to stdout/stderr.
        file_: Input file to be elevated.
        incidents: False if no incidents should be included in the result.
        infrastructure: True if infrastructure should be included in the result.
        package_created_by_id: If set, this identifier ref will be applied in
            the `created_by_ref` property.
        default_timestamp: If set, this value will be used when: the object
            does not have a timestamp, the parent does not have a timestamp.
            When this value is not set, current time will be used instead.
        validator_args: If set, these values will be used to create a
            ValidationOptions instance if requested.
        enable: Messages to enable.
        disable: Messages to disable.

    Note:
        All messages are turned on by default.
    """
    def __init__(self, cmd_args=None, file_=None, incidents=True,
                 no_squirrel_gaps=False, infrastructure=False,
                 package_created_by_id=None, default_timestamp=None,
                 validator_args="--strict-types", verbose=False,
                 enable="", disable="", silent=False):

        if cmd_args is not None:
            self.file_ = cmd_args.file_
            self.incidents = cmd_args.incidents
            self.no_squirrel_gaps = cmd_args.no_squirrel_gaps
            self.infrastructure = cmd_args.infrastructure
            self.package_created_by_id = cmd_args.package_created_by_id
            self.default_timestamp = cmd_args.default_timestamp
            self.validator_args = cmd_args.validator_args

            self.verbose = cmd_args.verbose
            self.enable = cmd_args.enable
            self.disable = cmd_args.disable
            self.silent = cmd_args.silent

        else:
            self.file_ = file_
            self.incidents = incidents
            self.no_squirrel_gaps = no_squirrel_gaps
            self.infrastructure = infrastructure
            self.package_created_by_id = package_created_by_id
            self.default_timestamp = default_timestamp
            self.validator_args = validator_args

            self.verbose = verbose
            self.enable = enable
            self.disable = disable
            self.silent = silent

        # Convert string of comma-separated checks to a list,
        # and convert check code numbers to names. By default all messages are
        # enabled.
        if self.disable:
            self.disabled = self.disable.split(",")
            self.disabled = [CHECK_CODES[x] if x in CHECK_CODES else x
                             for x in self.disabled]
        else:
            self.disabled = []

        if self.enable:
            self.enabled = self.enable.split(",")
            self.enabled = [CHECK_CODES[x] if x in CHECK_CODES else x
                            for x in self.enabled]
        else:
            self.enabled = [text_type(x) for x in CHECK_CODES]


def initialize_options(elevator_args=None):
    global ALL_OPTIONS
    if not ALL_OPTIONS:
        ALL_OPTIONS = ElevatorOptions(elevator_args)


def get_validator_options():
    if ALL_OPTIONS:
        """Return a stix2validator.validators.ValidationOptions instance."""
        # Parse stix-validator command-line args
        validator_parser = stix2_validator._get_arg_parser(is_script=False)
        validator_args = validator_parser.parse_args(
            shlex.split(get_option_value("validator_args")))

        validator_args.files = None
        return ValidationOptions(validator_args)


def get_option_value(option_name):
    if ALL_OPTIONS and hasattr(ALL_OPTIONS, option_name):
        return getattr(ALL_OPTIONS, option_name)
    else:
        return None


def set_option_value(option_name, option_value):
    if ALL_OPTIONS:
        setattr(ALL_OPTIONS, option_name, option_value)
    else:
        error("options not initialized", 207)


def msg_id_enabled(msg_id):
    msg_id = str(msg_id)

    if get_option_value("silent"):
        return False

    if not get_option_value("disabled"):
        return msg_id in get_option_value("enabled")
    else:
        return not (msg_id in get_option_value("disabled"))


# These codes are aligned with elevator_log_messages spreadsheet.
CHECK_CODES = [201, 202, 203, 204, 205, 206, 207, 301, 302, 303, 304, 305, 306,
               401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413,
               414, 415, 416, 417, 418, 419, 420, 421, 422, 501, 502, 503, 504,
               505, 506, 507, 508, 509, 510, 511, 601, 602, 603, 604, 605, 606,
               607, 608, 609, 610, 611, 612, 613, 614, 615, 616, 617, 618, 701,
               702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712, 713, 714,
               715, 716, 717, 718, 801, 802, 803, 804, 805, 806, 807, 808, 809,
               810, 811, 812, 813, 901, 902, 903, 904, 905]
