# Standard Library
import copy
import logging
import os
import shlex

# external
from stix2validator.scripts import stix2_validator

ALL_OPTIONS = None

formatter = logging.Formatter("[%(name)s] [%(ecode)d] [%(levelname)-7s] [%(asctime)s] %(message)s")

# Console Handler for Elevator messages
ch = logging.StreamHandler()
ch.setFormatter(formatter)

# File Handler for Elevator logs, set individually for each file.
fh = None

# Module-level logger
log = logging.getLogger(__name__)
# temporary? hack to prevent multiple loggers from printing messages
log.propagate = False
log.addHandler(ch)

MESSAGES_GENERATED = False


def info(fmt, ecode, *args):
    if msg_id_enabled(ecode):
        global MESSAGES_GENERATED
        log.info(fmt, *args, extra={'ecode': ecode})
        MESSAGES_GENERATED = True


def warn(fmt, ecode, *args):
    if msg_id_enabled(ecode):
        global MESSAGES_GENERATED
        log.warning(fmt, *args, extra={'ecode': ecode})
        MESSAGES_GENERATED = True


def error(fmt, ecode, *args):
    if msg_id_enabled(ecode):
        global MESSAGES_GENERATED
        log.error(fmt, *args, extra={'ecode': ecode})
        MESSAGES_GENERATED = True


def setup_logger(package_id):
    global log
    global fh
    global ALL_OPTIONS

    if ALL_OPTIONS:
        log.setLevel(get_option_value("log_level"))

        if not get_option_value("message_log_directory"):
            return

        output_directory = get_option_value("message_log_directory")
        file_directory = get_option_value("file_")

        if file_directory:
            project_path, filename = os.path.split(file_directory)
            filename = filename.split(".")[0]
            filename += ".log"
        else:
            filename = package_id.split(":")[1]
            filename += ".log"

        if not os.path.exists(output_directory):
            os.makedirs(output_directory)

        destination = os.path.join(output_directory, filename)
        destination = os.path.abspath(destination)

        # Remove File Handler from root logger if present.
        if fh in log.handlers:
            fh.close()
            log.removeHandler(fh)

        # The delay=True should prevent the file from being opened until a
        # message is emitted by the logger.
        fh = logging.FileHandler(destination, mode='w', delay=True)
        fh.setFormatter(formatter)
        log.addHandler(fh)


def _convert_to_int_list(check_codes):
    """Takes a comma-separated string or list of strings and converts to list of ints.

    Args:
        check_codes: comma-separated string or list of strings

    Returns:
        list: the check codes as a list of integers

    Raises:
        ValueError: if conversion fails
        RuntimeError: if cannot determine how to convert input
    """
    if isinstance(check_codes, list):
        if all(isinstance(x, int) for x in check_codes):
            return check_codes  # good input
        else:
            return [int(x) for x in check_codes]  # list of str
    elif isinstance(check_codes, str):
        return [int(x) for x in check_codes.split(",")]  # str, comma-separated expected
    raise RuntimeError("Could not convert values: {} of type {}".format(check_codes, type(check_codes)))


class ElevatorOptions(object):
    """Collection of stix2-elevator options which can be set via command line or
    programmatically in a script.

    It can be initialized either by passing in the result of parse_args() from
    ``argparse.Namespace`` to the cmd_args parameter, or by specifying
    individual options with the other parameters.

    Attributes:
        cmd_args: An instance of ``argparse.Namespace`` containing options
            supplied on the command line.
        file_: Input file to be elevated.
        incidents: True if incidents should be included in the result.
        infrastructure: True if infrastructure should be included in the result.
        package_created_by_id: If set, this identifier ref will be applied in
            the `created_by_ref` property.
        default_timestamp: If set, this value will be used when: the object
            does not have a timestamp, the parent does not have a timestamp.
            When this value is not set, current time will be used instead.
        validator_args: If set, these values will be used to create a
            ValidationOptions instance if requested.  The elevator should not produce any custom objects.
        enabled: Messages to enable. Expects a list of ints.
        disabled: Messages to disable. Expects a list of ints.
        silent: If set, no stix2-elevator log messages will be emitted.
        message_log_directory: If set, it will write all emitted messages to
            file. It will use the filename or package id to name the log file.

    Note:
        All messages are turned on by default.
    """
    def __init__(self, cmd_args=None, file_=None, incidents=False,
                 missing_policy="add-to-description", custom_property_prefix="elevator",
                 infrastructure=False, package_created_by_id=None, default_timestamp=None,
                 validator_args="--strict-types", enabled=None, disabled=None,
                 silent=False, message_log_directory=None,
                 policy="no_policy", output_directory=None, log_level="INFO",
                 markings_allowed="", spec_version="2.1", acs=False):

        if cmd_args is not None:
            if hasattr(cmd_args, "file_"):
                self.file_ = cmd_args.file_
            self.incidents = cmd_args.incidents
            self.missing_policy = cmd_args.missing_policy
            self.custom_property_prefix = cmd_args.custom_property_prefix
            self.infrastructure = cmd_args.infrastructure
            self.acs = cmd_args.acs
            self.package_created_by_id = cmd_args.package_created_by_id
            self.default_timestamp = cmd_args.default_timestamp
            self.validator_args = cmd_args.validator_args

            self.enabled = cmd_args.enabled
            self.disabled = cmd_args.disabled
            self.silent = cmd_args.silent
            self.policy = cmd_args.policy
            self.message_log_directory = cmd_args.message_log_directory
            self.log_level = cmd_args.log_level
            self.markings_allowed = cmd_args.markings_allowed
            if hasattr(cmd_args, "output_directory"):
                self.output_directory = cmd_args.output_directory
            self.spec_version = cmd_args.spec_version

        else:
            self.file_ = file_
            self.incidents = incidents
            self.missing_policy = missing_policy
            self.custom_property_prefix = custom_property_prefix
            self.infrastructure = infrastructure
            self.acs = acs
            self.package_created_by_id = package_created_by_id
            self.default_timestamp = default_timestamp
            self.validator_args = validator_args

            self.enabled = enabled
            self.disabled = disabled
            self.silent = silent
            self.policy = policy
            self.message_log_directory = message_log_directory
            self.log_level = log_level
            self.output_directory = output_directory
            self.markings_allowed = markings_allowed
            self.spec_version = spec_version

        if self.validator_args.find("--version") == -1:
            self.validator_args = self.validator_args + " --version " + self.spec_version

        if self.markings_allowed:
            self.markings_allowed = self.markings_allowed.split(",")

        self.marking_container = None

    @property
    def disabled(self):
        return self._disabled

    @disabled.setter
    def disabled(self, disabled):
        def remove_silent(item, elements):
            try:
                elements.remove(item)
            except ValueError:
                pass  # suppress exception if value is not present
        # Convert string of comma-separated checks to a list,
        # and convert check code numbers to names. By default no messages are
        # disabled.
        if disabled:
            self._disabled = _convert_to_int_list(disabled)
            self._disabled = [x for x in self._disabled if x in CHECK_CODES]
            for x in self._disabled:
                remove_silent(x, self._enabled)
        else:
            self._disabled = []

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        def remove_silent(item, elements):
            try:
                elements.remove(item)
            except ValueError:
                pass  # suppress exception if value is not present
        # Convert string of comma-separated checks to a list,
        # and convert check code numbers to names. By default all messages are
        # enabled.
        if enabled:
            self._enabled = _convert_to_int_list(enabled)
            self._enabled = [x for x in self._enabled if x in CHECK_CODES]
            for x in self._enabled:
                remove_silent(x, self._disabled)
        else:
            self._enabled = copy.deepcopy(CHECK_CODES)


def initialize_options(options=None):
    global ALL_OPTIONS
    if not ALL_OPTIONS:
        if isinstance(options, ElevatorOptions):
            ALL_OPTIONS = options
        elif isinstance(options, dict):
            ALL_OPTIONS = ElevatorOptions(**options)
        else:
            ALL_OPTIONS = ElevatorOptions(options)

        if ALL_OPTIONS.silent and ALL_OPTIONS.message_log_directory:
            info("Both console and output log have disabled messages.", 209)

        if ALL_OPTIONS.silent and ALL_OPTIONS.policy != "no_policy":
            warn("silent option is not compatible with a policy", 211)

        if ALL_OPTIONS.spec_version == "2.1":
            if not ALL_OPTIONS.incidents:
                info("%s option was not given, but it defaults to true for version 2.1", 214, "incidents")
                ALL_OPTIONS.incidents = True
            if not ALL_OPTIONS.infrastructure:
                info("%s option was not given, but it defaults to true for version 2.1", 214, "infrastructure")
                ALL_OPTIONS.infrastructure = True
            if ALL_OPTIONS.missing_policy == "use-custom-properties":
                info("Custom properties/objects/extensions are deprecated in version 2.1.  Suggest using 'use-extensions' instead", 215)

        if not ALL_OPTIONS.custom_property_prefix == "elevator" and not ALL_OPTIONS.missing_policy == "use-custom-properties":
            warn("custom_property_prefix option is provided, but the missing policy option is not 'use-custom-properies'.  It will be ignored.", 213)

        if ALL_OPTIONS.missing_policy == "use-extensions" and ALL_OPTIONS.spec_version == "2.0":
            error("The missing policy option of 'use-extensions' cannot be used with version 2.0. 'use-custom-properies' is suggested", 216)

        if ALL_OPTIONS.acs and ALL_OPTIONS.spec_version == "2.0":
            warn("ACS data markings cannot be supported in version 2.0. --acs option is ignored.", 217)
            ALL_OPTIONS.acs = False


def get_validator_options():
    if ALL_OPTIONS:
        """Return a stix2validator.validators.ValidationOptions instance."""
        return stix2_validator.parse_args(shlex.split(get_option_value("validator_args")))


def get_option_value(option_name):
    if ALL_OPTIONS and hasattr(ALL_OPTIONS, option_name):
        return getattr(ALL_OPTIONS, option_name)
    else:
        return None


def set_option_value(option_name, option_value):
    global ALL_OPTIONS
    if ALL_OPTIONS:
        setattr(ALL_OPTIONS, option_name, option_value)
    else:
        error("options not initialized", 207)


def msg_id_enabled(msg_id):
    if get_option_value("silent"):
        return False

    if not get_option_value("disabled"):
        return msg_id in get_option_value("enabled")
    else:
        return not (msg_id in get_option_value("disabled"))


# These codes are aligned with elevator_log_messages spreadsheet.

# current number of messages: 177

CHECK_CODES = [201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213,
               214, 215, 216, 217,

               301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313,
               314, 315, 316, 317, 318, 319,

               401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413,
               414, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426,
               427, 428, 429, 430, 431, 432, 433, 434, 435, 436,

               501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511, 512,

               601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612, 613,
               614, 615, 616, 617, 618, 619, 620, 621, 622, 623, 624, 625, 626,
               627, 628, 629, 630, 631, 632, 633, 634, 635, 636, 637, 638, 639,
               640, 641,

               701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712, 713,
               714, 715, 716, 717, 718, 719, 720, 721, 722, 723, 724, 725, 726,
               727, 728, 729,

               801, 802, 803, 804, 805, 806, 807, 808, 809, 810, 811, 812, 813,
               814, 815, 816, 817, 818,

               901, 902, 903, 904, 905]
