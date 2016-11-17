
SQUIRREL_GAPS_IN_DESCRIPTIONS = True

INFRASTRUCTURE_IN_20 = False

INCIDENT_IN_20 = True

DEFAULT_TIMESTAMP = ""

DEFAULT_IDENTIFIER = ""


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
        file_: A list of input files and directories of files to be
            validated.
        schema_dir: A user-defined schema directory to validate against.
        lax: Specifies that only mandatory requirements, not ones which are
            merely recommended, should be checked.
        lax_prefix: Specifies that less strict requirements for custom object
            and property names should be used.
        strict_types: Specifies that no custom object types be used, only
            those detailed in the STIX specification.

    """
    def __init__(self, cmd_args=None, file_=None, no_incidents=True,
                 infrastructure=False, default_created_by_id="",
                 default_timestamp="", validator_args="", verbose=False,
                 enable="", disable=""):
        if cmd_args is not None:
            self.file_ = cmd_args.file_
            self.no_incidents = cmd_args.no_incidents
            self.infrastructure = cmd_args.infrastructure
            self.default_created_by_id = cmd_args.default_created_by_id
            self.default_timestamp = cmd_args.default_timestamp
            self.validator_args = cmd_args.validator_args

            self.verbose = cmd_args.verbose
            self.enable = cmd_args.enable
            self.disable = cmd_args.disable

        else:
            self.file_ = file_
            self.no_incidents = no_incidents
            self.infrastructure = infrastructure
            self.default_created_by_id = default_created_by_id
            self.default_timestamp = default_timestamp
            self.validator_args = validator_args

            self.verbose = verbose
            self.enable = enable
            self.disable = disable

        # Convert string of comma-separated checks to a list,
        # and convert check code numbers to names
        if self.disable:
            self.disable = self.disable.split(",")
            self.disable = [CHECK_CODES[x] if x in CHECK_CODES else x
                            for x in self.disable]
        if self.enable:
            self.enable = self.enable.split(",")
            self.enable = [CHECK_CODES[x] if x in CHECK_CODES else x
                           for x in self.enable]


def set_infrastructure(include_infrastructure=False):
    global INFRASTRUCTURE_IN_20
    INFRASTRUCTURE_IN_20 = include_infrastructure


def set_incidents(include_incidents=True):
    global INCIDENT_IN_20
    INCIDENT_IN_20 = include_incidents


def set_gap_descriptions(include_descriptions=True):
    global SQUIRREL_GAPS_IN_DESCRIPTIONS
    SQUIRREL_GAPS_IN_DESCRIPTIONS = include_descriptions


def set_default_identifier(default_identifier=""):
    global DEFAULT_IDENTIFIER
    DEFAULT_IDENTIFIER = default_identifier


def set_default_timestamp(default_timestamp=""):
    global DEFAULT_TIMESTAMP
    DEFAULT_TIMESTAMP = default_timestamp


def set_options(options):
    set_infrastructure(options.infrastructure)
    set_incidents(options.incidents)
    set_gap_descriptions(options.gaps)
    set_default_identifier(options.identifier)
    set_default_timestamp(options.timestamp)


# Mapping of check code numbers to names
CHECK_CODES = {
    '3': 'append-to-description-property',
    '301': '',
    '302': '',
    '303': '',
    '304': '',
    '305': '',
    '306': '',
    '4': 'drop-content-not-supported',
    '401': '',
    '402': '',
    '403': '',
    '404': '',
    '405': '',
    '406': '',
    '407': '',
    '408': '',
    '409': '',
    '410': '',
    '411': '',
    '412': '',
    '413': '',
    '414': '',
    '415': '',
    '416': '',
    '417': '',
    '418': '',
    '419': '',
    '420': '',
    '421': '',
    '5': 'multiple-values-not-supported',
    '501': '',
    '502': '',
    '503': '',
    '504': '',
    '505': '',
    '506': '',
    '507': '',
    '6': 'issues-in-original-content',
    '601': '',
    '602': '',
    '603': '',
    '604': '',
    '605': '',
    '606': '',
    '607': '',
    '608': '',
    '609': '',
    '610': '',
    '611': '',
    '7': 'conversion-assumptions',
    '701': '',
    '702': '',
    '703': '',
    '704': '',
    '705': '',
    '706': '',
    '707': '',
    '708': '',
    '709': '',
    '710': '',
    '711': '',
    '712': '',
    '713': '',
    '8': 'content-not-supported',
    '801': '',
    '802': '',
    '803': '',
    '804': '',
    '805': '',
    '806': '',
    '807': '',
    '808': '',
    '9': 'using-parent-or-current-timestamp',
    '901': '',
    '902': '',
    '903': '',
    '904': '',
    '905': '',
}
