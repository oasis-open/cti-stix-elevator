
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

# built-in
import json

# external
import stix
from stix.core import STIXPackage
from stix.utils.parser import EntityParser

from stix2validator import codes
from stix2validator import output
from stix2validator import validators
from stix2validator import validate_string, ValidationError

from elevator.convert_pattern import clear_pattern_mapping
from elevator.ids import clear_id_mapping
from elevator.utils import warn
from elevator.convert_stix import convert_package
from elevator import options
from elevator.version import __version__  # noqa


def elevate_file(fn, elevator_options=None):
    warn("WARNING: Results produced by the stix-elevator are not for production purposes.")
    clear_id_mapping()
    clear_pattern_mapping()

    if not elevator_options:
        elevator_options = options.ElevatorOptions()
        options.set_options(elevator_options)
        validator_options = elevator_options.get_validator_options()
    else:
        options.set_options(elevator_options)
        validator_options = elevator_options.get_validator_options()

    try:
        output.set_level(validator_options.verbose)

        stix_package = EntityParser().parse_xml(fn)

        if not isinstance(stix_package, STIXPackage):
            raise TypeError("Must be an instance of stix.core.STIXPackage")

        json_string = json.dumps(convert_package(stix_package, elevator_options.package_created_by_id), indent=4,
                                 separators=(',', ': '), sort_keys=True)
        validation_results = validate_string(json_string, validator_options)
        output.print_results(validation_results)
        return json_string

    except ValidationError as ex:
        output.error("Validation error occurred: '%s'" % str(ex),
                     codes.EXIT_VALIDATION_ERROR)


def elevate_string(string, elevator_options=None):
    warn("WARNING: Results produced by the stix-elevator are not for production purposes.")
    clear_id_mapping()
    clear_pattern_mapping()

    if not elevator_options:
        elevator_options = options.ElevatorOptions()
        options.set_options(elevator_options)
        validator_options = elevator_options.get_validator_options()
    else:
        options.set_options(elevator_options)
        validator_options = elevator_options.get_validator_options()

    try:
        output.set_level(validator_options.verbose)

        io = StringIO(string)
        stix_package = EntityParser().parse_xml(io)

        if not isinstance(stix_package, STIXPackage):
            raise TypeError("Must be an instance of stix.core.STIXPackage")

        json_string = json.dumps(convert_package(stix_package), indent=4,
                                 separators=(',', ': '), sort_keys=True)
        validation_results = validate_string(json_string, validator_options)
        output.print_results(validation_results)
        return json_string

    except ValidationError as ex:
        output.error("Validation error occurred: '%s'" % str(ex),
                     codes.EXIT_VALIDATION_ERROR)


def elevate_package(package, elevator_options=None):
    warn("WARNING: Results produced by the stix-elevator are not for production purposes.")
    clear_id_mapping()
    clear_pattern_mapping()

    if not elevator_options:
        elevator_options = options.ElevatorOptions()
        options.set_options(elevator_options)
        validator_options = elevator_options.get_validator_options()
    else:
        options.set_options(elevator_options)
        validator_options = elevator_options.get_validator_options()

    try:
        output.set_level(validator_options.verbose)

        if not isinstance(package, STIXPackage):
            raise TypeError("Must be an instance of stix.core.STIXPackage")

        json_string = json.dumps(convert_package(package), indent=4,
                                 separators=(',', ': '), sort_keys=True)
        validation_results = validate_string(json_string, validator_options)
        output.print_results(validation_results)
        return json_string

    except ValidationError as ex:
        output.error("Validation error occurred: '%s'" % str(ex),
                     codes.EXIT_VALIDATION_ERROR)
