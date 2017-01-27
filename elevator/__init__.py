
# built-in
import json
import logging

# external
import stix
from stix.core import STIXPackage
from stix.utils.parser import EntityParser

from six import StringIO

from stix2validator import codes
from stix2validator import output
from stix2validator import validate_string, ValidationError

from elevator.convert_pattern import clear_pattern_mapping
from elevator.ids import clear_id_mapping
from elevator.utils import *
from elevator.convert_stix import convert_package
from elevator.options import get_validator_options, initialize_options, get_option_value
from elevator.version import __version__  # noqa

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(ecode)d] [%(levelname)-7s] [%(asctime)s] %(message)s"
)

log = logging.getLogger(__name__)


def elevate_file(fn):
    warn("Results produced by the stix-elevator are not for production purposes.", 201)
    clear_id_mapping()
    clear_pattern_mapping()

    validator_options = get_validator_options()

    try:
        output.set_level(validator_options.verbose)

        stix_package = EntityParser().parse_xml(fn)

        if not isinstance(stix_package, STIXPackage):
            raise TypeError("Must be an instance of stix.core.STIXPackage")

        setup_logger(stix_package.id_)
        json_string = json.dumps(convert_package(stix_package,
                                                 get_option_value("package_created_by_id"),
                                                 get_option_value("default_timestamp")),
                                 indent=4,
                                 separators=(',', ': '),
                                 sort_keys=True)
        validation_results = validate_string(json_string, validator_options)
        output.print_results(validation_results)
        return json_string

    except ValidationError as ex:
        output.error("Validation error occurred: '%s'" % ex,
                     codes.EXIT_VALIDATION_ERROR)
    except OSError as ex:
        log.error(ex)


def elevate_string(string):
    warn("Results produced by the stix-elevator are not for production purposes.", 201)
    clear_id_mapping()
    clear_pattern_mapping()

    validator_options = get_validator_options()

    try:
        output.set_level(validator_options.verbose)

        io = StringIO(string)
        stix_package = EntityParser().parse_xml(io)

        if not isinstance(stix_package, STIXPackage):
            raise TypeError("Must be an instance of stix.core.STIXPackage")

        setup_logger(stix_package.id_)
        json_string = json.dumps(convert_package(stix_package,
                                                 get_option_value("package_created_by_id"),
                                                 get_option_value("default_timestamp")),
                                 indent=4,
                                 separators=(',', ': '),
                                 sort_keys=True)
        validation_results = validate_string(json_string, validator_options)
        output.print_results(validation_results)
        return json_string

    except ValidationError as ex:
        output.error("Validation error occurred: '%s'" % ex,
                     codes.EXIT_VALIDATION_ERROR)
    except OSError as ex:
        log.error(ex)


def elevate_package(package):
    warn("Results produced by the stix-elevator are not for production purposes.", 201)
    clear_id_mapping()
    clear_pattern_mapping()

    validator_options = get_validator_options()

    try:
        output.set_level(validator_options.verbose)

        if not isinstance(package, STIXPackage):
            raise TypeError("Must be an instance of stix.core.STIXPackage")

        setup_logger(package.id_)
        json_string = json.dumps(convert_package(package,
                                                 get_option_value("package_created_by_id"),
                                                 get_option_value("default_timestamp")),
                                 indent=4,
                                 separators=(',', ': '),
                                 sort_keys=True)
        validation_results = validate_string(json_string, validator_options)
        output.print_results(validation_results)
        return json_string

    except ValidationError as ex:
        output.error("Validation error occurred: '%s'" % ex,
                     codes.EXIT_VALIDATION_ERROR)
    except OSError as ex:
        log.error(ex)
