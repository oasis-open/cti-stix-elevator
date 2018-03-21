import json
import logging

import cybox.utils.caches
from six import StringIO
from stix2validator import ValidationError, codes, output, validate_string
from stix.core import STIXPackage
import stixmarx

from stix2elevator.convert_pattern import (clear_observable_mappings,
                                           clear_pattern_cache)
from stix2elevator.convert_stix import convert_package
from stix2elevator.ids import clear_id_mapping, clear_object_id_mapping
from stix2elevator.options import (get_option_value, get_validator_options,
                                   set_option_value, setup_logger, warn)
from stix2elevator.utils import clear_1x_markings_map
from stix2elevator.version import __version__  # noqa

# Module-level logger
log = logging.getLogger(__name__)


def elevate_file(fn):
    # TODO:  combine elevate_file, elevate_string and elevate_package
    global MESSAGES_GENERATED
    print("Results produced by the stix2-elevator are not for production purposes.")
    clear_id_mapping()
    clear_1x_markings_map()
    clear_pattern_cache()
    clear_object_id_mapping()
    clear_observable_mappings()
    cybox.utils.caches.cache_clear()
    MESSAGES_GENERATED = False

    validator_options = get_validator_options()

    try:
        output.set_level(validator_options.verbose)
        output.set_silent(validator_options.silent)

        container = stixmarx.parse(fn)
        stix_package = container.package
        set_option_value("marking_container", container)

        if not isinstance(stix_package, STIXPackage):
            raise TypeError("Must be an instance of stix.core.STIXPackage")

        setup_logger(stix_package.id_)
        warn("Results produced by the stix2-elevator are not for production purposes.", 201)
        json_string = json.dumps(convert_package(stix_package,
                                                 get_option_value("package_created_by_id"),
                                                 get_option_value("default_timestamp")),
                                 indent=4,
                                 separators=(',', ': '),
                                 sort_keys=True)

        if get_option_value("policy") == "no_policy":
            return json_string
        else:
            validation_results = validate_string(json_string, validator_options)
            output.print_results(validation_results)
            if not MESSAGES_GENERATED and validation_results._is_valid:
                return json_string
            else:
                return None

    except ValidationError as ex:
        output.error("Validation error occurred: '%s'" % ex,
                     codes.EXIT_VALIDATION_ERROR)
    except OSError as ex:
        log.error(ex)


def elevate_string(string):
    global MESSAGES_GENERATED
    clear_id_mapping()
    clear_1x_markings_map()
    clear_pattern_cache()
    clear_object_id_mapping()
    clear_observable_mappings()
    cybox.utils.caches.cache_clear()
    MESSAGES_GENERATED = False

    validator_options = get_validator_options()

    try:
        output.set_level(validator_options.verbose)
        output.set_silent(validator_options.silent)

        io = StringIO(string)
        container = stixmarx.parse(io)
        stix_package = container.package
        set_option_value("marking_container", container)

        if not isinstance(stix_package, STIXPackage):
            raise TypeError("Must be an instance of stix.core.STIXPackage")

        setup_logger(stix_package.id_)
        warn("Results produced by the stix2-elevator are not for production purposes.", 201)
        json_string = json.dumps(convert_package(stix_package,
                                                 get_option_value("package_created_by_id"),
                                                 get_option_value("default_timestamp")),
                                 indent=4,
                                 separators=(',', ': '),
                                 sort_keys=True)

        if get_option_value("policy") == "no_policy":
            return json_string
        else:
            validation_results = validate_string(json_string, validator_options)
            output.print_results(validation_results)
            if not MESSAGES_GENERATED and validation_results._is_valid:
                return json_string
            else:
                return None

    except ValidationError as ex:
        output.error("Validation error occurred: '%s'" % ex,
                     codes.EXIT_VALIDATION_ERROR)
    except OSError as ex:
        log.error(ex)


def elevate_package(package):
    global MESSAGES_GENERATED
    clear_id_mapping()
    clear_1x_markings_map()
    clear_pattern_cache()
    clear_object_id_mapping()
    clear_observable_mappings()
    cybox.utils.caches.cache_clear()
    MESSAGES_GENERATED = False

    validator_options = get_validator_options()

    try:
        output.set_level(validator_options.verbose)
        output.set_silent(validator_options.silent)

        # It needs to be re-parsed.
        container = stixmarx.parse(StringIO(package.to_xml()))
        stix_package = container.package
        set_option_value("marking_container", container)

        if not isinstance(stix_package, STIXPackage):
            raise TypeError("Must be an instance of stix.core.STIXPackage")

        setup_logger(stix_package.id_)
        warn("Results produced by the stix2-elevator are not for production purposes.", 201)
        json_string = json.dumps(convert_package(stix_package,
                                                 get_option_value("package_created_by_id"),
                                                 get_option_value("default_timestamp")),
                                 indent=4,
                                 separators=(',', ': '),
                                 sort_keys=True)
        if get_option_value("policy") == "no_policy":
            return json_string
        else:
            validation_results = validate_string(json_string, validator_options)
            output.print_results(validation_results)
            if not MESSAGES_GENERATED and validation_results._is_valid:
                return json_string
            else:
                return None

    except ValidationError as ex:
        output.error("Validation error occurred: '%s'" % ex,
                     codes.EXIT_VALIDATION_ERROR)
    except OSError as ex:
        log.error(ex)
