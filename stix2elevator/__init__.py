# Standard Library
import json
import logging
import os
import re
import warnings

# external
import cybox.utils.caches
from six import BytesIO, StringIO, binary_type, text_type
from stix2validator import ValidationError, codes, output
from stix.core import STIXPackage
import stixmarx
from stixmarx.container import MarkingContainer

# internal
from stix2elevator.convert_cybox import clear_directory_mappings
from stix2elevator.convert_pattern import (
    clear_observable_mappings, clear_pattern_cache
)
from stix2elevator.convert_stix import (
    clear_kill_chains_phases_mapping, convert_package
)
from stix2elevator.ids import (
    clear_id_mapping, clear_id_of_obs_in_characterizations,
    clear_object_id_mapping
)
from stix2elevator.options import (
    get_option_value, get_validator_options, set_option_value, setup_logger,
    warn
)
from stix2elevator.utils import (
    Environment, clear_1x_markings_map, validate_stix2_string
)
from stix2elevator.version import __version__  # noqa

# Module-level logger
log = logging.getLogger(__name__)


def clear_globals():
    clear_id_mapping()
    clear_1x_markings_map()
    clear_pattern_cache()
    clear_object_id_mapping()
    clear_observable_mappings()
    clear_kill_chains_phases_mapping()
    clear_id_of_obs_in_characterizations()
    clear_directory_mappings()
    cybox.utils.caches.cache_clear()


def elevate(stix_package):
    global MESSAGES_GENERATED
    MESSAGES_GENERATED = False
    print("Results produced by the stix2-elevator are not for production purposes.")
    clear_globals()
    fn = None

    validator_options = get_validator_options()

    output.set_level(validator_options.verbose)
    output.set_silent(validator_options.silent)

    try:
        if isinstance(stix_package, MarkingContainer):
            # No need to re-parse the MarkingContainer.
            container = stix_package
        elif isinstance(stix_package, STIXPackage):
            io = BytesIO(stix_package.to_xml())
            container = stixmarx.parse(io)
        elif os.path.isfile(stix_package):
            container = stixmarx.parse(stix_package)
            fn = stix_package
        elif isinstance(stix_package, text_type):
            io = StringIO(stix_package)
            container = stixmarx.parse(io)
        elif isinstance(stix_package, binary_type):
            io = BytesIO(stix_package)
            container = stixmarx.parse(io)
        else:
            raise RuntimeError("Unable to resolve object {} of type {}".format(stix_package, type(stix_package)))

        container_package = container.package
        set_option_value("marking_container", container)

        if not isinstance(container_package, STIXPackage):
            raise TypeError("Must be an instance of stix.core.STIXPackage")
    except OSError as ex:
        log.error(ex)
        return None

    try:
        setup_logger(container_package.id_)
        warn("Results produced by the stix2-elevator may generate warning messages which should be investigated.", 201)
        env = Environment(get_option_value("package_created_by_id"))
        json_string = json.dumps(
            convert_package(container_package, env),
            ensure_ascii=False,
            indent=4,
            separators=(',', ': '),
            sort_keys=True
        )

        bundle_id = re.findall(
            r"bundle--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            json_string
        )
        validation_results = validate_stix2_string(json_string, validator_options, fn or bundle_id[0])
        output.print_results([validation_results])

        if get_option_value("policy") == "no_policy":
            return json_string
        else:
            if not MESSAGES_GENERATED and validation_results._is_valid:
                return json_string

    except ValidationError as ex:
        output.error("Validation error occurred: '%s'" % ex,
                     codes.EXIT_VALIDATION_ERROR)


def elevate_file(fn):
    # TODO:  combine elevate_file, elevate_string and elevate_package
    warnings.warn("This method is deprecated and will be removed in the next major release. Please use elevate() instead.", DeprecationWarning)
    global MESSAGES_GENERATED
    MESSAGES_GENERATED = False
    print("Results produced by the stix2-elevator are not for production purposes.")
    clear_globals()

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
        warn("Results produced by the stix2-elevator may generate warning messages which should be investigated.", 201)
        env = Environment(get_option_value("package_created_by_id"))
        json_string = json.dumps(convert_package(stix_package, env),
                                 ensure_ascii=False,
                                 indent=4,
                                 separators=(',', ': '),
                                 sort_keys=True)

        validation_results = validate_stix2_string(json_string, validator_options, fn)
        output.print_results([validation_results])

        if get_option_value("policy") == "no_policy":
            return json_string
        else:
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
    warnings.warn("This method is deprecated and will be removed in the next major release. Please use elevate() instead.", DeprecationWarning)
    global MESSAGES_GENERATED
    MESSAGES_GENERATED = False
    clear_globals()

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
        env = Environment(get_option_value("package_created_by_id"))
        json_string = json.dumps(convert_package(stix_package, env),
                                 ensure_ascii=False,
                                 indent=4,
                                 separators=(',', ': '),
                                 sort_keys=True)

        validation_results = validate_stix2_string(json_string, validator_options)
        output.print_results([validation_results])

        if get_option_value("policy") == "no_policy":
            return json_string
        else:

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
    warnings.warn("This method is deprecated and will be removed in the next major release. Please use elevate() instead.", DeprecationWarning)
    global MESSAGES_GENERATED
    MESSAGES_GENERATED = False
    clear_globals()

    validator_options = get_validator_options()

    try:
        output.set_level(validator_options.verbose)
        output.set_silent(validator_options.silent)

        # It needs to be re-parsed.
        container = stixmarx.parse(BytesIO(package.to_xml()))
        stix_package = container.package
        set_option_value("marking_container", container)

        if not isinstance(stix_package, STIXPackage):
            raise TypeError("Must be an instance of stix.core.STIXPackage")

        setup_logger(stix_package.id_)
        warn("Results produced by the stix2-elevator are not for production purposes.", 201)
        env = Environment(get_option_value("package_created_by_id"))
        json_string = json.dumps(convert_package(stix_package, env),
                                 ensure_ascii=False,
                                 indent=4,
                                 separators=(',', ': '),
                                 sort_keys=True)

        validation_results = validate_stix2_string(json_string, validator_options)
        output.print_results([validation_results])

        if get_option_value("policy") == "no_policy":
            return json_string
        else:
            if not MESSAGES_GENERATED and validation_results._is_valid:
                return json_string
            else:
                return None

    except ValidationError as ex:
        output.error("Validation error occurred: '%s'" % ex,
                     codes.EXIT_VALIDATION_ERROR)
    except OSError as ex:
        log.error(ex)
