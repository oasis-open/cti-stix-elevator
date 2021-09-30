# Standard Library
import io
import json
import logging
import os
import re

# external
import cybox.utils.caches
import lxml.etree
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
    clear_kill_chains_phases_mapping, clear_location_objects,
    clear_observed_data_mappings, clear_unfinished_marked_objects,
    convert_package
)
from stix2elevator.ids import (
    clear_id_mapping, clear_id_of_obs_in_characterizations,
    clear_object_id_mapping
)
from stix2elevator.options import (
    get_option_value, get_validator_options, info, set_option_value,
    setup_logger
)
from stix2elevator.utils import (
    Environment, clear_1x_markings_map, validate_stix2_string
)
from stix2elevator.version import __version__  # noqa

# Module-level logger
log = logging.getLogger(__name__)
log.propagate = False

formatter = logging.Formatter("[%(name)s] [%(levelname)-7s] [%(asctime)s] %(message)s")

# Console Handler for Elevator messages
ch = logging.StreamHandler()
ch.setFormatter(formatter)
log.addHandler(ch)

# global lists

# _IDS_TO_NEW_IDS:                          stix1x_id -> stix2x_id*
# _PATTERN_CACHE:                           stix1x_id (Object) -> stix2x Pattern
# _IDS_TO_CYBER_OBSERVABLES                 stix1x_id (Object) -> stix2.1 SCO* | stix2.0 dict
# _OBSERVABLE_MAPPINGS                      stix1x_id (Object) | stix1x_id (Observable) -> stix1x (Observable)
# _ID_OF_OBSERVABLES_IN_CHARACTERIZATIONS   stix2x_id* (ObservedData)
# _OBSERVABLE_TO_OBSERVED_DATA_MAPPINGS     stix1x_id (Observable) -> stix2x (ObservedData)


def clear_globals():
    clear_id_mapping()
    clear_1x_markings_map()
    clear_pattern_cache()
    clear_object_id_mapping()
    clear_observable_mappings()
    clear_kill_chains_phases_mapping()
    clear_observed_data_mappings()
    clear_id_of_obs_in_characterizations()
    clear_directory_mappings()
    clear_location_objects()
    clear_unfinished_marked_objects()
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
            bytes_obj = io.BytesIO(stix_package.to_xml())
            container = stixmarx.parse(bytes_obj)
        elif isinstance(stix_package, str):
            if stix_package.endswith(".xml") or os.path.isfile(stix_package):
                # a path-like string was passed
                fn = stix_package
                if os.path.exists(fn) is False:
                    raise IOError("The file '{}' was not found.".format(fn))
            else:
                stix_package = io.StringIO(stix_package)
            container = stixmarx.parse(stix_package)
        elif isinstance(stix_package, bytes):
            if stix_package.endswith(b".xml") or os.path.isfile(stix_package):
                # a path-like string was passed
                fn = stix_package
                if os.path.exists(fn) is False:
                    raise IOError("The file '{}' was not found.".format(fn))
            else:
                stix_package = io.BytesIO(stix_package)
            container = stixmarx.parse(stix_package)
        else:
            raise RuntimeError("Unable to resolve object {} of type {}".format(stix_package, type(stix_package)))

        container_package = container.package
        set_option_value("marking_container", container)

        if not isinstance(container_package, STIXPackage):
            raise TypeError("Must be an instance of stix.core.STIXPackage")
    except (OSError, IOError, lxml.etree.Error) as ex:
        log.error("Error occurred: %s", ex)
        return None

    try:
        setup_logger(container_package.id_)
        info("Results produced by the stix2-elevator may generate warning messages which should be investigated.", 201)
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
        output.error("Validation error occurred: '{}'".format(ex))
        output.error("Error Code: {}".format(codes.EXIT_VALIDATION_ERROR))
