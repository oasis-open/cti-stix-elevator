import json

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

from stix2validator.validators import ValidationOptions
from stix2validator.output import print_results
from stix2validator import validate_string

from elevator.convert_pattern import clear_pattern_mapping
from elevator.ids import clear_id_mapping
from elevator.utils import warn
from elevator.convert_stix import convert_package
from elevator.version import __version__  # noqa


def elevate_file(fn):
    warn("WARNING: Results produced by the stix-elevator are not for production purposes.")
    clear_id_mapping()
    clear_pattern_mapping()

    stix_package = EntityParser().parse_xml(fn)

    if isinstance(stix_package, STIXPackage):
        json_string = json.dumps(convert_package(stix_package), indent=4,
                                 separators=(',', ': '), sort_keys=True)
        validation_results = validate_string(json_string, ValidationOptions())
        print_results(validation_results)
        return json_string
    else:
        raise TypeError("Must be an instance of stix.core.STIXPackage")


def elevate_string(string):
    warn("WARNING: Results produced by the stix-elevator are not for production purposes.")
    clear_id_mapping()
    clear_pattern_mapping()

    io = StringIO(string)
    stix_package = EntityParser().parse_xml(io)

    if isinstance(stix_package, STIXPackage):
        json_string = json.dumps(convert_package(stix_package), indent=4,
                                 separators=(',', ': '), sort_keys=True)
        validation_results = validate_string(json_string, ValidationOptions())
        print_results(validation_results)
        return json_string
    else:
        raise TypeError("Must be an instance of stix.core.STIXPackage")


def elevate_package(package):
    warn("WARNING: Results produced by the stix-elevator are not for production purposes.")
    clear_id_mapping()
    clear_pattern_mapping()

    if isinstance(package, STIXPackage):
        json_string = json.dumps(convert_package(package), indent=4,
                                 separators=(',', ': '), sort_keys=True)
        validation_results = validate_string(json_string, ValidationOptions())
        print_results(validation_results)
        return json_string
    else:
        raise TypeError("Must be an instance of stix.core.STIXPackage")
