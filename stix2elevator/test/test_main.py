# Standard Library
from argparse import Namespace
import io
import os

# external
import pytest
from stix.core import STIXPackage
import stixmarx

# internal
from stix2elevator import elevate, options
from stix2elevator.options import (
    ElevatorOptions, get_option_value, initialize_options, set_option_value
)
from stix2elevator.utils import find_dir, get_environment_variable_value

# This module only tests for the main functions used to interact with the elevator from a programmatic or
# interactive point of view. Actual idioms tests are done in test_idioms.py


def setup_options():
    version = get_environment_variable_value('VERSION', "2.1")
    policy = get_environment_variable_value("MISSING_POLICY", "ignore")

    initialize_options()
    set_option_value("missing_policy", policy)
    set_option_value("log_level", "DEBUG")
    set_option_value("spec_version", version)
    set_option_value("validator_args", "--version " + version)
    set_option_value("policy", "no_policy")


@pytest.mark.parametrize("opts", [
    ElevatorOptions(policy="no_policy", spec_version=get_environment_variable_value('VERSION'), log_level="DEBUG", disabled=[212, 901]),
    {"policy": "no_policy", "spec_version": get_environment_variable_value('VERSION'), "log_level": "DEBUG", "disabled": [212, 901]},
    Namespace(policy="no_policy", spec_version=get_environment_variable_value('VERSION'), log_level="DEBUG", disabled="212,901",
              file_=None, incidents=False, missing_policy=get_environment_variable_value("MISSING_POLICY"),
              custom_property_prefix="elevator", infrastructure=False, package_created_by_id=None,
              default_timestamp=None, validator_args="--strict-types", enabled=None, silent=False,
              message_log_directory=None, output_directory=None, markings_allowed="", acs=False),
])
def test_setup_options(opts):
    options.ALL_OPTIONS = None  # To make sure we can set it again
    initialize_options(opts)
    assert get_option_value("policy") == "no_policy"
    assert get_option_value("spec_version") == get_environment_variable_value('VERSION')
    assert get_option_value("log_level") == "DEBUG"
    assert get_option_value("disabled") == [212, 901]


def test_elevate_with_marking_container():
    setup_options()

    directory = os.path.dirname(__file__)
    xml_idioms_dir = find_dir(directory, "idioms-xml")
    archive_file = os.path.join(xml_idioms_dir, "141-TLP-marking-structures.xml")

    with io.open(archive_file, mode="r", encoding="utf-8") as f:
        input_stix = f.read()

    container = stixmarx.parse(io.StringIO(input_stix))
    json_result = elevate(container)
    assert json_result
    print(json_result)


def test_elevate_with_stix_package():
    setup_options()

    directory = os.path.dirname(__file__)
    xml_idioms_dir = find_dir(directory, "idioms-xml")
    archive_file = os.path.join(xml_idioms_dir, "141-TLP-marking-structures.xml")

    with io.open(archive_file, mode="r", encoding="utf-8") as f:
        input_stix = f.read()

    json_result = elevate(STIXPackage.from_xml(io.StringIO(input_stix)))
    assert json_result
    print(json_result)


def test_elevate_with_text_string():
    setup_options()

    directory = os.path.dirname(__file__)
    xml_idioms_dir = find_dir(directory, "idioms-xml")
    archive_file = os.path.join(xml_idioms_dir, "141-TLP-marking-structures.xml")

    with io.open(archive_file, mode="r", encoding="utf-8") as f:
        input_stix = f.read()

    json_result = elevate(input_stix)
    assert json_result
    print(json_result)


def test_elevate_with_binary_string():
    setup_options()

    directory = os.path.dirname(__file__)
    xml_idioms_dir = find_dir(directory, "idioms-xml")
    archive_file = os.path.join(xml_idioms_dir, "141-TLP-marking-structures.xml")

    with io.open(archive_file, mode="rb") as f:
        input_stix = f.read()

    json_result = elevate(input_stix)
    assert json_result
    print(json_result)


def test_elevate_with_file():
    setup_options()

    directory = os.path.dirname(__file__)
    xml_idioms_dir = find_dir(directory, "idioms-xml")
    archive_file = os.path.join(xml_idioms_dir, "141-TLP-marking-structures.xml")

    json_result = elevate(archive_file)
    assert json_result
    print(json_result)
