
from __future__ import print_function

import json
import os

from six import StringIO
from six.moves import zip

from stix2elevator import elevate_file
from stix2elevator.options import initialize_options, set_option_value, get_option_value
from stix2elevator.utils import iterpath, find_dir


TESTED_XML_FILES = []
XML_FILENAMES = []
MASTER_JSON_FILES = []

IGNORE = (u"id", u"idref", u"created_by_ref", u"object_refs", u"marking_ref",
          u"object_marking_refs", u"target_ref", u"source_ref", u"valid_until",
          u"sighting_of_ref", u"observed_data_refs", u"where_sighted_refs",
          u"created", u"modified", u"first_seen", u"valid_from", u"last_seen",
          u"first_observed", u"last_observed", u"published",
          u"external_references")


def idiom_mappings(xml_file_path, stored_json):
    """Test fresh conversion from XML to JSON matches stored JSON samples."""
    print("Checking - " + xml_file_path)
    print("With Master - " + stored_json["id"])

    initialize_options()
    set_option_value("log_level", "CRITICAL")
    set_option_value("validator_args", "--no-cache")
    if not get_option_value("policy") == "no_policy":
        print("'no_policy' is not allowed for testing")
    set_option_value("policy", "no_policy")

    converted_json = elevate_file(xml_file_path)
    io = StringIO(converted_json)
    converted_json = json.load(io)

    for good, to_check in zip(iterpath(stored_json), iterpath(converted_json)):
        good_path, good_value = good
        last_good_field = good_path[-1]

        if isinstance(good_value, (dict, list)):
            # Rule #1: No need to verify iterable types. Since we will deal
            # with individual values in the future.
            continue

        if (any(s in (u"object_marking_refs", u"granular_markings")
                for s in good_path)):
            # Exception to Rule #1: object_marking_refs and granular_markings
            # are not verifiable because they contain identifiers per rule #2.
            continue

        if last_good_field in IGNORE:
            # Rule #2: Since fresh conversion may create dynamic values.
            # Some fields are omitted for verification. Currently
            # fields with: identifier and timestamp values.
            continue

        yield good, to_check


def setup_tests():
    directory = os.path.dirname(__file__)

    xml_idioms_dir = find_dir(directory, "idioms-xml")
    json_idioms_dir = find_dir(directory, "idioms-json")

    print("Setting up tests from following directories...")
    print(xml_idioms_dir)
    print(json_idioms_dir)

    for json_filename in sorted(os.listdir(json_idioms_dir)):
        if json_filename.endswith(".json"):
            path = os.path.join(json_idioms_dir, json_filename)

            json_file = open(path, "r")
            io = StringIO(json_file.read())
            loaded_json = json.load(io)
            json_file.close()

            MASTER_JSON_FILES.append(loaded_json)

    for xml_filename in sorted(os.listdir(xml_idioms_dir)):
        if xml_filename.endswith(".xml"):
            path = os.path.join(xml_idioms_dir, xml_filename)
            XML_FILENAMES.append(xml_filename.split(".")[0])
            TESTED_XML_FILES.append(path)


def test_idiom_mapping(test_file, stored_master):
    for good_path, check_path in idiom_mappings(test_file, stored_master):
        assert good_path == check_path


def pytest_generate_tests(metafunc):
    setup_tests()
    argnames = ["test_file", "stored_master"]
    argvalues = [(x, y) for x, y in zip(TESTED_XML_FILES, MASTER_JSON_FILES)]

    metafunc.parametrize(argnames=argnames, argvalues=argvalues, ids=XML_FILENAMES, scope="function")
