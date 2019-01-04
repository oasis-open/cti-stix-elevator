import json
import os

from stix2elevator.stix_stepper import step_file
from stix2elevator.utils import find_dir

from .test_idioms import (BEFORE_FILENAMES, BEFORE_FILES, MASTER_JSON_FILES,
                          find_index_of_difference, idiom_mappings,
                          setup_tests)


def idiom_stepper_mappings(before_file_path, stored_json):
    """Test fresh conversion from XML to JSON matches stored JSON samples."""
    print("Checking - " + before_file_path)
    print("With Master - " + stored_json["id"])

    converted_json = step_file(before_file_path)
    converted_json = json.loads(converted_json)
    return idiom_mappings(converted_json, stored_json)


def setup_stepper_tests():
    directory = os.path.dirname(__file__)

    before_idioms_dir = find_dir(directory, "idioms-json-2.0-valid")
    after_idioms_dir = find_dir(directory, "idioms-json-2.1-valid")
    setup_tests(before_idioms_dir, after_idioms_dir, ".json", ".json")


def test_stepper_idiom_mapping(test_file, stored_master):
    for good_path, check_path in idiom_stepper_mappings(test_file, stored_master):
        if good_path != check_path:
            find_index_of_difference(good_path, check_path)
            assert good_path == check_path


def pytest_generate_tests(metafunc):
    setup_stepper_tests()
    argnames = ["test_file", "stored_master"]
    argvalues = [(x, y) for x, y in zip(BEFORE_FILES, MASTER_JSON_FILES)]

    metafunc.parametrize(argnames=argnames, argvalues=argvalues, ids=BEFORE_FILENAMES, scope="function")
