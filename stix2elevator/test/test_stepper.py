# Standard Library
import json
import os

# external
import stix2validator

# internal
from stix2elevator.options import initialize_options, set_option_value
from stix2elevator.stix_stepper import step_file
from stix2elevator.utils import extension_definition_id_property, find_dir, id_property

from .test_idioms import (
    BEFORE_FILENAMES, BEFORE_FILES, MASTER_JSON_FILES,
    find_index_of_difference, idiom_mappings, setup_tests
)

# _IGNORE = (u"id",
#            u"bcc_refs", u"cc_refs", u"child_refs", u"object_refs", u"opened_connection_refs", u"to_refs",
#            u"body_raw_ref", u"dst_ref", u"from_refs", u"parent_ref", u"parent_directory_ref", u"source_ref", u"src_ref", u"target_ref"
#            )

_IGNORE = ()


def custom_type(type_name):
    return type_name not in [u"attack-pattern", u"campaign", u"course-of-action", u"grouping", u"identity", u"incident",
                             u"indicator", u"infrastructure", u"intrusion-set", u"location", u"malware", u"malware-instance",
                             u"note", u"observed-data", u"opinion", u"report", u"threat-actor", u"tool", "vulnerability",

                             u"artifact", u"autonomous-system", u"directory", u"domain-name", u"email-addr", u"email-message",
                             u"file", u"ipv4-addr", u"ipv6-addr", u"mac-address", u"mutex", u"network-traffic", u"process",
                             u"software", u"url", u"user-account", u"windows-registry-key", u"x509-certificate",

                             u"language_content", u"marking-definition", u"extension-definition", u"bundle"]


def idiom_stepper_mappings(before_file_path, stored_json):
    """Test fresh conversion from XML to JSON matches stored JSON samples."""
    validator_options = stix2validator.parse_args("")
    initialize_options()
    set_option_value("missing_policy", "use-extensions")
    set_option_value("custom_property_prefix", "elevator")

    stix2validator.output.set_level(validator_options.verbose)
    stix2validator.output.set_silent(validator_options.silent)

    print("Checking - " + before_file_path)
    print("With Master - " + stored_json["id"])

    converted_json = step_file(before_file_path, validator_options)
    converted_json = json.loads(converted_json)
    return idiom_mappings(converted_json, stored_json, _IGNORE)


def setup_stepper_tests():
    directory = os.path.dirname(__file__)

    before_idioms_dir = find_dir(directory, "idioms-json-2.0-valid")
    after_idioms_dir = find_dir(directory, "idioms-json-2.1-valid")
    setup_tests(before_idioms_dir, after_idioms_dir, ".json", ".json")


def test_stepper_idiom_mapping(test_file, stored_master):
    for good_path, check_path in idiom_stepper_mappings(test_file, stored_master):
        if extension_definition_id_property(check_path) and extension_definition_id_property(good_path):
            continue
        # we want to check for ids in the stepper, especially to test deterministic ids - but the stepper MIGHT
        # add a relationship and its id will always be different from the golden one.
        # additionally, process ids are always UUIDv4 - so they will also always be different
        # so we skip testing for equality on relationship and process ids
        if id_property(check_path) and id_property(good_path):
            type_of_good_id = good_path[1].split("--")[0]
            type_of_check_id = check_path[1].split("--")[0]
            if (type_of_good_id == 'relationship' and type_of_check_id == 'relationship' or
                    type_of_good_id == 'process' and type_of_check_id == 'process' or
                    type_of_good_id.startswith("x-") and type_of_check_id.startswith("x-") or
                    custom_type(type_of_good_id) and custom_type(type_of_check_id)):
                continue
        if good_path != check_path:
            find_index_of_difference(good_path, check_path)
            assert check_path == good_path


def pytest_generate_tests(metafunc):
    setup_stepper_tests()
    argnames = ["test_file", "stored_master"]
    argvalues = [(x, y) for x, y in zip(BEFORE_FILES, MASTER_JSON_FILES)]

    metafunc.parametrize(argnames=argnames, argvalues=argvalues, ids=BEFORE_FILENAMES, scope="function")
