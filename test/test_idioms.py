import os
import json
import unittest

try:
    from itertools import izip as zip
except ImportError:
    from itertools import zip_longest as zip

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

from elevator import elevate_file
from elevator.utils import iterpath
from elevator.options import initialize_options, set_option_value


TESTED_XML_FILES = []
XML_FILENAMES = []
MASTER_JSON_FILES = []

IGNORE = (u"id", u"idref", u"created_by_ref", u"object_refs", u"marking_ref",
          u"object_marking_refs", u"target_ref", u"source_ref", u"valid_until",
          u"sighting_of_ref", u"observed_data_refs", u"where_sighted_refs",
          u"created", u"modified", u"first_seen", u"valid_from", u"last_seen",
          u"first_observed", u"last_observed", u"published",
          u"external_references")


class MappingContentTest(unittest.TestCase):
    longMessage = True


def idiom_mappings(xml_file_path, stored_json):
    """Test fresh conversion from XML to JSON matches stored JSON samples."""
    print("Checking - " + xml_file_path)

    initialize_options()
    set_option_value("no_incidents", False)

    converted_json = elevate_file(xml_file_path)
    io = StringIO(converted_json)
    converted_json = json.load(io)

    for good, to_check in zip(iterpath(stored_json), iterpath(converted_json)):
        good_path, good_value = good
        last_good_field = good_path[-1]

        if isinstance(good_value, (dict, list)):
            # No need to verify iterable types. Since we will deal
            # with individual values in the future.
            continue

        if last_good_field in IGNORE:
            # Since fresh conversion may create dynamic values.
            # Some fields are omitted for verification. Currently
            # fields with: identifier and timestamp values.
            continue

        yield good, to_check


def test_generator(test_file, stored_master):
    def test(self):
        for good_path, check_path in idiom_mappings(test_file, stored_master):
            self.assertEquals(good_path, check_path)
    return test


def setup_tests():
    directory = os.path.dirname(__file__)
    path, last_dir = os.path.split(directory)

    xml_idioms_dir = os.path.join(path, "idioms-xml")
    xml_idioms_dir = os.path.abspath(xml_idioms_dir)

    json_idioms_dir = os.path.join(path, "idioms-json")
    json_idioms_dir = os.path.abspath(json_idioms_dir)

    print("Setting up tests from following directories...")
    print(xml_idioms_dir)
    print(json_idioms_dir)

    for json_filename in os.listdir(json_idioms_dir):
        path = os.path.join(json_idioms_dir, json_filename)

        json_file = open(path, "r")
        io = StringIO(json_file.read())
        loaded_json = json.load(io)
        json_file.close()

        MASTER_JSON_FILES.append(loaded_json)

    for xml_filename in os.listdir(xml_idioms_dir):
        path = os.path.join(xml_idioms_dir, xml_filename)
        XML_FILENAMES.append(xml_filename.split(".")[0])
        TESTED_XML_FILES.append(path)


def load_tests(loader, standard_tests, pattern):
    setup_tests()

    suite = unittest.TestSuite()

    for idx, tname in enumerate(XML_FILENAMES):
        test_name = "test_%s" % tname
        test = test_generator(TESTED_XML_FILES[idx], MASTER_JSON_FILES[idx])
        setattr(MappingContentTest, test_name, test)

    standard_tests = loader.loadTestsFromTestCase(MappingContentTest)
    suite.addTests(standard_tests)

    return suite


if __name__ == '__main__':
    unittest.main()
