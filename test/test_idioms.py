# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

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

from elevator.convert_stix import convert_file
from elevator.utils import iterpath


class MappingContentTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.IGNORE = (u"id", u"idref", u"created_by_ref", u"object_refs",
                      u"marking_ref", u"object_marking_refs",
                      u"target_ref", u"source_ref", u"sighting_of_ref",
                      u"observed_data_refs", u"where_sighted_refs", u"created",
                      u"modified", u"first_seen", u"valid_until", u"valid_from",
                      u"first_observed", u"last_observed", u"published",
                      u"last_seen", u"external_references")

        cls.stored_json_files = []
        cls.converted_json_from_xml = []
        cls.tested_filenames = []

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

            cls.stored_json_files.append(loaded_json)

        for xml_filename in os.listdir(xml_idioms_dir):
            path = os.path.join(xml_idioms_dir, xml_filename)

            converted_json = convert_file(path)
            io = StringIO(converted_json)
            loaded_json = json.load(io)

            cls.converted_json_from_xml.append(loaded_json)
            cls.tested_filenames.append(path)

    def test_idiom_mappings(self):
        """Test fresh conversion from XML to JSON matches stored JSON samples."""
        counter = 0

        for stored, converted in zip(self.stored_json_files,
                                     self.converted_json_from_xml):

            print("Checking - " + self.tested_filenames[counter])

            for good, to_check in zip(iterpath(stored), iterpath(converted)):
                good_path, good_value = good
                to_check_path, to_check_value = to_check

                last_good_field = good_path[-1]

                if isinstance(good_value, (dict, list)):
                    # No need to verify iterable types. Since we will deal
                    # with individual values in the future.
                    continue

                if last_good_field in self.IGNORE:
                    # Since fresh conversion may create dynamic values.
                    # Some fields are omitted for verification. Currently
                    # fields with identifier and timestamp.
                    continue

                self.assertEqual(good_value, to_check_value)

            counter += 1


if __name__ == '__main__':
    unittest.main()
