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


class MappingContentTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.stored_json_files = []
        cls.converted_json_from_xml = []

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

    def test_idiom_mappings(self):
        """Test fresh conversion from XML to JSON matches stored JSON samples."""
        for stored, converted in zip(self.stored_json_files,
                                     self.converted_json_from_xml):

            # Make this better... Fails currently because of id's and timestamps.
            self.assertDictEqual(stored, converted)


if __name__ == '__main__':
    unittest.main()
