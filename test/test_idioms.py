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


IGNORE = (u"id", u"idref", u"created_by_ref", u"object_refs", u"marking_ref",
          u"object_marking_refs", u"target_ref", u"source_ref", u"valid_until",
          u"sighting_of_ref", u"observed_data_refs", u"where_sighted_refs",
          u"created", u"modified", u"first_seen", u"valid_from", u"last_seen",
          u"first_observed", u"last_observed", u"published",
          u"external_references")


def idiom_mappings(xml_file_path, stored_json):
    """Test fresh conversion from XML to JSON matches stored JSON samples."""
    print("Checking - " + xml_file_path)

    converted_json = convert_file(xml_file_path)
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


class MappingContentTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.longMessage = True
        cls.stored_json_files = []
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
            cls.tested_filenames.append(path)

    def test_Appendix_G_IOCs_Full(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[0],
                                                    self.stored_json_files[0]):
            self.assertEquals(good_path, check_path)

    def test_block_network_traffic(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[1],
                                                    self.stored_json_files[1]):
            self.assertEquals(good_path, check_path)

    def test_campaign_v_actors(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[2],
                                                    self.stored_json_files[2]):
            self.assertEquals(good_path, check_path)

    def test_command_and_control_ip_list(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[3],
                                                    self.stored_json_files[3]):
            self.assertEquals(good_path, check_path)

    def test_cve_in_exploit_target(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[4],
                                                    self.stored_json_files[4]):
            self.assertEquals(good_path, check_path)

    def test_file_hash_reputation(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[5],
                                                    self.stored_json_files[5]):
            self.assertEquals(good_path, check_path)

    def test_fix_embedded_relationship_example(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[6],
                                                    self.stored_json_files[6]):
            self.assertEquals(good_path, check_path)

    def test_identifying_a_threat_actor_group(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[7],
                                                    self.stored_json_files[7]):
            self.assertEquals(good_path, check_path)

    def test_incident_malware(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[8],
                                                    self.stored_json_files[8]):
            self.assertEquals(good_path, check_path)

    def test_incident_with_affected_asset(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[9],
                                                    self.stored_json_files[9]):
            self.assertEquals(good_path, check_path)

    def test_incident_with_related_observables(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[10],
                                                    self.stored_json_files[10]):
            self.assertEquals(good_path, check_path)

    def test_indicator_for_c2_ip_address(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[11],
                                                    self.stored_json_files[11]):
            self.assertEquals(good_path, check_path)

    def test_indicator_for_malicious_url(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[12],
                                                    self.stored_json_files[12]):
            self.assertEquals(good_path, check_path)

    def test_indicator_w_kill_chain(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[13],
                                                    self.stored_json_files[13]):
            self.assertEquals(good_path, check_path)

    def test_kill_chain(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[14],
                                                    self.stored_json_files[14]):
            self.assertEquals(good_path, check_path)

    def test_malicious_email_indicator_with_attachment(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[15],
                                                    self.stored_json_files[15]):
            self.assertEquals(good_path, check_path)

    def test_malware_characterization_using_maec(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[16],
                                                    self.stored_json_files[16]):
            self.assertEquals(good_path, check_path)

    def test_malware_indicator_for_file_hash(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[17],
                                                    self.stored_json_files[17]):
            self.assertEquals(good_path, check_path)

    def test_Mandiant_APT1_Report(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[18],
                                                    self.stored_json_files[18]):
            self.assertEquals(good_path, check_path)

    def test_multiple_reports_in_package(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[19],
                                                    self.stored_json_files[19]):
            self.assertEquals(good_path, check_path)

    def test_pattern_id_ref_issue(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[20],
                                                    self.stored_json_files[20]):
            self.assertEquals(good_path, check_path)

    def test_simple_incident(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[21],
                                                    self.stored_json_files[21]):
            self.assertEquals(good_path, check_path)

    def test_snort_test_mechanism(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[22],
                                                    self.stored_json_files[22]):
            self.assertEquals(good_path, check_path)

    def test_threat_actor_leveraging_attack_patterns_and_malware(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[23],
                                                    self.stored_json_files[23]):
            self.assertEquals(good_path, check_path)

    def test_victim_targeting(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[24],
                                                    self.stored_json_files[24]):
            self.assertEquals(good_path, check_path)

    def test_victim_targeting_sector(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[25],
                                                    self.stored_json_files[25]):
            self.assertEquals(good_path, check_path)

    def test_yara_test_mechanism(self):
        for good_path, check_path in idiom_mappings(self.tested_filenames[26],
                                                    self.stored_json_files[26]):
            self.assertEquals(good_path, check_path)

if __name__ == '__main__':
    unittest.main()
