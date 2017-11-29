# The json-generator.py is not an essential part of the stix2-elevator library.
# It serves as a complimentary tool to generate "idioms-json" directory for
# testing purposes. Which helps by automating this process.


import os
import sys

from stix2elevator import elevate_file
from stix2elevator.options import initialize_options
from stix2elevator.utils import find_dir

# The output is set to the internal json-idioms container.
# WARNING: This will overwrite the contents inside the idioms-json directory.

# First argument is the output location for json-idioms. Second for input XML.


def main():
    directory = os.path.dirname(__file__)

    if len(sys.argv) > 1:
        json_dir = sys.argv[1]
    else:
        json_dir = find_dir(directory, "idioms-json")

    if len(sys.argv) > 2:
        xml_dir = sys.argv[2]
    else:
        xml_dir = find_dir(directory, "idioms-xml")

    if not os.path.exists(json_dir):
        os.makedirs(json_dir)

    for filename in sorted(os.listdir(xml_dir)):
        file_and_ext = filename.split(".")
        xml_path = os.path.join(xml_dir, filename)

        destination = os.path.join(json_dir, file_and_ext[0] + ".json")
        destination = os.path.abspath(destination)

        initialize_options()

        if file_and_ext[1] == "xml":
            sys.stdout.write(xml_path + "\n")
            json_output = elevate_file(xml_path)

            output_file = open(destination, "w")
            output_file.write(json_output)
            output_file.close()


if __name__ == "__main__":
    main()
