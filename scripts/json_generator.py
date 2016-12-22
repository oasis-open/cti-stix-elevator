# The json-generator.py is not an essential part of the stix-elevator library.
# It serves as a complimentary tool to generate "idioms-json" directory for
# testing purposes. Which helps by automating this process.


import os
import sys

from elevator import elevate_file
from elevator.options import initialize_options, set_option_value

# The output is set to the own json-idioms container.
# WARNING: This will overwrite the contents inside the idioms-json directory.


def main():

    directory = os.path.dirname(__file__)
    project_path, last_dir = os.path.split(directory)

    if len(sys.argv) > 1:
        json_dir = sys.argv[1]
    else:
        json_dir = os.path.join(project_path, "idioms-json")
        json_dir = os.path.abspath(json_dir)

    if len(sys.argv) > 2:
        xml_dir = sys.argv[2]
    else:
        xml_dir = os.path.join(project_path, "idioms-xml")
        xml_dir = os.path.abspath(xml_dir)

    if not os.path.exists(json_dir):
        os.makedirs(json_dir)

    for filename in os.listdir(xml_dir):
        file_and_ext = filename.split(".")
        xml_path = os.path.join(xml_dir, filename)

        destination = os.path.join(json_dir, str(file_and_ext[0]) + ".json")
        destination = os.path.abspath(destination)

        initialize_options()
        set_option_value("no_incidents", False)

        if file_and_ext[1] == "xml":
            sys.stdout.write(xml_path + "\n")
            json_output = elevate_file(xml_path)

            output_file = open(destination, "w")
            output_file.write(json_output)
            output_file.close()

if __name__ == "__main__":
    main()
