# The json-generator.py is not an essential part of the stix-elevator library.
# It serves as a complimentary tool to generate "idioms-json" directory for
# testing purposes. Which helps by automating this process.


import os
import sys

from elevator.convert_stix import convert_file

# The output is set to the user home directory.


def main():
    output_path = os.path.expanduser("~/Desktop/")
    directory = os.path.join(output_path, "idioms-json")

    if not os.path.exists(directory):
        os.makedirs(directory)

    for filename in os.listdir(sys.argv[1]):
        file_and_ext = filename.split(".")
        xml_path = os.path.join(sys.argv[1], filename)

        destination = os.path.join(directory, str(file_and_ext[0]) + ".json")
        destination = os.path.abspath(destination)

        if file_and_ext[1] == "xml":
            sys.stdout.write(xml_path + "\n")
            json_output = convert_file(xml_path)

            output_file = open(destination, "w")
            output_file.write(json_output)
            output_file.close()

if __name__ == "__main__":
    main()
