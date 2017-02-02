import os
import sys

from stix2elevator import elevate_file
from stix2elevator.options import initialize_options, set_option_value


def main():
    for filename in os.listdir(sys.argv[1]):
        path = os.path.join(sys.argv[1], filename)

        initialize_options()
        set_option_value("incidents", False)
        if path.endswith(".xml"):
            sys.stdout.write(path + "\n")
            print(elevate_file(path) + "\n")


if __name__ == '__main__':
    main()
