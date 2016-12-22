import os
import sys

from elevator import elevate_file
from elevator.options import initialize_options


def main():
    for filename in os.listdir(sys.argv[1]):
        path = os.path.join(sys.argv[1], filename)

        initialize_options()
        if path.endswith(".xml"):
            sys.stdout.write(path + "\n")
            print(elevate_file(path) + "\n")


if __name__ == '__main__':
    main()
