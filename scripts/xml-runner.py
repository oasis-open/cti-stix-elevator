# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import os
import sys

from elevator import elevate_file


def main():
    for filename in os.listdir(sys.argv[1]):
        path = os.path.join(sys.argv[1], filename)

        if path.endswith(".xml"):
            sys.stdout.write(path + "\n")
            print(elevate_file(path) + "\n")


if __name__ == '__main__':
    main()
