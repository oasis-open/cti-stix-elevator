import sys
import os
from convert_stix import convert_file

if __name__ == '__main__':
    for file in os.listdir(sys.argv[1]):
        path = os.path.join(sys.argv[1], file)
        if path.endswith(".xml"):
            print path
            convert_file(path)