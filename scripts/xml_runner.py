# Standard Library
import io
import os
import sys

# internal
from stix2elevator import elevate
from stix2elevator.cli import _get_arg_parser
from stix2elevator.options import (
    get_option_value, initialize_options, set_option_value
)


def main():
    elevator_parser = _get_arg_parser(False)

    elevator_parser.add_argument(
        "dir_",
        help="A directory containing STIX 1.x documents to be elevated.",
        metavar="dir"
    )

    elevator_parser.add_argument(
        "--output-directory",
        help="output logs",
        dest="output_directory",
        action="store",
        default=None
    )
    elevator_args = elevator_parser.parse_args()
    initialize_options(elevator_args)
    set_option_value("validator_args",
                     get_option_value("validator_args") + " --version " + get_option_value("spec_version"))

    all_succeeded = True

    sys.setrecursionlimit(2000)

    for filename in sorted(os.listdir(elevator_args.dir_)):
        path = os.path.join(elevator_args.dir_, filename)

        if path.endswith(".xml"):
            sys.stdout.write(path + "\n")
            file_and_ext = filename.split(".")
            set_option_value("file_", file_and_ext[0])
            result = elevate(path)

            if result:
                if elevator_args.output_directory:
                    destination = os.path.join(elevator_args.output_directory, file_and_ext[0] + ".json")
                    destination = os.path.abspath(destination)
                    with io.open(destination, "w", encoding="utf-8") as f:
                        f.write(result)
                else:
                    sys.stdout.write(result + "\n")
            else:
                all_succeeded = False
    if not all_succeeded:
        sys.exit(1)


if __name__ == '__main__':
    main()
