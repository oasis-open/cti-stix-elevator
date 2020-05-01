# Standard Library
import argparse
from collections import OrderedDict
import io
import json
import shlex
import sys

# external
from six import text_type
from stix2.pattern_visitor import create_pattern_object
import stix2validator

# internal
from stix2elevator.ids import generate_sco_id
from stix2elevator.utils import NewlinesHelpFormatter, validate_stix2_string
from stix2elevator.version import __version__


def lookup_stix_id(obs_id, all_objects):
    if obs_id in all_objects:
        return all_objects[obs_id]["id"]


def handle_references(obj, all_objects):
    for key, value in obj.items():
        if isinstance(value, dict):
            handle_references(value, all_objects)
        # handle list of objects
        if isinstance(value, list) and isinstance(value[0], dict):
            for v in value:
                handle_references(v, all_objects)
        elif key.endswith("_ref"):
            obj[key] = lookup_stix_id(obj[key], all_objects)
        elif key.endswith("_refs"):
            refs = obj[key]
            obj[key] = []
            for r in refs:
                obj[key].append(lookup_stix_id(r, all_objects))


def step_cyber_observable(obj, observed_data):
    all_objects = observed_data["objects"]
    objs = []
    type_name20 = obj["type"]

    if type_name20 == "directory":
        if "created" in obj:
            obj["ctime"] = obj["created"]
            obj.pop("created", None)
        if "modified" in obj:
            obj["mtime"] = obj["modified"]
            obj.pop("modified", None)
        if "associated" in obj:
            obj["atime"] = obj["associated"]
            obj.pop("associated", None)
    elif type_name20 == "file":
        obj.pop("is_encrypted", None)
        obj.pop("encryption_algorithm", None)
        obj.pop("decryption_key", None)
        if "created" in obj:
            obj["ctime"] = obj["created"]
            obj.pop("created", None)
        if "modified" in obj:
            obj["mtime"] = obj["modified"]
            obj.pop("modified", None)
        if "associated" in obj:
            obj["atime"] = obj["associated"]
            obj.pop("associated", None)
        if "extensions" in obj:
            exts = obj["extensions"]
            if "raster-image-ext" in exts:
                exts["raster-image-ext"].pop("image_compression_algorithm", None)
    elif type_name20 == "network-traffic":
        if "extensions" in obj:
            exts = obj["extensions"]
            if "socket-ext" in exts:
                exts["socket-ext"].pop("protocol_family", None)
    elif type_name20 == "process":
        obj.pop("name", None)
        obj.pop("arguments", None)
        if "binary_ref" in obj:
            obj["image_ref"] = obj["binary_ref"]
            obj.pop("binary_ref", None)
    elif type_name20 == "user-account":
        if "password_last_changed" in obj:
            obj["credential_last_changed"] = obj["password_last_changed"]
            obj.pop("password_last_changed", None)
    handle_references(obj, all_objects)
    objs.append(obj)
    return objs


def step_observable_data(observed_data):
    scos = list()
    for observable in observed_data["objects"].values():
        observable["id"] = generate_sco_id(observable["type"], observable)
    for observable in observed_data["objects"].values():
        scos.extend(step_cyber_observable(observable, observed_data))
    observed_data.pop("objects")
    observed_data["object_refs"] = []
    for sco in scos:
        observed_data["object_refs"].append(sco["id"])
        for prop in ["description", "external_references"]:
            if prop in sco and sco[prop] in ("", u"", [], None, dict()):
                sco.pop(prop)
    scos.append(observed_data)
    return scos


def step_pattern(pattern):
    pattern_obj = create_pattern_object(pattern, module_suffix="Elevator", module_name="stix2elevator.convert_pattern")
    # replacing property names performed in toSTIX21
    return text_type(pattern_obj.toSTIX21())


def step_object(stix_object):
    type_set = set(("indicator", "malware", "report", "threat-actor", "tool"))
    stix_object["spec_version"] = "2.1"
    if stix_object["type"] in type_set:
        if "labels" in stix_object:
            types_property_name = stix_object["type"].replace("-", "_") + "_types"
            if len(stix_object["labels"]) != 1 or "unknown" not in stix_object["labels"]:
                stix_object[types_property_name] = stix_object["labels"]
            stix_object.pop("labels")
    if stix_object["type"] == "indicator":
        stix_object["pattern"] = step_pattern(stix_object["pattern"])
        stix_object["pattern_type"] = "stix"
        return [stix_object]
    elif stix_object["type"] == "malware":
        # couldn't explicitly represent malware families in 2.0, so assume False
        stix_object["is_family"] = False
        return [stix_object]
    elif stix_object["type"] == "observed-data":
        x = step_observable_data(stix_object)
        return x
    else:
        return [stix_object]


# update "in place"

def step_bundle(bundle):
    additional_objects = []
    current_objects = bundle["objects"]
    bundle["objects"] = []
    for o in current_objects:
        additional_objects.extend(step_object(o))
    bundle.pop("spec_version", None)
    bundle["objects"].extend(additional_objects)
    return bundle


def _get_arg_parser(is_script=True):
    """Create and return an ArgumentParser for this application."""

    desc = "stix_stepper v{0}\n\n".format(__version__)

    parser = argparse.ArgumentParser(
        description=desc,
        formatter_class=NewlinesHelpFormatter,
        epilog=""
    )

    if is_script:
        parser.add_argument(
            "file_",
            help="The input STIX 1.x document to be stepped.",
            metavar="file"
        )

    parser.add_argument(
        "--validator-args",
        help="Arguments to pass to stix2-validator. Default: --strict-types\n\n"
             "Example: stix2_elevator.py <file> --validator-args=\"-v --strict-types -d 212\"",
        dest="validator_args",
        action="store",
        default=""
    )
    return parser


def step_file(fn, validator_options, encoding="utf-8"):
    sys.setrecursionlimit(5000)

    with io.open(fn, "r", encoding=encoding) as json_data:
        json_content = json.load(json_data, object_pairs_hook=OrderedDict)

    if 'spec_version' in json_content and "type" in json_content and json_content["type"] == "bundle":
        new_json_content = step_bundle(json_content)
        json_string = json.dumps(new_json_content,
                                 ensure_ascii=False,
                                 indent=4,
                                 separators=(',', ': '),
                                 sort_keys=True)
        print(json_string)
        try:
            validation_results = validate_stix2_string(json_string, validator_options, fn)
            stix2validator.output.print_results([validation_results])
        except stix2validator.ValidationError as ex:
            stix2validator.output.error("Validation error occurred: '%s'" % ex,
                                        stix2validator.codes.EXIT_VALIDATION_ERROR)
        return json_string
    else:
        print("stix_stepper only converts STIX 2.0 to STIX 2.1")
        return


def main():
    stepper_arg_parser = _get_arg_parser()
    stepper_args = stepper_arg_parser.parse_args()
    validator_options = stix2validator.parse_args(shlex.split(stepper_args.validator_args))

    stix2validator.output.set_level(validator_options.verbose)
    stix2validator.output.set_silent(validator_options.silent)

    step_file(stepper_args.file_, validator_options)


if __name__ == '__main__':
    main()
