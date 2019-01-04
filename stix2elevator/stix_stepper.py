import io
import json
import sys

from six import text_type
from stix2.pattern_visitor import create_pattern_object


def step_cyber_observable(obj):
    type_name20 = obj["type"]
    if type_name20 == "file":
        obj.pop("is_encrypted", None)
        obj.pop("encryption_algorithm", None)
        obj.pop("decryption_key", None)
        if "extensions" in obj:
            exts = obj["extensions"]
            if "archive-ext" in exts:
                exts["archive-ext"].pop("version", None)
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


def step_observable_data(object):
    for key, obj in object["objects"].items():
        step_cyber_observable(obj)


def step_pattern(pattern):
    pattern_obj = create_pattern_object(pattern, module_suffix="Elevator", module_name="stix2elevator.convert_pattern")
    return text_type(pattern_obj.toSTIX21())


def step_object(object):
    object["spec_version"] = "2.1"
    if (object["type"] == "indicator" or object["type"] == "malware" or
            object["type"] == "report" or object["type"] == "threat-actor" or
            object["type"] == "tool"):
        if "labels" in object:
            types_property_name = object["type"].replace("-", "_") + "_types"
            object[types_property_name] = object["labels"]
            object.pop("labels")
        if object["type"] == "indicator":
            object["pattern"] = step_pattern(object["pattern"])
    elif object["type"] == "observed-data":
        step_observable_data(object)


# update "in place"

def step_bundle(bundle):
    for o in bundle["objects"]:
        step_object(o)
    bundle.pop("spec_version", None)
    return bundle


def step_file(fn, encoding="utf-8"):
    sys.setrecursionlimit(5000)
    with io.open(fn, "r", encoding=encoding) as json_data:
        json_content = json.load(json_data)

    if 'spec_version' in json_content and "type" in json_content and json_content["type"] == "bundle":
        json_string = json.dumps(step_bundle(json_content),
                                 ensure_ascii=False,
                                 indent=4,
                                 separators=(',', ': '),
                                 sort_keys=True)
        print(json_string)
        return json_string
    else:
        print("stix_stepper only converts STIX 2.0 to STIX 2.1")
        return


if __name__ == '__main__':
    step_file(sys.argv[1])
