import io
import json
import sys
from collections import OrderedDict

from six import text_type
from stix2.pattern_visitor import create_pattern_object

from stix2elevator.convert_stix import create_relationship
from stix2elevator.ids import generate_sco_id
from stix2elevator.utils import Environment


def lookup_stix_id(obs_id, all_objects):
    if obs_id in all_objects:
        return all_objects[obs_id]["id"]


def fix_refs_property(obj, refs_property_name, all_objects):
    refs = obj[refs_property_name]
    obj[refs_property_name] = []
    for r in refs:
        obj[refs_property_name].append(lookup_stix_id(r, all_objects))


def fix_all_refs_properties(obj, refs_property_names, all_objects):
    for name in refs_property_names:
        if name in obj:
            fix_refs_property(obj, name, all_objects)


def fix_ref_property(obj, property_name, all_objects):
    obj[property_name] = lookup_stix_id(obj[property_name], all_objects)


def fix_all_ref_properties(obj, property_names, all_objects):
    for name in property_names:
        if name in obj:
            fix_ref_property(obj, name, all_objects)


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
        if "contains_refs" in obj:
            fix_refs_property(obj, "contains_refs", all_objects)
    elif type_name20 == "email-addr":
        if "belongs_to_ref" in obj:
            fix_ref_property(obj, "belongs_to_ref", all_objects)
    elif type_name20 == "email-message":
        fix_all_ref_properties(obj, ["from_ref", "sender_ref", "raw_email_ref"], all_objects)
        fix_all_refs_properties(obj, ["to_refs", "cc_refs", "bcc_refs"], all_objects)
        if "body_multipart" in obj:
            for mime_part in obj["body_multipart"]:
                if "body_raw_ref" in mime_part:
                    fix_ref_property(mime_part, "body_raw_ref", all_objects)
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
            if "archive-ext" in exts:
                exts["archive-ext"].pop("version", None)
                if "contains_refs" in exts["archive-ext"]:
                    fix_refs_property(exts["archive-ext"], "contains_refs", all_objects)
            if "raster-image-ext" in exts:
                exts["raster-image-ext"].pop("image_compression_algorithm", None)
        if "parent_directory_ref" in obj:
            obj["parent_directory_ref"] = lookup_stix_id(obj["parent_directory_ref"], all_objects)
        if "contains_refs" in obj:
            fix_refs_property(obj, "contains_refs", all_objects)
        if "content_ref" in obj:
            fix_ref_property(obj, "contains_ref", all_objects)
    elif type_name20 == 'ipv4-addr' or type_name20 == 'ipv6-addr' or type_name20 == "domain-name":
        env = Environment(observed_data["created_by_ref"] if "created_by_ref" in observed_data else None,
                          observed_data["created"])
        if "resolves_to_refs" in obj:
            for obs_id in obj["resolves_to_refs"]:
                objs.append(
                    create_relationship(obj["id"], lookup_stix_id(obs_id, all_objects), env, "resolves_to"))
            obj.pop("resolves_to_refs")
        if "belongs_to_refs" in obj:
            for obs_id in obj["resolves_to_refs"]:
                objs.append(
                    create_relationship(obj["id"], lookup_stix_id(obs_id, all_objects), env, "belongs_to"))
            obj.pop("belongs_to_refs")
    elif type_name20 == "network-traffic":
        fix_all_ref_properties(obj,
                               ["src_ref", "dst_ref", "src_payload_ref", "dst_payload_ref", "encapsulated_by_ref"],
                               all_objects)
        if "encapsulates_refs" in obj:
            fix_refs_property(obj, "encapsulates_refs", all_objects)
        if "extensions" in obj:
            exts = obj["extensions"]
            if "socket-ext" in exts:
                exts["socket-ext"].pop("protocol_family", None)
            if "http-request-ext" in exts:
                if "message_body_data_ref" in exts["http-request-ext"]:
                    fix_ref_property(exts["http-request-ext"], "message_body_data_ref", all_objects)
    elif type_name20 == "process":
        obj.pop("name", None)
        obj.pop("arguments", None)
        if "binary_ref" in obj:
            obj["image_ref"] = obj["binary_ref"]
            obj.pop("binary_ref", None)
        fix_all_ref_properties(obj, ["creator_user_ref", "image_ref", "parent_ref"], all_objects)
        fix_all_refs_properties(obj, ["opened_connection_refs", "child_refs"], all_objects)
        if "extensions" in obj:
            exts = obj["extensions"]
            if "windows-service-ext" in exts:
                if "service_dll_refs" in exts["windows-service-ext"]:
                    fix_refs_property(exts["windows-service-ext"], "service_dll_refs", all_objects)
    elif type_name20 == "user-account":
        if "password_last_changed" in obj:
            obj["credential_last_changed"] = obj["password_last_changed"]
            obj.pop("password_last_changed", None)
    elif type_name20 == "windows-registry-key":
        if "creator_user_ref" in obj:
            fix_ref_property(obj, "creator_user_ref", all_objects)
    objs.append(obj)
    return objs


def step_observable_data(object):
    for key, obj in object["objects"].items():
        obj["id"] = generate_sco_id(obj["type"])
    objs = list()
    for key, obj in object["objects"].items():
        objs.extend(step_cyber_observable(obj, object))
    object.pop("objects")
    object["object_refs"] = []
    for obj in objs:
        object["object_refs"].append(obj["id"])
    objs.append(object)
    return objs


def step_pattern(pattern):
    pattern_obj = create_pattern_object(pattern, module_suffix="Elevator", module_name="stix2elevator.convert_pattern")
    # replacing property names performed in toSTIX21
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
        return [object]
    elif object["type"] == "observed-data":
        x = step_observable_data(object)
        return x
    else:
        return [object]


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


def step_file(fn, encoding="utf-8"):
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
        return json_string
    else:
        print("stix_stepper only converts STIX 2.0 to STIX 2.1")
        return


if __name__ == '__main__':
    step_file(sys.argv[1])
