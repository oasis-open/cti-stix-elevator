# Standard Library
import argparse
import base64
from datetime import datetime
import os
import re
import textwrap

# external
from stix2validator import validate_string
from stix2validator.validator import FileValidationResults

# internal
from stix2elevator.options import info, warn


def id_property(path):
    name = path[0][-1]
    if name.find('[') != -1:
        name = path[0][-2]
    return name == "id" or name.endswith("ref") or name.endswith("refs")


def extension_definition_id_property(path):
    if len(path[0]) > 3:
        name = path[0][3]
        return name.startswith("extension-definition")
    else:
        return False


def identifying_info(stix1x_obj):
    if stix1x_obj:
        if hasattr(stix1x_obj, "id_") and stix1x_obj.id_:
            return str(stix1x_obj.id_)
        elif hasattr(stix1x_obj, "idref") and stix1x_obj.idref:
            return "idref " + str(stix1x_obj.idref)
        elif hasattr(stix1x_obj, "title") and stix1x_obj.title:
            return "'" + str(stix1x_obj.title) + "'"
        elif hasattr(stix1x_obj, "name") and stix1x_obj.name:
            return "'" + str(stix1x_obj.name) + "'"
        elif hasattr(stix1x_obj, "item") and stix1x_obj.item:
            # Useful in Related Types.
            return "parent of object " + identifying_info(stix1x_obj.item)
        else:
            return stix1x_obj.__class__.__name__
    return "- no identifying information available"


def add_label(stix2x_instance, label):
    if "labels" not in stix2x_instance:
        stix2x_instance["labels"] = [label]
    else:
        stix2x_instance["labels"].append(label)


def canonicalize_label(t):
    t = str(t)
    t = t.lower()

    t = t.replace(" ", "-")

    return t


def map_vocabs_to_label(t, vocab_map):
    if vocab_map.get(t, ""):
        return vocab_map[t]
    else:
        return canonicalize_label(t)


def convert_controlled_vocabs_to_open_vocabs(new_obj, new_property_name, old_vocabs, vocab_mapping, only_one, required=True):
    if not old_vocabs and required:
        if only_one:
            new_obj[new_property_name] = "unknown"
        else:
            new_obj[new_property_name] = ["unknown"]
        warn("No STIX 1.x vocab value given for %s, using 'unknown'", 509, new_property_name)
    else:
        new_obj[new_property_name] = []
        for t in old_vocabs:
            if new_obj[new_property_name] is None or not only_one:
                if isinstance(t, (str, bytes)):
                    new_obj[new_property_name].append(map_vocabs_to_label(t, vocab_mapping))
                else:
                    new_obj[new_property_name].append(map_vocabs_to_label(str(t.value), vocab_mapping))
            else:
                warn("Only one %s allowed in STIX 2.0 - used first one", 510, new_property_name)


def strftime_with_appropriate_fractional_seconds(timestamp, milliseconds_only):
    if isinstance(timestamp, (str, bytes)):
        timestamp = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
    if milliseconds_only:
        return timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    else:
        return timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def convert_timestamp_to_string(timestamp, entity=None, parent_timestamp=None, milliseconds_only=False):
    if timestamp is not None:
        return strftime_with_appropriate_fractional_seconds(timestamp, milliseconds_only)
    elif parent_timestamp is not None:
        info("Using parent object timestamp with %s", 902, identifying_info(entity))
        return strftime_with_appropriate_fractional_seconds(parent_timestamp, milliseconds_only)
    else:
        warn("Timestamp not available for %s, using current time", 905, identifying_info(entity))
        return strftime_with_appropriate_fractional_seconds(datetime.now(), milliseconds_only)


def convert_timestamp_of_stix_object(entity, parent_timestamp=None, milliseconds_only=False):
    if entity and hasattr(entity, "timestamp"):
        if entity.timestamp is not None:
            return strftime_with_appropriate_fractional_seconds(entity.timestamp, milliseconds_only)
    if parent_timestamp is not None:
        info("Using parent object timestamp with %s", 902, identifying_info(entity))
        # parent_timestamp might have already been converted to a string in a previous call
        if isinstance(parent_timestamp, str):
            return parent_timestamp
        else:
            return strftime_with_appropriate_fractional_seconds(parent_timestamp, milliseconds_only)
    warn("Timestamp not available for %s, using current time", 905, identifying_info(entity))
    return strftime_with_appropriate_fractional_seconds(datetime.now(), milliseconds_only)


_TYPE_MAP_FROM_1_x_TO_2_x = {"observable": "observed-data",
                             "toolinformation": "tool"}


def map_1x_type_to_20(stix1x_type):
    if stix1x_type in _TYPE_MAP_FROM_1_x_TO_2_x:
        return _TYPE_MAP_FROM_1_x_TO_2_x[stix1x_type]
    return stix1x_type


_MARKING_MAP_FROM_1_x_TO_2_x = {}

_MARKING_MAP_FROM_2_x_ID_TO_2_x = {}


def check_map_1x_markings_to_2x(stix1x_marking):
    return (stix1x_marking in _MARKING_MAP_FROM_1_x_TO_2_x or
            stix1x_marking.id_ in _MARKING_MAP_FROM_1_x_TO_2_x or
            stix1x_marking.idref in _MARKING_MAP_FROM_1_x_TO_2_x)


def map_1x_markings_to_2x(stix1x_marking):
    if check_map_1x_markings_to_2x(stix1x_marking):
        if stix1x_marking in _MARKING_MAP_FROM_1_x_TO_2_x:
            return _MARKING_MAP_FROM_1_x_TO_2_x[stix1x_marking]
        if stix1x_marking.id_ in _MARKING_MAP_FROM_1_x_TO_2_x:
            return _MARKING_MAP_FROM_1_x_TO_2_x[stix1x_marking.id_]
        if stix1x_marking.idref in _MARKING_MAP_FROM_1_x_TO_2_x:
            return _MARKING_MAP_FROM_1_x_TO_2_x[stix1x_marking.idref]
    return stix1x_marking


def lookup_marking_reference(marking_ref):
    if marking_ref in _MARKING_MAP_FROM_2_x_ID_TO_2_x:
        return _MARKING_MAP_FROM_2_x_ID_TO_2_x[marking_ref]
    return None


def add_marking_map_entry(stix1x_marking, stix2x_marking):
    if stix1x_marking not in _MARKING_MAP_FROM_1_x_TO_2_x:
        _MARKING_MAP_FROM_1_x_TO_2_x[stix1x_marking] = stix2x_marking
        if stix1x_marking.id_:
            _MARKING_MAP_FROM_1_x_TO_2_x[stix1x_marking.id_] = stix2x_marking
        _MARKING_MAP_FROM_2_x_ID_TO_2_x[stix2x_marking["id"]] = stix2x_marking
        return
    return map_1x_markings_to_2x(stix1x_marking)


def clear_1x_markings_map():
    global _MARKING_MAP_FROM_1_x_TO_2_x
    global _MARKING_MAP_FROM_2_x_ID_TO_2_x
    _MARKING_MAP_FROM_1_x_TO_2_x = {}
    _MARKING_MAP_FROM_2_x_ID_TO_2_x = {}


def apply_ais_markings(stix2x_instance, stix2x_marking):
    instance_labels = stix2x_instance.get("labels", []) + stix2x_marking.get("labels", [])
    if instance_labels and stix2x_marking["created_by_ref"] == stix2x_instance["id"]:
        stix2x_instance["labels"] = instance_labels
        stix2x_instance["created_by_ref"] = stix2x_instance["id"]


def set_tlp_reference(stix2x_instance, color, prop):
    if color == "white":
        stix2x_instance[prop] = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    elif color == "green":
        stix2x_instance[prop] = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
    elif color == "amber":
        stix2x_instance[prop] = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
    elif color == "red":
        stix2x_instance[prop] = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"


def iterpath(obj, path=None):
    """
    Generator which walks the input ``obj`` model. Each iteration yields a
    tuple containing a list of ancestors and the property value.

    Args:
        obj: A TLO object.
        path: None, used recursively to store ancestors.

    Example:
        >>> for item in iterpath(tlo):
        >>>     print(item)
        (['type'], 'campaign')
        ...
        (['cybox', 'objects', '[0]', 'hashes', 'sha1'], 'cac35ec206d868b7d7cb0b55f31d9425b075082b')

    Returns:
        tuple: Containing two items: a list of ancestors and the property value.

    """
    if path is None:
        path = []

    for varname, varobj in iter(sorted(obj.items())):
        path.append(varname)
        yield (path, varobj)

        if isinstance(varobj, dict):

            for item in iterpath(varobj, path):
                yield item

        elif isinstance(varobj, list):

            for idx, item in enumerate(varobj):
                index = "[{0}]".format(idx)
                path.append(index)

                yield (path, item)

                if isinstance(item, dict):
                    for descendant in iterpath(item, path):
                        yield descendant

                path.pop()

        path.pop()


def operation_on_path(obj, path, value, op=1):
    """operations: (1 = set_value, 2 = delete_entry)"""
    current = path[0]
    path = path[1:]

    if isinstance(current, int):
        current_obj = obj[current]
    elif "[" in current and "]" in current:
        current = int(current.strip("[]"))
        current_obj = obj[current]
    else:
        current_obj = obj[current]

    if not path:
        if op == 1:
            obj[current] = value
        elif op == 2:
            del obj[current]

        return

    operation_on_path(current_obj, path, value, op)


def find_dir(path, directory):
    """
    Args:
        path: str containing path of the script calling this method.
        directory: str containing directory to find.

    Returns:
        str: A string containing the absolute path to the directory.
        None otherwise.

    Note:
        It only finds directories under the cti-stix-elevator package.

    Raises:
        RuntimeError: If trying to access other directories outside of the
        cti-stix-elevator package.
    """
    working_dir = path.split("cti-stix-elevator")

    if len(working_dir) <= 1 or not all(x for x in working_dir):
        msg = "Verify working directory. Only works under cti-stix-elevator"
        raise RuntimeError(msg)

    working_dir = os.path.join(working_dir[0], "cti-stix-elevator")

    for root, dirs, files in os.walk(working_dir, topdown=True):
        if directory in dirs:
            found_dir = os.path.join(root, directory)
            return os.path.abspath(found_dir)


class NewlinesHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Custom help formatter to insert newlines between argument help texts.
    """
    def _split_lines(self, text, width):
        text = self._whitespace_matcher.sub(' ', text).strip()
        txt = textwrap.wrap(text, width)
        txt[-1] += '\n'
        return txt


def validate_stix2_string(json_string, validator_options, file_path=None):
    results = validate_string(json_string, validator_options)
    fvr = FileValidationResults(results.is_valid, file_path, results)
    return fvr


def encode_in_base64(s):
    return base64.b64encode(str(s).encode('utf-8')).decode('utf-8')


def convert_to_stix_literal(s):
    return re.sub("\\-+", "-", s.replace(" ", "-").lower())


def get_environment_variable_value(name, no_value_default="ignore"):
    value = os.getenv(name)
    if value:
        return value
    else:
        return no_value_default


class Environment():
    def __init__(self, created_by_ref=None, timestamp=None, bundle_instance=None, get_identity_called=False):
        self.created_by_ref = created_by_ref
        self.timestamp = timestamp
        self.bundle_instance = bundle_instance
        self.get_identity_called = get_identity_called

    def newEnv(self, created_by_ref=None, timestamp=None, get_identity_called=False):
        return Environment(created_by_ref if created_by_ref else self.created_by_ref,
                           timestamp if timestamp else self.timestamp,
                           self.bundle_instance,
                           get_identity_called if get_identity_called else self.get_identity_called)

    def add_to_env(self, created_by_ref=None, timestamp=None):
        if created_by_ref:
            self.created_by_ref = created_by_ref
        if timestamp:
            self.timestamp = timestamp
