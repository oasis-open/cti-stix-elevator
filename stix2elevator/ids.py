# Standard Library
import importlib
import inspect
import re
import uuid

# external
from stix2.base import SCO_DET_ID_NAMESPACE
from stix2.canonicalization.Canonicalize import canonicalize

# internal
from stix2elevator.options import error, info, warn
from stix2elevator.utils import map_1x_type_to_20


def record_ids(stix_id, new_id):
    if stix_id in _IDS_TO_NEW_IDS:
        info("%s is already associated other ids: %s", 703, str(stix_id), tuple(_IDS_TO_NEW_IDS[stix_id]))
    if new_id is None:
        error("Could not associate %s with None", 611, stix_id)
        return
    add_id_value(stix_id, new_id)


_SDO_ID_WITH_NO_1X_OBJECT = []


def clear_ids_with_no_1x_object():
    global _SDO_ID_WITH_NO_1X_OBJECT
    _SDO_ID_WITH_NO_1X_OBJECT = []


def exists_ids_with_no_1x_object(sdo_id):
    return sdo_id in _SDO_ID_WITH_NO_1X_OBJECT


def add_ids_with_no_1x_object(sdo_id):
    if not exists_ids_with_no_1x_object(sdo_id):
        _SDO_ID_WITH_NO_1X_OBJECT.append(sdo_id)


# arguments:
#   stix20SOName - the name of the type of object in 2.0
#   stix12ID - the ID on the STIX 1.x object.  In STIX 1.x, embedded objects might not have an ID.  Additionally
#               some objects in STIX 1.x didn't have IDs, but the corresponding object in STIX 2.0 does
#   id_used - sometimes (with TTPs and ETs), more than one object in 2.0 is created from a 1.x object - this flag
#               indicates that the 1.x's ID has been used for another 2.0 object, so a new one must be created
#
# algorithm:
#   if a stix12ID is given, and it hasn't been used already, then
#       split the stix12ID into its type and UUID parts.
#       if the stix20SOName has been given, create the new id from it and the UUID
#       otherwise, unless the stix12ID's type is ttp or et (which don't exist in 2.0) use the mapped 1.x type
#
#   if a stix12ID isn't given or it has been used already (STIX 1.x TTPs, etc can generate multiple STIX 2.0 objects)
#       generated a new UUID
#       create the new id using stix20SOName and the new UUID


def generate_stix2x_id(stix2x_so_name, stix12_id=None, id_used=False):
    if not stix12_id or id_used:
        new_id = stix2x_so_name + "--" + str(uuid.uuid4())
        add_ids_with_no_1x_object(new_id)
        return new_id
    else:
        # this works for all versions of UUID
        result = re.search('^(.+)-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})',
                           stix12_id)
        if result:
            current_uuid = result.group(2)
            if stix2x_so_name is None:
                stx1x_type = result.group(1).split(":")
                if stx1x_type[1].lower() == "ttp" or stx1x_type[1].lower() == "et":
                    error("Unable to determine the STIX 2.x type for %s", 604, stix12_id)
                    return None
                else:
                    return map_1x_type_to_20(stx1x_type[1]) + "--" + current_uuid
            else:
                return stix2x_so_name + "--" + current_uuid
        else:
            if stix2x_so_name:
                warn("Malformed id %s. Generated a new uuid", 605, stix12_id)
                return stix2x_so_name + "--" + str(uuid.uuid4())
            else:
                error("Unable to determine the STIX 2.x type for %s, which is malformed", 629, stix12_id)
                return None


_SCO_CLASSES = {}


def _choose_one_hash(hash_dict):
    if "MD5" in hash_dict:
        return {"MD5": hash_dict["MD5"]}
    elif "SHA-1" in hash_dict:
        return {"SHA-1": hash_dict["SHA-1"]}
    elif "SHA-256" in hash_dict:
        return {"SHA-256": hash_dict["SHA-256"]}
    elif "SHA-512" in hash_dict:
        return {"SHA-512": hash_dict["SHA-512"]}
    else:
        k = next(iter(hash_dict), None)
        if k is not None:
            return {k: hash_dict[k]}


def generate_sco_id(type, instance):
    required_prefix = type + "--"
    if not _SCO_CLASSES:
        # compute it once
        module = importlib.import_module("stix2.v21")
        for k, c in inspect.getmembers(module, inspect.isclass):
            if hasattr(c, "_properties") and "type" in c._properties:
                _SCO_CLASSES[c._properties["type"]._fixed_value] = c
    if type in _SCO_CLASSES:
        klass = _SCO_CLASSES[type]
        if klass and hasattr(klass, "_id_contributing_properties") and klass._id_contributing_properties:
            contributing_properties = klass._id_contributing_properties
            # streamlined_obj_vals = []
            streamlined_object = {}
            possible_hash = None
            if "hashes" in instance and "hashes" in contributing_properties:
                possible_hash = _choose_one_hash(instance["hashes"])
            if possible_hash:
                # streamlined_obj_vals.append(possible_hash)
                streamlined_object["hashes"] = possible_hash
            for key in contributing_properties:
                if key != "hashes" and key in instance:
                    # We don't need to handle the isinstance(...) cases here
                    # because the elevator uses Python default containers
                    # to represent its content.
                    # streamlined_obj_vals.append(instance[key])
                    streamlined_object[key] = instance[key]

            # if streamlined_obj_vals:
            if streamlined_object:
                # data = canonicalize(streamlined_obj_vals, utf8=False)
                data = canonicalize(streamlined_object, utf8=False)

                # try/except here to enable python 2 compatibility
                try:
                    return required_prefix + str(uuid.uuid5(SCO_DET_ID_NAMESPACE, data))
                except UnicodeDecodeError:
                    return required_prefix + str(uuid.uuid5(SCO_DET_ID_NAMESPACE, data.encode("utf-8")))

    return required_prefix + str(uuid.uuid4())


_IDS_TO_NEW_IDS = {}


def exists_id_key(key):
    return key in _IDS_TO_NEW_IDS


def get_id_value(key):
    if exists_id_key(key):
        return _IDS_TO_NEW_IDS[key]
    else:
        return []


def get_id_values():
    return _IDS_TO_NEW_IDS.values()


def add_id_value(key, value):
    if not value:
        warn("No object mapped to %s", 610, key)
    if exists_id_key(key):
        _IDS_TO_NEW_IDS[key].append(value)
    else:
        _IDS_TO_NEW_IDS[key] = [value]


def clear_id_mapping():
    global _IDS_TO_NEW_IDS
    _IDS_TO_NEW_IDS = {}


_IDS_TO_CYBER_OBSERVABLES = {}


def clear_object_id_mapping():
    global _IDS_TO_CYBER_OBSERVABLES
    _IDS_TO_CYBER_OBSERVABLES = {}


def exists_object_id_key(key):
    return key in _IDS_TO_CYBER_OBSERVABLES


def get_object_id_value(key):
    if exists_object_id_key(key):
        return _IDS_TO_CYBER_OBSERVABLES[key]
    else:
        return []


def get_object_id_values():
    return _IDS_TO_CYBER_OBSERVABLES.values()


def add_object_id_value(key, value):
    if exists_object_id_key(key):
        warn("This observable %s already is associated with cyber observables", 610, key)
    else:
        _IDS_TO_CYBER_OBSERVABLES[key] = value
    if not value:
        warn("Trying to associate %s with None", 610, key)


_ID_OF_OBSERVABLES_IN_CHARACTERIZATIONS = []


def clear_id_of_obs_in_characterizations():
    global _ID_OF_OBSERVABLES_IN_CHARACTERIZATIONS
    _ID_OF_OBSERVABLES_IN_CHARACTERIZATIONS = []


def exists_id_of_obs_in_characterizations(id):
    return id in _ID_OF_OBSERVABLES_IN_CHARACTERIZATIONS


def add_id_of_obs_in_characterizations(id):
    global _ID_OF_OBSERVABLES_IN_CHARACTERIZATIONS
    if not exists_id_of_obs_in_characterizations(id):
        _ID_OF_OBSERVABLES_IN_CHARACTERIZATIONS.append(id)


def fix_ids_in_characterizations():
    global _ID_OF_OBSERVABLES_IN_CHARACTERIZATIONS
    remaining_ids = []
    for id in _ID_OF_OBSERVABLES_IN_CHARACTERIZATIONS:
        if exists_id_key(id):
            remaining_ids.extend(get_id_value(id))
        else:
            remaining_ids.append(id)
    _ID_OF_OBSERVABLES_IN_CHARACTERIZATIONS = remaining_ids


def get_uuid_from_id(id, separator="--"):
    type_and_uuid = id.split(separator)
    return type_and_uuid[1]


def get_type_from_id(id, separator="--"):
    type_and_uuid = id.split(separator)
    return type_and_uuid[0]


def is_stix1x_id(id):
    return id and id.find("--") == -1 and id.find("-") != -1


def property_contains_stix1x_id(obj, property):
    if property in obj:
        value = obj[property]
        return isinstance(value, str) and is_stix1x_id(value)
