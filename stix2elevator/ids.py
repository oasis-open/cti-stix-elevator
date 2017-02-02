import uuid
import re
from six import text_type

from stix2elevator.utils import *

IDS_TO_NEW_IDS = {}

SDO_WITH_NO_1X_OBJECT = []


def clear_id_mapping():
    global IDS_TO_NEW_IDS
    IDS_TO_NEW_IDS = {}


def record_ids(stix_id, new_id):
    if stix_id in IDS_TO_NEW_IDS:
        info("%s is already associated other ids: %s", 703, text_type(stix_id), tuple(IDS_TO_NEW_IDS[stix_id]))
    # info("associating " + new_id + " with " + id)
    if new_id is None:
        error("Could not associate %s with None", 611, stix_id)
        return
    add_id_value(stix_id, new_id)

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


def generate_stix20_id(stix20_so_name, stix12_id=None, id_used=False):
    if not stix12_id or id_used:
        new_id = stix20_so_name + "--" + text_type(uuid.uuid4())
        SDO_WITH_NO_1X_OBJECT.append(new_id)
        return new_id
    else:
        result = re.search('^(.+)-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})',
                           stix12_id)
        if result:
            current_uuid = result.group(2)
            if stix20_so_name is None:
                stx1x_type = result.group(1).split(":")
                if stx1x_type[1].lower() == "ttp" or stx1x_type[1].lower() == "et":
                    error("Unable to determine the STIX 2.0 type for %s", 604, stix12_id)
                    return None
                else:
                    return map_1x_type_to_20(stx1x_type[1]) + "--" + current_uuid
            else:
                return stix20_so_name + "--" + current_uuid
        else:
            warn("Malformed id %s. Generated a new uuid", 605, stix12_id)
            return stix20_so_name + "--" + text_type(uuid.uuid4())


def exists_id_key(key):
    return key in IDS_TO_NEW_IDS


def get_id_value(key):
    if exists_id_key(key):
        return IDS_TO_NEW_IDS[key]
    else:
        return []


def get_id_values():
    return IDS_TO_NEW_IDS.values()


def add_id_value(key, value):
    if exists_id_key(key):
        IDS_TO_NEW_IDS[key].append(value)
    else:
        IDS_TO_NEW_IDS[key] = [value]
    if not value:
        warn("Trying to associate %s with None", 610, key)
