# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import uuid

from elevator.utils import *

IDS_TO_NEW_IDS = {}

SDO_WITH_NO_1X_OBJECT = []


def clear_id_mapping():
    global IDS_TO_NEW_IDS
    IDS_TO_NEW_IDS = {}


def record_ids(id, new_id):
    if id in IDS_TO_NEW_IDS:
        info(str(id) + " is already associated other ids: " + str(IDS_TO_NEW_IDS[id]))
    # info("associating " + new_id + " with " + id)
    if new_id is None:
        error("Could not associate " + id + " with None")
    add_id_value(id, new_id)

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
#   if a stix12ID isn't given or it has been used already
#       generated a new UUID
#       create the new id using stix20SOName and the new UUID


def generateSTIX20Id(stix20SOName, stix12ID=None, id_used=False):
    if not stix12ID or id_used:
        new_id = stix20SOName + "--" + str(uuid.uuid4())
        SDO_WITH_NO_1X_OBJECT.append(new_id)
        return new_id
    else:
        namespace_type_uuid = stix12ID.split("-", 1)
        if stix20SOName is None:
            stx1x_type = namespace_type_uuid[0].split(":", 1)
            if stx1x_type[1].lower() == "ttp" or stx1x_type[1].lower() == "et":
                error("Unable to determine the STIX 2.0 type for " + stix12ID)
                return None
            else:
                return map_1x_type_to_20(stx1x_type[1]) + "--" + namespace_type_uuid[1]
        else:
            return stix20SOName + "--" + namespace_type_uuid[1]


def exists_id_key(key):
    return key in IDS_TO_NEW_IDS


def get_id_value(key):
    return IDS_TO_NEW_IDS[key]


def get_id_values():
    return IDS_TO_NEW_IDS.values()


def add_id_value(key, value):
    if exists_id_key(key):
        IDS_TO_NEW_IDS[key].append(value)
    else:
        IDS_TO_NEW_IDS[key] = [value]
    if not value:
        warn("trying to associate " + key + " will None")
