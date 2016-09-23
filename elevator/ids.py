# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import uuid

from elevator.utils import *

IDS_TO_NEW_IDS = {}

SDO_WITH_NO_1X_OBJECT = []

def clear_id_mapping():
    IDS_TO_NEW_IDS = {}

def record_ids(id, new_id):
    if id in IDS_TO_NEW_IDS:
        info(str(id) + " is already associated with a new id " + str(IDS_TO_NEW_IDS[id]))
    # info("associating " + new_id + " with " + id)
    if new_id is None:
        error("Could not associate " + id + " with None")
    add_id_value(id, new_id)


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
