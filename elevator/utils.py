# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import sys
from datetime import *

def info(fmt, *args):
    msg = fmt % args
    sys.stdout.write("[INFO] %s\n" % msg)


def warn(fmt, *args):
    msg = fmt % args
    sys.stderr.write("[WARN] %s\n" % msg)


def error(fmt, *args):
    msg = fmt % args
    sys.stderr.write("[ERROR] %s\n" % msg)

def cannonicalize_label(t):
    # TODO: stub
    return t


def map_vocabs_to_label(t, vocab_map):
    try:
        return vocab_map[t]
    except KeyError:
        return cannonicalize_label(t)


def convert_controlled_vocabs_to_open_vocabs(new_obj, new_property_name, old_vocabs, vocab_mapping, only_one):
    new_obj[new_property_name] = []
    for t in old_vocabs:
        if new_obj[new_property_name] is None or not only_one:
            new_obj[new_property_name].append(map_vocabs_to_label(t.value, vocab_mapping))
        else:
            warn("Only one " + new_property_name + " allowed in STIX 2.0 - used first one")
    if not new_obj[new_property_name]:
        del new_obj[new_property_name]


def convert_timestamp(entity, parent_timestamp=None):
    if hasattr(entity, "timestamp"):
        if entity.timestamp is not None:
            return entity.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            warn("Timestamp not available, using current time")
            return str(datetime.now().isoformat()) + "Z"
    elif parent_timestamp is not None:
        info("Using enclosing object timestamp")
        return parent_timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        warn("Timestamp not available, using current time")
        return str(datetime.now().isoformat()) + "Z"
