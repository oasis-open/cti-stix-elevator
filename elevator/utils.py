# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import sys
from datetime import *

import six


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
    if entity and hasattr(entity, "timestamp"):
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


def convert_to_str(value):
    escaped = value.encode('unicode_escape')
    escaped_ascii = escaped.decode('ascii')

    if isinstance(escaped, str):
        return escaped
    else:
        return escaped_ascii


def map_1x_type_to_20(stix1x_type):
    # TODO: stub
    return stix1x_type


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

    for varname, varobj in iter(sorted(six.iteritems(obj))):
        path.append(varname)
        yield (path, varobj)

        if isinstance(varobj, dict):

            for item in iterpath(varobj, path):
                yield item

        elif isinstance(varobj, list):

            for item in varobj:
                index = "[{0}]".format(varobj.index(item))
                path.append(index)

                yield (path, item)

                if isinstance(item, dict):
                    for descendant in iterpath(item, path):
                        yield descendant

                path.pop()

        path.pop()


def set_value_path(obj, path, value):
    current = path[0]
    path = path[1:]

    if "[" in current and "]" in current:
        current = int(current.strip("[]"))
        current_obj = obj[current]
    else:
        current_obj = obj[current]

    if not path:
        obj[current] = value
        return

    set_value_path(current_obj, path, value)
