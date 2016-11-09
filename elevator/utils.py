import sys
from datetime import *
from numbers import Number

import six


def info(fmt, *args):
    msg = fmt % args
    sys.stdout.write("[INFO] {message}\n".format(message=msg))


def warn(fmt, *args):
    msg = fmt % args
    sys.stderr.write("[WARN] {message}\n".format(message=msg))


def error(fmt, *args):
    msg = fmt % args
    sys.stderr.write("[ERROR] {message}\n".format(message=msg))


def identifying_info(stix1x_obj):
    if stix1x_obj:
        if hasattr(stix1x_obj, "id_") and stix1x_obj.id_:
            return convert_to_str(stix1x_obj.id_)
        elif hasattr(stix1x_obj, "title") and stix1x_obj.title:
            return "'" + convert_to_str(stix1x_obj.title) + "'"
        elif hasattr(stix1x_obj, "name") and stix1x_obj.name:
            return "'" + convert_to_str(stix1x_obj.name) + "'"
    return "- no identifying information"


def canonicalize_label(t):
    t = convert_to_str(t)
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
        warn("No STIX 1.x vocab value given for {prop}, using 'unknown'".format(prop=new_property_name))
    else:
        new_obj[new_property_name] = []
        for t in old_vocabs:
            if new_obj[new_property_name] is None or not only_one:
                new_obj[new_property_name].append(map_vocabs_to_label(t.value, vocab_mapping))
            else:
                warn("Only one {prop} allowed in STIX 2.0 - used first one".format(prop=new_property_name))



def convert_timestamp_string(timestamp, entity, parent_timestamp):
    if timestamp is not None:
        return timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    elif parent_timestamp is not None:
        info("Using enclosing object timestamp")
        return parent_timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        warn("Timestamp not available for " + identifying_info(entity)+ ", using current time")
        return str(datetime.now().isoformat()) + "Z"


def convert_timestamp(entity, parent_timestamp=None):
    if entity and hasattr(entity, "timestamp"):
        if entity.timestamp is not None:
            return entity.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        elif parent_timestamp is not None:
            info("Using enclosing object timestamp")
            return parent_timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    warn("Timestamp not available for " + identifying_info(entity)  + ", using current time")
    return str(datetime.now().isoformat()) + "Z"


def convert_to_str(value):
    if not value:
        return ""
    if isinstance(value, six.text_type):
        return value
    if isinstance(value, Number) or isinstance(value, list):
       value = str(value)
    escaped = value.encode('unicode_escape')
    escaped_ascii = escaped.decode('ascii')

    if isinstance(escaped, str):
        return escaped
    else:
        return escaped_ascii


_TYPE_MAP_FROM_1_x_TO_2_0 = { "observable": "observed-data",
                              "toolinformation": "tool"}

def map_1x_type_to_20(stix1x_type):
    if stix1x_type in _TYPE_MAP_FROM_1_x_TO_2_0:
        return _TYPE_MAP_FROM_1_x_TO_2_0[stix1x_type]
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


def operation_on_path(obj, path, value, op=1):
    """operations: (1 = set_value, 2 = delete_entry)"""
    current = path[0]
    path = path[1:]

    if "[" in current and "]" in current:
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
