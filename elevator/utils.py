
# built-in
import logging
from datetime import datetime
from numbers import Number

# external
import six

from elevator import options

log = logging.getLogger(__name__)


def info(fmt, ecode, *args):
    if options.msg_id_enabled(ecode):
        log.info(fmt, *args, extra={'ecode': ecode})


def warn(fmt, ecode, *args):
    if options.msg_id_enabled(ecode):
        log.warn(fmt, *args, extra={'ecode': ecode})


def error(fmt, ecode, *args):
    if options.msg_id_enabled(ecode):
        log.error(fmt, *args, extra={'ecode': ecode})


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
        warn("No STIX 1.x vocab value given for %s, using 'unknown'", 509, new_property_name)
    else:
        new_obj[new_property_name] = []
        for t in old_vocabs:
            if new_obj[new_property_name] is None or not only_one:
                if isinstance(t, (six.text_type, six.binary_type)):
                    new_obj[new_property_name].append(map_vocabs_to_label(t, vocab_mapping))
                else:
                    new_obj[new_property_name].append(map_vocabs_to_label(str(t.value), vocab_mapping))
            else:
                warn("Only one %s allowed in STIX 2.0 - used first one", 510, new_property_name)


def strftime_with_appropriate_fractional_seconds(timestamp, milliseconds_only):
    if milliseconds_only:
        return timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    else:
        return timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def convert_timestamp_string(timestamp, entity, parent_timestamp, milliseconds_only=False):

    if timestamp is not None:
        return strftime_with_appropriate_fractional_seconds(timestamp, milliseconds_only)
    elif parent_timestamp is not None:
        info("Using parent object timestamp on %s", 902, identifying_info(entity))
        return strftime_with_appropriate_fractional_seconds(parent_timestamp, milliseconds_only)
    else:
        warn("Timestamp not available for %s, using current time", 905, identifying_info(entity))
        return strftime_with_appropriate_fractional_seconds(datetime.now(), milliseconds_only)


def convert_timestamp(entity, parent_timestamp=None, milliseconds_only=False):
    if entity and hasattr(entity, "timestamp"):
        if entity.timestamp is not None:
            return strftime_with_appropriate_fractional_seconds(entity.timestamp, milliseconds_only)
    if parent_timestamp is not None:
        info("Using parent object timestamp on %s", 902, identifying_info(entity))
        # parent_timestamp might have already been converted to a string in a previous call
        if isinstance(parent_timestamp, str):
            return parent_timestamp
        else:
            return strftime_with_appropriate_fractional_seconds(parent_timestamp, milliseconds_only)
    warn("Timestamp not available for %s, using current time", 905, identifying_info(entity))
    return strftime_with_appropriate_fractional_seconds(datetime.now(), milliseconds_only)


def convert_to_str(value, encoding='utf-8'):
    if not value:
        return ""
    if isinstance(value, six.text_type):
        return value
    if isinstance(value, Number) or isinstance(value, list):
        value = str(value)

    escaped = value.encode(encoding)
    escaped_ascii = escaped.decode('ascii')

    if isinstance(escaped, str):
        return escaped
    else:
        return escaped_ascii


_TYPE_MAP_FROM_1_x_TO_2_0 = {"observable": "observed-data",
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
