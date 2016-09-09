# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from cybox.core import Observable
from cybox.objects.address_object import Address
from cybox.objects.uri_object import URI
from cybox.objects.email_message_object import EmailMessage
from cybox.objects.file_object import File
from cybox.objects.win_registry_key_object import WinRegistryKey

from utils import info, warn, error

OBSERVABLE_TO_PATTERN_MAPPING = {}

def need_not(condition):
    return condition == "DoesNotContain"

def convert_condition(condition):
    if condition == "Equals":
        return "EQ"
    elif condition == "DoesNotEqual":
        return "NEQ"
    elif condition == "Contains" or condition == "DoesNotContain":
        return "CONTAINS"
    # StartsWith
    # EndsWith
    elif condition == "GreaterThan":
        return "GT"
    elif condition == "GreaterThanOrEqual":
        return "GE"
    elif condition == "LessThan":
        return "LT"
    elif condition == "LessThanOrEqual":
        return "LE"
    # DoesNotContain
    # StartsWith
    # EndsWith
    # InclusiveBetween
    # ExclusiveBetween
    # FitsPattern
    # BitwiseAnd
    # BitwiseOr
    elif condition is None:
        warn("No condition given - assume EQ")
        return "EQ"

def create_term_with_regex(lhs, condition, rhs):
    if condition == "StartsWith":
        return lhs + " MATCHES " + " /^" + rhs + "/"
    elif condition == "EndsWith":
        return lhs + " MATCHES " + " /" + rhs + "$/"

def create_term(lhs, condition, rhs):
    if condition == "StartsWith" or condition == "EndsWith":
        return create_term_with_regex(lhs, condition, rhs)
    elif condition is None:
        warn("No condition given - assume EQ")
        return lhs + " EQ '" + str(rhs) + "'"
    else:
        try:
            if need_not(condition):
                return "NOT (" + lhs + " " + convert_condition(condition) + " '" + str(rhs) + "')"
            else:
                return lhs + " " + convert_condition(condition) + " '" + str(rhs) + "'"
        except TypeError:
            pass

def convert_address_to_pattern(add):
    if add.category == add.CAT_IPV4:
        return create_term("ipv4addr-object:value",  add.address_value.condition, add.address_value.value)

def convert_uri_to_pattern(uri):
    return create_term("url-object:value", uri.value.condition, uri.value.value)

def convert_email_message_to_pattern(mess):
    first_one = True
    expression = ""
    if mess.header is not None:
        header = mess.header
        if header.to is not None:
            # is to a list???
            expression += (" AND " if not first_one else "") + \
                          create_term("email-message-object:header:to",
                                      header.to.condition,
                                      header.to.value)
            first_one = False
        elif header.subject is not None:
            expression += (" AND " if not first_one else "") + \
                         create_term("email-message-object:header:subject",
                                     header.subject.condition,
                                     header.subject.value)
            first_one = False
    if mess.attachments is not None:
        warn("email attachments not handled yet")
    return expression

def convert_file_to_pattern(file):
    first_one = True
    expression = ""
    if file.hashes is not None:
        first_hash = True
        hash_expression = ""
        for hash in file.hashes:
            hash_expression += (" OR " if not first_hash else "") + \
                              create_term("file-object:hashes" + ":" + str(hash.type_).lower(),
                                          hash.simple_hash_value.condition,
                                          hash.simple_hash_value.value)
            first_hash = False
        if not first_hash:
            expression += hash_expression
    if file.file_name is not None:
        name_expression = create_term("file-object:file_name",
                                      file.file_name.condition,
                                      file.file_name.value)
        expression += (" AND " if expression != "" else "") + name_expression
    return expression

def convert_registry_key_value_property(prop, property_name):
    property_expression = ""
    if hasattr(prop, "condition"):
        cond = prop.condition
    else:
        warn("No condition given - assume EQ")
        cond = None
    return create_term("win-registry-key-object:values[*]" + ":" + property_name, cond, prop)


def convert_registry_key_to_pattern(reg_key):
    first_one = True
    expression = ""
    if reg_key.key:
        key_value_term = ""
        if reg_key.hive:
            if reg_key.hive.condition is None:
                key_value_term += reg_key.hive.value + "\\"
            else:
                warn("Condition on a hive property not handled")
            key_value_term += reg_key.key.value
            expression += create_term("win-registry-key-object:key", reg_key.key.condition,  key_value_term)
    if reg_key.values:
        values_expression = ""
        data_expression = ""
        name_expression = ""
        type_expression = ""
        first_value = True
        for v in reg_key.values:
            value_expression = ""
            if hasattr(v, "data") and v.data:
                data_expression = convert_registry_key_value_property(v.data, "data")
            if data_expression:
                value_expression += (" AND " if value_expression != "" else "") + data_expression
            if hasattr(v, "name") and v.name:
                name_expression = convert_registry_key_value_property(v.name, "name")
            if name_expression:
                value_expression += (" AND " if value_expression != "" else "") + name_expression
            if hasattr(v, "datatype") and v.datatype:
                type_expression = convert_registry_key_value_property(v.datatype, "data_type")
            if type_expression:
                value_expression += (" AND " if value_expression != "" else "") + type_expression
            values_expression += (" OR " if value_expression else "") + value_expression
        expression += (" AND " if expression != "" else "") + values_expression
    return expression


####################################################################################################################

def convert_observable_composition_to_pattern(obs_comp, bundleInstance, observable_mapping):
    expression = []
    for obs in obs_comp.observables:
        expression.append(convert_observable_to_pattern(obs, bundleInstance, observable_mapping))
    operator_as_string = " " + obs_comp.operator + " "
    return "(" + operator_as_string.join(expression) + ")"


def convert_object_to_pattern(obj):
    prop = obj.properties
    if isinstance(prop, Address):
        return convert_address_to_pattern(prop)
    elif isinstance(prop, URI):
        return convert_uri_to_pattern(prop)
    elif isinstance(prop, EmailMessage):
        return convert_email_message_to_pattern(prop)
    elif isinstance(prop, File):
        return convert_file_to_pattern(prop)
    elif isinstance(prop, WinRegistryKey):
        return convert_registry_key_to_pattern(prop)
    else:
        warn(str(obj.properties) + " cannot be converted to a pattern, yet.  Using 'true'")
        return "true"


def match_1x_id_with_20_id(id_1x, id_20):
    return True


def find_observable_data(idref, obserableData):
    for obs in obserableData:
        if match_1x_id_with_20_id(idref, obs["id"]):
            return obs
    warn (idref + " cannot be resolved")
    return None

def convert_observable_to_pattern(obs, bundleInstance, observable_mapping):
    global OBSERVABLE_TO_PATTERN_MAPPING
    if obs.observable_composition is not None:
        return convert_observable_composition_to_pattern( obs.observable_composition, bundleInstance, observable_mapping)
    elif obs.object_ is not None:
        pattern = convert_object_to_pattern(obs.object_)
        OBSERVABLE_TO_PATTERN_MAPPING[obs.id_] = pattern
        return pattern
    elif obs.idref is not None:
        if obs.idref in OBSERVABLE_TO_PATTERN_MAPPING:
            return OBSERVABLE_TO_PATTERN_MAPPING[obs.idref]
        else:
            # resolve now, and remove from observed_data
            observableDataInstance = find_observable_data(obs.idref, bundleInstance["observed_data"])
            if observableDataInstance is not None:
                bundleInstance["observed_data"].remove(observableDataInstance)
                if obs.idref in observable_mapping:
                    return convert_observable_to_pattern(observable_mapping[obs.idref], bundleInstance, observable_mapping)
            return obs.idref


def interatively_resolve_placeholder_refs():
    global OBSERVABLE_TO_PATTERN_MAPPING
    done = True
    while done:
        # collect all of the fully resolved idrefs
        fully_resolved_idrefs = []
        for idref, expr in OBSERVABLE_TO_PATTERN_MAPPING.iteritems():
            if expr.find(idref) != -1:
                fully_resolved_idrefs.append(idref)
                done = False
        # replace only fully resolved idrefs
        for fr_idref in fully_resolved_idrefs:
            for idref, expr in OBSERVABLE_TO_PATTERN_MAPPING.iteritems():
                OBSERVABLE_TO_PATTERN_MAPPING[idref] = expr.replace(idref, OBSERVABLE_TO_PATTERN_MAPPING[fr_idref])


def fix_pattern(pattern):
    if not OBSERVABLE_TO_PATTERN_MAPPING == {}:
#        interatively_resolve_placeholder_refs()
        for idref in OBSERVABLE_TO_PATTERN_MAPPING.keys():
            # TODO: this can probably be done in place
            pattern = pattern.replace(idref, OBSERVABLE_TO_PATTERN_MAPPING[idref])
    return pattern