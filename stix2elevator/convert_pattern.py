from cybox.objects.address_object import Address
from cybox.objects.uri_object import URI
from cybox.objects.email_message_object import EmailMessage
from cybox.objects.file_object import File
from cybox.objects.win_registry_key_object import WinRegistryKey
from cybox.objects.win_process_object import WinProcess
from cybox.objects.win_service_object import WinService
from cybox.objects.process_object import Process
from cybox.objects.domain_name_object import DomainName
from cybox.objects.mutex_object import Mutex
from cybox.objects.network_connection_object import NetworkConnection
from cybox.objects.win_executable_file_object import WinExecutableFile
from cybox.objects.archive_file_object import ArchiveFile

from stix2elevator.vocab_mappings import *
from stix2elevator.ids import *

import re
from six import text_type

PATTERN_CACHE = {}

KEEP_OBSERVABLE_DATA_USED_IN_PATTERNS = False

KEEP_INDICATORS_USED_IN_COMPOSITE_INDICATOR_EXPRESSION = True


def get_root_from_object_path(lhs):
    path_as_parts = lhs.split(":")
    return path_as_parts[0]


class ComparisonExpression(object):
    def __init__(self, operator, lhs, rhs, negated=False):
        self.operator = operator
        self.lhs = lhs
        self.rhs = rhs
        self.negated = negated
        self.root_type = get_root_from_object_path(lhs)

    def to_string(self):
        return self.lhs + (" NOT" if self.negated else "") + " " + self.operator + " '" + text_type(self.rhs) + "'"

    def contains_placeholder(self):
        return False

    def replace_placeholder_with_idref_pattern(self, idref):
        return False, self

    def partition_according_to_object_path(self):
        return self

    def contains_unconverted_term(self):
        return False


class BooleanExpression(object):
    def __init__(self, operator, operands, negated=False):
        self.operator = operator
        self.operands = operands
        self.negated = negated

    def add_operand(self, operand):
        self.operands.append(operand)

    def to_string(self):
        sub_exprs = []
        for o in self.operands:
            sub_exprs.append(o.to_string())
        return "(" + (" " + self.operator + " ").join(sub_exprs) + ")"

    def contains_placeholder(self):
        for args in self.operands:
            if args.contains_placeholder():
                return True
        return False

    def replace_placeholder_with_idref_pattern(self, idref):
        new_operands = []
        change_made = False
        for args in self.operands:
            change_made_this_time, new_operand = args.replace_placeholder_with_idref_pattern(idref)
            change_made = change_made or change_made_this_time
            new_operands.append(new_operand)
        self.operands = new_operands
        return change_made, self

    def partition_according_to_object_path(self):
        subexpressions = []
        results = []
        for term in self.operands:
            term_was_appended = False
            for sub in subexpressions:
                if not hasattr(term, "root_type") and not hasattr(sub[0], "root_type"):
                    sub.append(term)
                    term_was_appended = True
                    break
                elif hasattr(term, "root_type") and hasattr(sub[0], "root_type") and term.root_type == sub[0].root_type:
                    sub.append(term)
                    term_was_appended = True
                    break
            if not term_was_appended:
                subexpressions.append([term])
        for x in subexpressions:
            if len(x) == 1:
                results.append(x[0])
            else:
                results.append(create_boolean_expression(self.operator, x))
        return ObservableExpression(self.operator, results)

    def contains_unconverted_term(self):
        for args in self.operands:
            if args.contains_unconverted_term():
                return True
        return False


class IdrefPlaceHolder(object):
    def __init__(self, idref):
        self.idref = idref

    def to_string(self):
        return "PLACEHOLDER:" + self.idref

    def contains_placeholder(self):
        return True

    def replace_placeholder_with_idref_pattern(self, idref):
        if idref == self.idref:
            return True, PATTERN_CACHE[idref]
        else:
            return False, self

    def partition_according_to_object_path(self):
        error("Placeholder %s should be resolved", 203, self.idref)
        return self

    def contains_unconverted_term(self):
        return False


class UnconvertedTerm(object):
    def __init__(self, term_info):
        self.term_info = term_info

    def to_string(self):
        return "unconverted_term:" + text_type(self.term_info)

    def contains_placeholder(self):
        return False

    def replace_placeholder_with_idref_pattern(self, idref):
        return False, self

    def partition_according_to_object_path(self):
        return self

    def contains_unconverted_term(self):
        return True


class ObservableExpression(object):
    def __init__(self, operator, operands):
        self.operator = operator
        self.operands = operands

    def to_string(self):
        sub_exprs = []
        if len(self.operands) == 1:
            return "[" + self.operands[0].to_string() + "]"
        for o in self.operands:
            sub_exprs.append("[" + o.to_string() + "]")
        return (" " + self.operator + " ").join(sub_exprs)

    def contains_placeholder(self):
        for args in self.operands:
            if args.contains_placeholder():
                error("Observable Expressions should not contain placeholders", 202)

    def contains_unconverted_term(self):
        for args in self.operands:
            if args.contains_unconverted_term():
                return True
        return False


def create_boolean_expression(operator, operands, negated=False):
    if len(operands) == 1:
        return operands[0]
    exp = BooleanExpression(operator, [], negated)
    for arg in operands:
        if not isinstance(arg, IdrefPlaceHolder) and not isinstance(arg, UnconvertedTerm) and hasattr(arg, "root_type"):
            if not hasattr(exp, "root_type"):
                exp.root_type = arg.root_type
            elif exp.root_type and (exp.root_type != arg.root_type):
                exp.root_type = None
        exp.add_operand(arg)
    return exp


###################


def clear_pattern_mapping():
    global PATTERN_CACHE
    PATTERN_CACHE = {}


def add_to_pattern_cache(key, pattern):
    global PATTERN_CACHE
    if pattern:
        PATTERN_CACHE[key] = pattern

# simulate dynamic variable environment


_DYNAMIC_SCOPING_ENV = {}


def intialize_dynamic_variable(var):
    global _DYNAMIC_SCOPING_ENV
    if var in _DYNAMIC_SCOPING_ENV:
        raise Exception
    else:
        _DYNAMIC_SCOPING_ENV[var] = []


def set_dynamic_variable(var, value):
    global _DYNAMIC_SCOPING_ENV
    if var not in _DYNAMIC_SCOPING_ENV:
        intialize_dynamic_variable(var)
    _DYNAMIC_SCOPING_ENV[var].append(value)


def get_dynamic_variable(var):
    if var not in _DYNAMIC_SCOPING_ENV:
        raise Exception
    else:
        return _DYNAMIC_SCOPING_ENV[var][-1]


def pop_dynamic_variable(var):
    if var not in _DYNAMIC_SCOPING_ENV or not _DYNAMIC_SCOPING_ENV[var]:
        raise Exception
    else:
        _DYNAMIC_SCOPING_ENV[var].pop


_CLASS_NAME_MAPPING = {"File": "file",
                       "URI": "uri",
                       "EmailMessage": "email-message",
                       "WinRegistryKey": "win-registry-key",
                       "Process": "process",
                       "DomainName": "domain_name",
                       "Mutex": "mutex",
                       "WinExecutableFile": "file:extended_properties.windows_pebinary_ext",
                       "ArchiveFile": "file:extended_properties.archive_ext"}

_ADDRESS_NAME_MAPPING = {Address.CAT_IPV4: "ipv4-addr",
                         Address.CAT_IPV6: "ipv6-addr",
                         Address.CAT_MAC: "mac-addr",
                         Address.CAT_EMAIL: "email-addr"}


# address, network_connection


def convert_cybox_class_name_to_object_path_root_name(instance):
    class_name = instance.__class__.__name__
    if class_name in _CLASS_NAME_MAPPING:
        return _CLASS_NAME_MAPPING[class_name]
    elif class_name == "Address" and instance.category in _ADDRESS_NAME_MAPPING:
        return _ADDRESS_NAME_MAPPING[class_name]
    else:
        error("Cannot convert CybOX 2.x class name %s to an object_path_root_name", 813, class_name)
        return None


def need_not(condition):
    return condition == "DoesNotContain"


def add_parens_if_needed(expr):
    if expr.find("AND") != -1 or expr.find("OR") != -1:
        return "(" + expr + ")"
    else:
        return expr


def convert_condition(condition):
    if condition == "Equals":
        return "="
    elif condition == "DoesNotEqual":
        return "!="
    elif condition == "Contains":
        return "="
    elif condition == "DoesNotContain":
        return "!="
    elif condition == "GreaterThan":
        return ">"
    elif condition == "GreaterThanOrEqual":
        return ">="
    elif condition == "LessThan":
        return "<"
    elif condition == "LessThanOrEqual":
        return "<="
    # StartsWith - handled in create_term_with_regex
    # EndsWith  - handled in create_term_with_regex
    # InclusiveBetween - handled in create_term_with_range
    # ExclusiveBetween - handled in create_term_with_range
    # FitsPattern
    # BitwiseAnd
    # BitwiseOr
    elif condition is None:
        warn("No condition given for %s - assume '='", 714,  identifying_info(get_dynamic_variable("current_observable")))
        return "="


def create_term_with_regex(lhs, condition, rhs, negated):
    if condition == "StartsWith":
        pattern = "^" + rhs
    elif condition == "EndsWith":
        pattern = rhs + "$"
    elif condition == "Contains" or condition == "DoesNotContain":
        pattern = rhs
    # return lhs + (" NOT MATCHES " if negated else " MATCHES ") + pattern
    return ComparisonExpression("MATCHES", lhs, pattern, negated)


def create_term_with_range(lhs, condition, rhs, negated=False):
    # TODO: handle negated
    if not isinstance(rhs, list) or len(rhs) != 2:
        error("%s was used, but two values were not provided.", 609, condition)
        return "'range term underspecified'"
    else:
        if condition == "InclusiveBetween":
            # return "(" + lhs + " GE " + text_type(rhs[0]) + " AND " + lhs + " LE " + text_type(rhs[1]) + ")"
            lower_bound = ComparisonExpression(">=", lhs, text_type(rhs[0]))
            upper_bound = ComparisonExpression("<=", lhs, text_type(rhs[1]))

        else:  # "ExclusiveBetween"
            # return "(" + lhs + " GT " + text_type(rhs[0]) + " AND " + lhs + " LT " + text_type(rhs[1]) + ")"
            lower_bound = ComparisonExpression(">", lhs, text_type(rhs[0]))
            upper_bound = ComparisonExpression("<", lhs, text_type(rhs[1]))
        return create_boolean_expression("AND", [lower_bound, upper_bound], negated)


def multi_valued_property(object_path):
    return object_path and object_path.find("*") != -1


def negate_if_needed(condition, negated):
    if negated:
        return "NOT " + condition
    else:
        return condition


def create_term(lhs, condition, rhs, negated=False):
    if condition == "StartsWith" or condition == "EndsWith":
        return create_term_with_regex(lhs, condition, rhs, negated)
    elif condition == "InclusiveBetween" or condition == "ExclusiveBetween":
        return create_term_with_range(lhs, condition, rhs, negated)
    else:
        if condition == "Contains" and not multi_valued_property(lhs):
            warn("Used MATCHES operator for %s", 715, condition)
            return (create_term_with_regex(lhs, condition, rhs, negated))
        elif condition == "DoesNotContain":
            warn("Used MATCHES operator for %s", 715, condition)
            return (create_term_with_regex(lhs, condition, rhs, not negated))
        # return lhs + " " + negate_if_needed(convert_condition(condition), negated) + " '" + convert_to_text_type(rhs) + "'"
        return ComparisonExpression(convert_condition(condition), lhs, text_type(rhs), negated)


def add_comparison_expression(prop, object_path):
    if prop is not None:
        if hasattr(prop, "condition"):
            cond = prop.condition
        else:
            warn("No condition given - assume '='", 714)
            cond = None
        return create_term(object_path, cond, prop.value)
    return ""


def convert_custom_properties(cps, object_type_name):
    expressions = []
    for cp in cps.property_:
        if not re.match("[a-z0-9_]+", cp.name):
            warn("The custom property name %s does not adhere to the specification rules", 617, cp.name)
        expressions.append(create_term(object_type_name + ":x_" + cp.name, cp.condition, cp.value))
    return create_boolean_expression("AND", expressions)


def convert_address_to_pattern(add):
    cond = add.address_value.condition
    if add.category == add.CAT_IPV4:
        return create_term("ipv4-addr:value", cond, add.address_value.value)
    elif add.category == add.CAT_IPV6:
        return create_term("ipv6-addr:value", cond, add.address_value.value)
    elif add.category == add.CAT_MAC:
        return create_term("mac-addr:value", cond, add.address_value.value)
    elif add.category == add.CAT_EMAIL:
        return create_term("email-addr:value", cond, add.address_value.value)
    else:
        warn("The address type %s is not part of Cybox 3.0", 421, add.category)


def convert_uri_to_pattern(uri):
    return create_term("url:value", uri.value.condition, uri.value.value)


# NOTICE:  The format of these PROPERTIES is different than the others in this file!!!!!!
_EMAIL_HEADER_PROPERTIES = [["email-message:subject", ["subject"]],
                            ["email-message:from_ref", ["from_", "address_value"]],
                            ["email-message:sender_ref", ["sender", "address_value"]],
                            ["email-message:date", ["date"]],
                            ["email-message:content_type", ["content_type"]],
                            ["email-message:to_refs[*]", ["to*", "address_value"]],
                            ["email-message:cc_refs[*]", ["cc*", "address_value"]],
                            ["email-message:bcc_refs[*]", ["bcc*", "address_value"]]]


_EMAIL_ADDITIONAL_HEADERS_PROPERTIES = \
    [["email-message:additional_header_fields:Reply-To", ["reply-to*", "address_value"]],
     ["email-message:additional_header_fields:Message_ID", ["message_id"]],
     ["email-message:additional_header_fields:In_Reply_To", ["in_reply_to"]],
     ["email-message:additional_header_fields:Errors_To", ["errors_to"]],
     ["email-message:additional_header_fields:MIME_Version", ["mime_version"]],
     ["email-message:additional_header_fields:Precedence", ["precedence"]],
     ["email-message:additional_header_fields:User_Agent", ["user_agent"]],
     ["email-message:additional_header_fields:Boundary", ["boundary"]],
     ["email-message:additional_header_fields:X_Originating_IP", ["x_originating_ip", "address_value"]],
     ["email-message:additional_header_fields:X_Priority", ["x_priority"]],
     ["email-message:additional_header_fields:X_Mailer", ["x_mailer"]]]


def cannonicalize_prop_name(name):
    if name.find("*") == -1:
        return name
    else:
        return name[:-1]


def create_terms_from_prop_list(prop_list, obj, object_path):
    if len(prop_list) == 1:
        prop_1x = prop_list[0]
        if hasattr(obj, cannonicalize_prop_name(prop_1x)):
            if multi_valued_property(prop_1x):
                prop_exprs = []
                for c in getattr(obj, cannonicalize_prop_name(prop_1x)):
                    prop_exprs.append(add_comparison_expression(c, object_path))
                # return " OR ".join(prop_exprs)
                if prop_exprs:
                    return create_boolean_expression("OR", prop_exprs)
            else:
                return add_comparison_expression(getattr(obj, cannonicalize_prop_name(prop_1x)), object_path)
    else:
        prop_1x, rest_of_prop_list = prop_list[0], prop_list[1:]
        if hasattr(obj, cannonicalize_prop_name(prop_1x)):
            if multi_valued_property(prop_1x):
                prop_exprs = []
                values = getattr(obj, cannonicalize_prop_name(prop_1x))
                if values:
                    for c in values:
                        prop_exprs.append(create_terms_from_prop_list(rest_of_prop_list, c, object_path))
                # return " OR ".join(prop_exprs)
                if prop_exprs:
                    return create_boolean_expression("OR", prop_exprs)
            else:
                return create_terms_from_prop_list(rest_of_prop_list,
                                                   getattr(obj, cannonicalize_prop_name(prop_1x)),
                                                   object_path)


def convert_email_header_to_pattern(head, properties):
    header_expressions = []
    for prop_spec in properties:
        object_path = prop_spec[0]
        prop_1x_list = prop_spec[1]
        if hasattr(head, cannonicalize_prop_name(prop_1x_list[0])):
            term = create_terms_from_prop_list(prop_1x_list, head, object_path)
            if term:
                header_expressions.append(term)
    if head.received_lines:
        warn("Email received lines not handled yet", 806)
    if header_expressions:
        return create_boolean_expression("AND", header_expressions)


def convert_email_message_to_pattern(mess):
    expressions = []
    if mess.header is not None:
        expressions.append(convert_email_header_to_pattern(mess.header, _EMAIL_HEADER_PROPERTIES))
        add_headers = convert_email_header_to_pattern(mess.header, _EMAIL_ADDITIONAL_HEADERS_PROPERTIES)
        if add_headers:
            expressions.append(add_headers)
    if mess.attachments is not None:
        warn("Email attachments not handled yet", 806)
    if mess.raw_body is not None:
        warn("Email raw body not handled yet", 806)
    if mess.links is not None:
        warn("Email links not handled yet", 806)
    if expressions:
        return create_boolean_expression("AND", expressions)


_PE_FILE_HEADER_PROPERTIES = \
    [["machine", "file:extended_properties.windows_pebinary_ext.file_header:machine"],
     ["time_date_stamp", "file:extended_properties.windows_pebinary_ext.file_header.time_date_stamp"],
     ["number_of_sections", "file:extended_properties.windows_pebinary_ext.file_header.number_of_sections"],
     ["pointer_to_symbol_table", "file:extended_properties.windows_pebinary_ext.file_header.pointer_to_symbol_table"],
     ["number_of_symbols", "file:extended_properties.windows_pebinary_ext.file_header.number_of_symbols"],
     ["size_of_optional_header", "file:extended_properties.windows_pebinary_ext.file_header.size_of_optional_header"],
     ["characteristics", "file:extended_properties.windows_pebinary_ext.file_header.characteristics"]]


_PE_SECTION_HEADER_PROPERTIES = [["name", "file:extended_properties.windows_pebinary_ext.section[*].name"],
                                 ["virtual_size", "file:extended_properties.windows_pebinary_ext.section[*].size"]]


_ARCHIVE_FILE_PROPERTIES = [["comment", "file:extended_properties.archive_ext.comment"],
                            ["version", "file:extended_properties.archive_ext.version"]]


def convert_windows_executable_file_to_pattern(file):
    expressions = []
    if file.headers:
        file_header = file.headers.file_header
        if file_header:
            file_header_expressions = []
            for prop_spec in _PE_FILE_HEADER_PROPERTIES:
                prop_1x = prop_spec[0]
                object_path = prop_spec[1]
                if hasattr(file_header, prop_1x) and getattr(file_header, prop_1x):
                    file_header_expressions.append(add_comparison_expression(getattr(file_header, prop_1x),
                                                                             object_path))
            if file_header.hashes is not None:
                hash_expression = convert_hashes_to_pattern(file_header.hashes)
                if hash_expression:
                    file_header_expressions.append(hash_expression)
            if file_header_expressions:
                expressions.append(create_boolean_expression("AND", file_header_expressions))
        if file.headers.optional_header:
            warn("file:extended_properties:windows_pebinary_ext:optional_header is not implemented yet", 807)

    if file.type_:
        expressions.append(create_term("file:extended_properties.windows_pebinary_ext.pe_type",
                                       file.type_.condition,
                                       map_vocabs_to_label(file.type_.value, WINDOWS_PEBINARY)))
    sections = file.sections
    if sections:
        sections_expressions = []
        # should order matter in patterns???
        for s in sections:
            section_expressions = []
            if s.section_header:
                for prop_spec in _PE_SECTION_HEADER_PROPERTIES:
                    prop_1x = prop_spec[0]
                    object_path = prop_spec[1]
                    if hasattr(s.section_header, prop_1x) and getattr(s.section_header, prop_1x):
                        section_expressions.append(add_comparison_expression(getattr(s.section_header, prop_1x),
                                                                             object_path))
            if s.entropy:
                section_expressions.append(create_term("file:extended_properties.windows_pebinary_ext.section[*].entropy",
                                                       s.entropy.condition,
                                                       s.entropy.value))
            if s.data_hashes:
                section_expressions.append(convert_hashes_to_pattern(s.data_hashes))
            if s.header_hashes:
                section_expressions.append(convert_hashes_to_pattern(s.header_hashes))
            if section_expressions:
                sections_expressions.append(create_boolean_expression("AND", section_expressions))
        if sections_expressions:
            expressions.append(create_boolean_expression("AND", sections_expressions))
    if file.exports:
        warn("The exports property of WinExecutableFileObj is not part of Cybox 3.0", 418)
        expressions.append(UnconvertedTerm("WinExecutableFileObj.exports"))
    if file.imports:
        warn("The imports property of WinExecutableFileObj is not part of Cybox 3.0", 419)
        expressions.append(UnconvertedTerm("WinExecutableFileObj.imports"))
    if expressions:
        return create_boolean_expression("AND", expressions)


def convert_archive_file_to_pattern(file):
    and_expressions = []
    for prop_spec in _ARCHIVE_FILE_PROPERTIES:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(file, prop_1x):
            and_expressions.append(add_comparison_expression(getattr(file, prop_1x), object_path))
    if and_expressions:
        return create_boolean_expression("AND", and_expressions)


def convert_hashes_to_pattern(hashes):
    hash_expressions = []
    for h in hashes:
        if getattr(h, "simple_hash_value"):
            hash_value = h.simple_hash_value
        else:
            hash_value = h.fuzzy_hash_value
        hash_expressions.append(create_term("file:hashes" + ":" + text_type(h.type_).lower(),
                                            hash_value.condition,
                                            hash_value.value))
    if hash_expressions:
        return create_boolean_expression("OR", hash_expressions)


def convert_file_name_and_path_to_pattern(file):
    file_name_path_expressions = []
    if file.file_name:
        file_name_path_expressions.append(create_term("file:file_name", file.file_name.condition, file.file_name.value))
    if file.file_path:
        if file.device_path:
            file_name_path_expressions.append(create_term("file:parent_directory_ref.name",
                                                          file.file_path.condition,
                                                          file.device_path.value + file.file_path.value))
    if file.full_path:
        warn("1.x full file paths are not processed, yet", 802)
    if file_name_path_expressions:
        return create_boolean_expression("AND", file_name_path_expressions)


_FILE_PROPERTIES = [["size_in_bytes", "file:size"],
                    ["magic_number", "file:magic_number_hex"],
                    ["created_time", "file:created"],
                    ["modified_time", "file:modified"],
                    ["accessed_time", "file:accessed"],
                    ["encyption_algorithm", "file:encyption_algorithm"],
                    ["decryption_key", "file:decryption_key"]]


def convert_file_to_pattern(file):
    expressions = []
    if file.hashes is not None:
        hash_expression = convert_hashes_to_pattern(file.hashes)
        if hash_expression:
            expressions.append(hash_expression)
    file_name_and_path_expression = convert_file_name_and_path_to_pattern(file)
    if file_name_and_path_expression:
        expressions.append(file_name_and_path_expression)
    properties_expressions = []
    for prop_spec in _FILE_PROPERTIES:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(file, prop_1x) and getattr(file, prop_1x):
            properties_expressions.append(add_comparison_expression(getattr(file, prop_1x), object_path))
    if properties_expressions:
        expressions.extend(properties_expressions)
    if isinstance(file, WinExecutableFile):
        windows_executable_file_expression = convert_windows_executable_file_to_pattern(file)
        if windows_executable_file_expression:
            expressions.append(windows_executable_file_expression)
        else:
            warn("No WinExecutableFile properties found in %s", 613, text_type(file))
    if isinstance(file, ArchiveFile):
        archive_file_expressions = convert_archive_file_to_pattern(file)
        if archive_file_expressions:
            expressions.append(archive_file_expressions)
        else:
            warn("No ArchiveFile properties found in %s", 614, text_type(file))
    if expressions:
        return create_boolean_expression("AND", expressions)


_REGISTRY_KEY_VALUES_PROPERTIES = [["data", "win-registry-key:values[*].data"],
                                   ["name", "win-registry-key:values[*].name"],
                                   ["datatype", "win-registry-key:values[*].data_type"]]


def convert_registry_key_to_pattern(reg_key):
    expressions = []
    if reg_key.key:
        key_value_term = ""
        if reg_key.hive:
            if reg_key.hive.condition is None:
                key_value_term += reg_key.hive.value + "\\"
            else:
                warn("Condition on a hive property not handled", 812)
            key_value_term += reg_key.key.value
            expressions.append(create_term("win-registry-key:key", reg_key.key.condition,  key_value_term))
    if reg_key.values:
        values_expressions = []
        for v in reg_key.values:
            value_expressions = []
            for prop_spec in _REGISTRY_KEY_VALUES_PROPERTIES:
                prop_1x = prop_spec[0]
                object_path = prop_spec[1]
                if hasattr(v, prop_1x) and getattr(v, prop_1x):
                    value_expressions.append(add_comparison_expression(getattr(v, prop_1x),
                                                                       object_path))
            if value_expressions:
                values_expressions.append(create_boolean_expression("OR", value_expressions))
        expressions.extend(values_expressions)
    if expressions:
        return create_boolean_expression("AND", expressions)


def convert_process_to_pattern(process):
    expressions = []
    if process.name:
        expressions.append(create_term("process:name", process.name.condition, process.name.value))
    if isinstance(process, WinProcess):
        win_process_expression = convert_windows_process_to_pattern(process)
        if win_process_expression:
            expressions.append(win_process_expression)
        else:
            warn("No WinProcess properties found in %s", 615, text_type(process))
        if isinstance(process, WinService):
            service_expression = convert_windows_service_to_pattern(process)
            if service_expression:
                expressions.append(service_expression)
            else:
                warn("No WinService properties found in %s", 616, text_type(process))
    if expressions:
        return create_boolean_expression("AND", expressions)


def convert_windows_process_to_pattern(process):
    expression = ""
    if process.handle_list:
        for h in process.handle_list:
            warn("Windows Handles are not a part of CybOX 3.0", 420)
    return expression


_WINDOWS_PROCESS_PROPERTIES = \
    [["service_name", "process:extension_data.windows_service_ext.service_name"],
     ["display_name", "process:extension_data.windows_service_ext.display_name"],
     ["startup_command_line", "process:extension_data.windows_service_ext.startup_command_line"],
     ["start_type", "process:extension_data.windows_service_ext.start_type"],
     ["service_type", "process:extension_data.windows_service_ext.service_type"],
     ["service_status", "process:extension_data.windows_service_ext.service_status"]]


def convert_windows_service_to_pattern(service):
    expressions = []
    for prop_spec in _WINDOWS_PROCESS_PROPERTIES:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(service, prop_1x) and getattr(service, prop_1x):
            expressions.append(add_comparison_expression(getattr(service, prop_1x), object_path))
    if hasattr(service, "description_list") and service.description_list:
        description_expressions = []
        for d in service.description_list:
            description_expressions.append(create_term("process:extension_data.windows_service_ext.descriptions[*]",
                                                       d.condition,
                                                       d.value))
        if description_expressions:
            expressions.append(create_boolean_expression("OR", description_expressions))
    if hasattr(service, "service_dll") and service.service_dll:
        warn("WinServiceObject.service_dll is not handled, yet.", 804)
        expressions.append(UnconvertedTerm("WinServiceObject.service_dll"))
    if expressions:
        return create_boolean_expression("AND", expressions)


def convert_domain_name_to_pattern(domain_name):
    return create_term("domain-name:value", domain_name.value.condition, domain_name.value.value)


def convert_mutex_to_pattern(mutex):
    if mutex.name:
        return create_term("mutex:name", mutex.name.condition, mutex.name.value)
    else:
        return None


def convert_network_connection_to_pattern(conn):
    # TODO: Implement pattern
    error("Network Connection not implemented, yet", 811)
    return UnconvertedTerm(conn)


####################################################################################################################


def convert_observable_composition_to_pattern(obs_comp, bundle_instance, observable_mapping):
    expressions = []
    for obs in obs_comp.observables:
        term = convert_observable_to_pattern(obs, bundle_instance, observable_mapping)
        if term:
            expressions.append(term)
    if expressions:
        return create_boolean_expression(obs_comp.operator, expressions)
    else:
        return ""


def convert_object_to_pattern(obj, obs_id):
    prop = obj.properties
    expression = None

    if prop:
        if isinstance(prop, Address):
            expression = convert_address_to_pattern(prop)
        elif isinstance(prop, URI):
            expression = convert_uri_to_pattern(prop)
        elif isinstance(prop, EmailMessage):
            expression = convert_email_message_to_pattern(prop)
        elif isinstance(prop, File):
            expression = convert_file_to_pattern(prop)
        elif isinstance(prop, WinRegistryKey):
            expression = convert_registry_key_to_pattern(prop)
        elif isinstance(prop, Process):
            expression = convert_process_to_pattern(prop)
        elif isinstance(prop, DomainName):
            expression = convert_domain_name_to_pattern(prop)
        elif isinstance(prop, Mutex):
            expression = convert_mutex_to_pattern(prop)
        # elif isinstance(prop, NetworkConnection):
        #     expression = convert_network_connection_to_pattern(prop)
        else:
            warn("%s found in %s cannot be converted to a pattern, yet.", 808, text_type(obj.properties), obs_id)
            expression = UnconvertedTerm(obs_id)

        if prop.custom_properties is not None:
            object_path_root = convert_cybox_class_name_to_object_path_root_name(prop)
            if object_path_root:
                if expression:
                    expression = create_boolean_expression("AND", [expression, convert_custom_properties(prop.custom_properties, object_path_root)])
                else:
                    expression = convert_custom_properties(prop.custom_properties, object_path_root)
    if not expression:
        warn("No pattern term was created from %s", 422, obs_id)
        expression = UnconvertedTerm(obs_id)
    return expression


def match_1x_id_with_20_id(id_1x, id_20):
    id_1x_split = id_1x.split("-", 1)
    id_20_split = id_20.split("--")
    return id_1x_split[1] == id_20_split[1]


def find_definition(idref, sdos):
    for obs in sdos:
        if match_1x_id_with_20_id(idref, obs["id"]):
            info("Found definition for %s", 204, idref)
            return obs
    # warn (idref + " cannot be resolved")
    return None


def negate_expression(obs):
    return hasattr(obs, "negate") and obs.negate


def convert_observable_to_pattern(obs, bundle_instance, observable_mapping):
    try:
        set_dynamic_variable("current_observable", obs)
        if negate_expression(obs):
            warn("Negation of %s is not handled yet", 810, obs.id_)
        return convert_observable_to_pattern_without_negate(obs, bundle_instance, observable_mapping)
    finally:
        pop_dynamic_variable("current_observable")


def convert_observable_to_pattern_without_negate(obs, bundle_instance, id_to_observable_mapping):
    global PATTERN_CACHE
    if obs.observable_composition is not None:
        pattern = convert_observable_composition_to_pattern(obs.observable_composition,
                                                            bundle_instance,
                                                            id_to_observable_mapping)
        if pattern and obs.id_:
            add_to_pattern_cache(obs.id_, pattern)
        return pattern
    elif obs.object_ is not None:
        pattern = convert_object_to_pattern(obs.object_, obs.id_)
        if pattern:
            add_to_pattern_cache(obs.id_, pattern)
        return pattern
    elif obs.idref is not None:
        if obs.idref in PATTERN_CACHE:
            return PATTERN_CACHE[obs.idref]
        else:
            # resolve now if possible, and remove from observed_data
            observable_data_instance = find_definition(obs.idref, bundle_instance["observed_data"])
            if observable_data_instance is not None:
                    # TODO: remove from the report's object_refs
                if obs.idref in id_to_observable_mapping:
                    return convert_observable_to_pattern(id_to_observable_mapping[obs.idref],
                                                         bundle_instance,
                                                         id_to_observable_mapping)
            return IdrefPlaceHolder(obs.idref)


# patterns can contain idrefs which might need to be resolved because the order in which the ids and idrefs appear
def interatively_resolve_placeholder_refs():
    global PATTERN_CACHE
    if not PATTERN_CACHE:
        return
    done = False
    while not done:
        # collect all of the fully resolved idrefs
        fully_resolved_idrefs = []
        for idref, expr in PATTERN_CACHE.items():
            if expr and not expr.contains_placeholder():
                # no PLACEHOLDER idrefs found in the expr, means this idref is fully resolved
                fully_resolved_idrefs.append(idref)
        # replace only fully resolved idrefs
        change_made = False
        for fr_idref in fully_resolved_idrefs:
            for idref, expr in PATTERN_CACHE.items():
                if expr:
                    change_made, expr = expr.replace_placeholder_with_idref_pattern(fr_idref)
                    # a change will be made, which could introduce a new placeholder id into the expr
                    if change_made:
                        PATTERN_CACHE[idref] = expr
        done = not change_made


def is_placeholder(thing):
    return thing.index("PLACEHOLDER") != -1


def fix_pattern(pattern):
    if not PATTERN_CACHE == {}:
        # info(text_type(PATTERN_CACHE))
        # info("pattern is: " +  pattern)
        if pattern and pattern.contains_placeholder:
            for idref in PATTERN_CACHE.keys():
                pattern.replace_placeholder_with_idref_pattern(idref)
    return pattern


def convert_indicator_to_pattern(ind, bundle_instance, observable_mapping):
    try:
        set_dynamic_variable("current_indicator", ind)
        if ind.negate:
            warn("Negation of %s is not handled yet", 810, ind.id_)
        return convert_indicator_to_pattern_without_negate(ind, bundle_instance, observable_mapping)

    finally:
        pop_dynamic_variable("current_indicator")


def convert_indicator_to_pattern_without_negate(ind, bundle_instance, id_to_observable_mapping):
    global PATTERN_CACHE
    if ind.composite_indicator_expression is not None:
        pattern = convert_indicator_composition_to_pattern(ind.composite_indicator_expression,
                                                           bundle_instance,
                                                           id_to_observable_mapping)
        if pattern and ind.id_:
            add_to_pattern_cache(ind.id_, pattern)
        return pattern
    elif ind.observable is not None:
        pattern = convert_observable_to_pattern(ind.observable)
        if pattern:
            add_to_pattern_cache(ind.id_, pattern)
        return pattern
    elif ind.idref is not None:
        if ind.idref in PATTERN_CACHE:
            return PATTERN_CACHE[ind.idref]
        else:
            # resolve now if possible, and remove from observed_data
            indicator_data_instance = find_definition(ind.idref, bundle_instance["indicators"])
            if indicator_data_instance is not None:
                indicator_data_instance["used_in_pattern"] = True
                # TODO: remove from the report's object_refs
                if ind.idref in id_to_observable_mapping:
                    return convert_observable_to_pattern(id_to_observable_mapping[ind.idref],
                                                         bundle_instance,
                                                         id_to_observable_mapping)
            return IdrefPlaceHolder(ind.idref)


def convert_indicator_composition_to_pattern(ind_comp, bundle_instance, observable_mapping):
    expressions = []
    for ind in ind_comp.indicators:
        term = convert_indicator_to_pattern(ind, bundle_instance, observable_mapping)
        if term:
            expressions.append(term)
        else:
            warn("No term was yielded for %s", 422, ind.id_ or ind.idref)
    if expressions:
        return create_boolean_expression(ind_comp.operator, expressions)
    else:
        return ""


def remove_pattern_objects(bundle_instance):
    all_new_ids_with_patterns = []
    for old_id in PATTERN_CACHE.keys():
        new_id = get_id_value(old_id)
        if new_id and len(new_id) == 1:
            all_new_ids_with_patterns.append(new_id[0])

    if not KEEP_OBSERVABLE_DATA_USED_IN_PATTERNS:
        remaining_objects = []
        for obj in bundle_instance["objects"]:
            if obj["type"] != "observed-data" or obj["id"] not in all_new_ids_with_patterns:
                remaining_objects.append(obj)
            else:
                warn("%s is used as a pattern, therefore it is not included as an observed_data instance", 423, obj["id"])
        bundle_instance["objects"] = remaining_objects

    if not KEEP_OBSERVABLE_DATA_USED_IN_PATTERNS:
        for obj in bundle_instance["objects"]:
            if obj["type"] == "report":
                remaining_object_refs = []
                for ident in obj["object_refs"]:
                    if not ident.startswith("observed-data") or ident not in all_new_ids_with_patterns:
                        remaining_object_refs.append(ident)
                obj["object_refs"] = remaining_object_refs

# TODO: only remove indicators that were involved ONLY as sub-indicators within composite indicator expressions
#   if not KEEP_INDICATORS_USED_IN_COMPOSITE_INDICATOR_EXPRESSION and "indicators" in bundle_instance:
#       remaining_indicators = []
#       for ind in bundle_instance["indicators"]:
#           if ind["id"] not in all_new_ids_with_patterns:
#               remaining_indicators.append(ind)
#       bundle_instance["indicators"] = remaining_indicators
