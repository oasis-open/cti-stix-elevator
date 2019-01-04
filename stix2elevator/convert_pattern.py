import datetime
import re
import sys

from cybox.objects.account_object import Account
from cybox.objects.address_object import Address
from cybox.objects.archive_file_object import ArchiveFile
from cybox.objects.domain_name_object import DomainName
from cybox.objects.email_message_object import EmailMessage
from cybox.objects.file_object import File
from cybox.objects.http_session_object import HostField, HTTPSession
from cybox.objects.mutex_object import Mutex
from cybox.objects.network_connection_object import NetworkConnection
from cybox.objects.network_packet_object import NetworkPacket
from cybox.objects.network_socket_object import NetworkSocket
from cybox.objects.process_object import Process
from cybox.objects.unix_user_account_object import UnixUserAccount
from cybox.objects.uri_object import URI
from cybox.objects.win_computer_account_object import WinComputerAccount
from cybox.objects.win_executable_file_object import WinExecutableFile
from cybox.objects.win_process_object import WinProcess
from cybox.objects.win_registry_key_object import WinRegistryKey
from cybox.objects.win_service_object import WinService
from six import text_type
import stix2
from stix2.patterns import (BasicObjectPathComponent, ListObjectPathComponent,
                            ObjectPath, ObservationExpression,
                            QualifiedObservationExpression,
                            ReferenceObjectPathComponent, _BooleanExpression,
                            _ComparisonExpression,
                            _CompoundObservationExpression, _Constant)
import stixmarx

from stix2elevator.common import ADDRESS_FAMILY_ENUMERATION, SOCKET_OPTIONS
from stix2elevator.convert_cybox import split_into_requests_and_responses
from stix2elevator.ids import (add_object_id_value, exists_object_id_key,
                               get_id_value, get_object_id_value)
from stix2elevator.options import error, get_option_value, info, warn
from stix2elevator.utils import identifying_info, map_vocabs_to_label
from stix2elevator.vocab_mappings import WINDOWS_PEBINARY

if sys.version_info > (3,):
    long = int

KEEP_OBSERVABLE_DATA_USED_IN_PATTERNS = False

KEEP_INDICATORS_USED_IN_COMPOSITE_INDICATOR_EXPRESSION = True


class BasicObjectPathComponentForElevator(BasicObjectPathComponent):
    @staticmethod
    def create_ObjectPathComponent(component_name):
        if component_name.endswith("_ref"):
            return ReferenceObjectPathComponentForElevator(component_name)
        elif component_name.find("[") != -1:
            parse1 = component_name.split("[")
            return ListObjectPathComponentForElevator(parse1[0], parse1[1][:-1])
        else:
            return BasicObjectPathComponentForElevator(component_name, False)


class ListObjectPathComponentForElevator(ListObjectPathComponent):
    @staticmethod
    def create_ObjectPathComponent(component_name):
        if component_name.endswith("_ref"):
            return ReferenceObjectPathComponentForElevator(component_name)
        elif component_name.find("[") != -1:
            parse1 = component_name.split("[")
            return ListObjectPathComponentForElevator(parse1[0], parse1[1][:-1])
        else:
            return BasicObjectPathComponentForElevator(component_name, False)


class ReferenceObjectPathComponentForElevator(ReferenceObjectPathComponent):
    @staticmethod
    def create_ObjectPathComponent(component_name):
        if component_name.endswith("_ref"):
            return ReferenceObjectPathComponentForElevator(component_name)
        elif component_name.find("[") != -1:
            parse1 = component_name.split("[")
            return ListObjectPathComponentForElevator(parse1[0], parse1[1][:-1])
        else:
            return BasicObjectPathComponentForElevator(component_name, False)


class ObjectPathForElevator(ObjectPath):
    def toSTIX21(self):
        current_cyber_observable_type = self.object_type_name
        for x in self.property_path:
            if x.property_name == "extensions":
                continue
            if current_cyber_observable_type == "file":
                if (x.property_name == "is_encrypted" or
                        x.property_name == "encryption_algorithm" or
                        x.property_name == "decryption_key"):
                    print(
                        "Expression contains the property " + x.property_name + ", for a file, which is not in STIX 2.1")
                elif x.property_name == "archive-ext" or x.property_name == "raster-image-ext":
                    current_cyber_observable_type = x.property_name
                elif x.property_name == "contains_refs":
                    current_cyber_observable_type = "file"
                elif x.property_name == "parent_directory_ref":
                    current_cyber_observable_type = "directory"
            elif current_cyber_observable_type == "directory":
                if x.property_name == "contains_refs":
                    # TODO - what if it is a directory?
                    current_cyber_observable_type = "file"
            elif current_cyber_observable_type == "archive-ext":
                if x.property_name == "version":
                    print("Expression contains the property version, for a file.archive-ext, which is not in STIX 2.1")
            elif current_cyber_observable_type == "raster-image-ext":
                if x.property_name == "image_compression_algorithm":
                    print(
                        "Expression contains the property image_compression_algorithm, for a file.raster-image-ext, which is not in STIX 2.1")
            elif current_cyber_observable_type == "network_traffic":
                if x.property_name == "socket-ext":
                    current_cyber_observable_type = x.property_name
            elif current_cyber_observable_type == "socket-ext":
                if x.property_name == "protocol_family":
                    print(
                        "Expression contains the property protocol_familys, for a network_traffic:socket-ext, which is not in STIX 2.1")
            elif current_cyber_observable_type == "process":
                if x.property_name == "name" or x.property_name == "arguments":
                    print(
                        "Expression contains the property " + x.property_name + ", for a process, which is not in STIX 2.1")
                elif x.property_name == "binary_ref":
                    x.property_name = "image_ref"
                elif x.property_name == "opened_connection_refs":
                    current_cyber_observable_type = "network_traffic"
                elif x.property_name == 'creator_user_ref':
                    current_cyber_observable_type = "user_account"
                elif x.property_name == 'binary_ref':
                    current_cyber_observable_type = "file"
                elif x.property_name == 'windows-service-ext':
                    current_cyber_observable_type = 'windows-service-ext'
            elif current_cyber_observable_type == 'windows-service-ext':
                if x.property_name == 'service_dll_refs':
                    current_cyber_observable_type = "file"
            elif current_cyber_observable_type == "user_account":
                if x.property_name == "password_last_changed":
                    x.property_name = "credential_last_changed"
        return self


class ComparisonExpressionForElevator(_ComparisonExpression):
    # overrides, so IdrefPlaceHolder can be handled
    def __init__(self, operator, lhs, rhs, negated=False):
        self.operator = operator
        if operator == "=" and isinstance(rhs, stix2.ListConstant):
            warn("apply_condition assumed to be 'ANY' in %s",
                 721, identifying_info(get_dynamic_variable("current_observable")))
            self.operator = "IN"
        if isinstance(lhs, stix2.ObjectPath):
            self.lhs = lhs
        else:
            self.lhs = stix2.ObjectPath.make_object_path(lhs)
        # rhs might be a reference to another object, which has its own observable pattern
        if isinstance(rhs, _Constant) or isinstance(rhs, IdrefPlaceHolder):
            self.rhs = rhs
        else:
            self.rhs = make_constant(rhs)
        self.negated = negated
        self.root_type = self.lhs.object_type_name

    def contains_placeholder(self):
        return isinstance(self.rhs, IdrefPlaceHolder)

    def collapse_reference(self, prefix):
        new_lhs = prefix.merge(self.lhs)
        new_lhs.collapsed = True
        return ComparisonExpressionForElevator(self.operator, new_lhs, self.rhs)

    def replace_placeholder_with_idref_pattern(self, idref):
        if isinstance(self.rhs, IdrefPlaceHolder):
            change_made, pattern = self.rhs.replace_placeholder_with_idref_pattern(idref)
            if change_made:
                if hasattr(self.lhs, "collapsed") and self.lhs.collapsed:
                    return True, ComparisonExpressionForElevator(pattern.operator, self.lhs, pattern.rhs)
                else:
                    return True, pattern.collapse_reference(self.lhs)
        return False, self

    def partition_according_to_object_path(self):
        return self

    def contains_unconverted_term(self):
        return False

    def toSTIX21(self):
        self.lhs = self.lhs.toSTIX21()
        return self


class EqualityComparisonExpressionForElevator(ComparisonExpressionForElevator):
    def __init__(self, lhs, rhs, negated=False):
        super(EqualityComparisonExpressionForElevator, self).__init__("=", lhs, rhs, negated)


class MatchesComparisonExpressionForElevator(ComparisonExpressionForElevator):
    def __init__(self, lhs, rhs, negated=False):
        super(MatchesComparisonExpressionForElevator, self).__init__("MATCHES", lhs, rhs, negated)


class GreaterThanComparisonExpressionForElevator(ComparisonExpressionForElevator):
    def __init__(self, lhs, rhs, negated=False):
        super(GreaterThanComparisonExpressionForElevator, self).__init__(">", lhs, rhs, negated)


class LessThanComparisonExpressionForElevator(ComparisonExpressionForElevator):
    def __init__(self, lhs, rhs, negated=False):
        super(LessThanComparisonExpressionForElevator, self).__init__("<", lhs, rhs, negated)


class GreaterThanEqualComparisonExpressionForElevator(ComparisonExpressionForElevator):
    def __init__(self, lhs, rhs, negated=False):
        super(GreaterThanEqualComparisonExpressionForElevator, self).__init__(">=", lhs, rhs, negated)


class LessThanEqualComparisonExpressionForElevator(ComparisonExpressionForElevator):
    def __init__(self, lhs, rhs, negated=False):
        super(LessThanEqualComparisonExpressionForElevator, self).__init__("<=", lhs, rhs, negated)


class InComparisonExpressionForElevator(ComparisonExpressionForElevator):
    def __init__(self, lhs, rhs, negated=False):
        super(InComparisonExpressionForElevator, self).__init__("IN", lhs, rhs, negated)


class LikeComparisonExpressionForElevator(ComparisonExpressionForElevator):
    def __init__(self, lhs, rhs, negated=False):
        super(LikeComparisonExpressionForElevator, self).__init__("LIKE", lhs, rhs, negated)


class IsSubsetComparisonExpressionForElevator(ComparisonExpressionForElevator):
    def __init__(self, lhs, rhs, negated=False):
        super(IsSubsetComparisonExpressionForElevator, self).__init__("ISSUBSET", lhs, rhs, negated)


class IsSupersetComparisonExpressionForElevator(ComparisonExpressionForElevator):
    def __init__(self, lhs, rhs, negated=False):
        super(IsSupersetComparisonExpressionForElevator, self).__init__("ISSUPERSET", lhs, rhs, negated)


class BooleanExpressionForElevator(_BooleanExpression):
    def add_operand(self, operand):
        self.operands.append(operand)

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
            if change_made_this_time:
                if not hasattr(self, "root_type"):
                    self.root_type = new_operand.root_type
                elif self.root_type and hasattr(new_operand, "root_type") and (self.root_type != new_operand.root_type):
                    self.root_type = None
            change_made = change_made or change_made_this_time
            new_operands.append(new_operand)
        self.operands = new_operands
        return change_made, self

    def collapse_reference(self, prefix):
        new_operands = []
        for operand in self.operands:
            new_operands.append(operand.collapse_reference(prefix))
        return BooleanExpressionForElevator(self.operator, new_operands)

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
        if len(results) == 1:
            return results[0]
        else:
            return CompoundObservationExpressionForElevator(self.operator, results)

    def contains_unconverted_term(self):
        for args in self.operands:
            if args.contains_unconverted_term():
                return True
        return False

    def toSTIX21(self):
        for args in self.operands:
            args.toSTIX21()
        return self


class AndBooleanExpressionForElevator(BooleanExpressionForElevator):
    """'AND' Boolean Pattern Expression. Only use if both operands are of
    the same root object.

    Args:
        operands (list): AND operands
    """

    def __init__(self, operands):
        super(AndBooleanExpressionForElevator, self).__init__("AND", operands)


class OrBooleanExpressionForElevator(BooleanExpressionForElevator):
    """'OR' Boolean Pattern Expression. Only use if both operands are of the same root object

    Args:
        operands (list): OR operands
    """

    def __init__(self, operands):
        super(OrBooleanExpressionForElevator, self).__init__("OR", operands)


class IdrefPlaceHolder(object):
    def __init__(self, idref):
        self.idref = idref

    def __str__(self):
        return "PLACEHOLDER:" + self.idref

    def contains_placeholder(self):
        return True

    def replace_placeholder_with_idref_pattern(self, idref):
        if idref == self.idref:
            return True, get_pattern_from_cache(idref)
        elif exists_object_id_key(self.idref) and idref == get_object_id_value(self.idref):
            return True, get_pattern_from_cache(idref)
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

    def __str__(self):
        return "unconverted_term:%s" % self.term_info

    def contains_placeholder(self):
        return False

    def replace_placeholder_with_idref_pattern(self, idref):
        return False, self

    def partition_according_to_object_path(self):
        return self

    def contains_unconverted_term(self):
        return True


class ObservationExpressionForElevator(ObservationExpression):
    def toSTIX21(self):
        self.operand.toSTIX21()
        return self


class CompoundObservationExpressionForElevator(_CompoundObservationExpression):
    def __str__(self):
        sub_exprs = []
        if len(self.operands) == 1:
            return "[%s]" % self.operands[0]
        for o in self.operands:
            if isinstance(o, ObservationExpressionForElevator) or isinstance(o,
                                                                             CompoundObservationExpressionForElevator):
                sub_exprs.append("%s" % o)
            else:
                sub_exprs.append("[%s]" % o)
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

    def partition_according_to_object_path(self):
        return self

    def toSTIX21(self):
        for arg in self.operands:
            arg.toSTIX21()
        return self


class AndObservationExpressionForElevator(CompoundObservationExpressionForElevator):
    """'AND' Compound Observation Pattern Expression

    Args:
        operands (str): compound observation operands
    """

    def __init__(self, operands):
        super(AndObservationExpressionForElevator, self).__init__("AND", operands)


class OrObservationExpressionForElevator(CompoundObservationExpressionForElevator):
    """Pattern 'OR' Compound Observation Expression

    Args:
        operands (str): compound observation operands
    """

    def __init__(self, operands):
        super(OrObservationExpressionForElevator, self).__init__("OR", operands)


class FollowedByObservationExpressionForElevator(CompoundObservationExpressionForElevator):
    """Pattern 'Followed by' Compound Observation Expression

    Args:
        operands (str): compound observation operands
    """

    def __init__(self, operands):
        super(FollowedByObservationExpressionForElevator, self).__init__("FOLLOWEDBY", operands)


class QualifiedObservationExpressionForElevator(QualifiedObservationExpression):
    """Pattern Qualified Observation Expression

    Args:
        observation_expression (PatternExpression OR _CompoundObservationExpression OR ): pattern expression
        qualifier (_ExpressionQualifier): pattern expression qualifier
    """

    def __init__(self, observation_expression, qualifier):
        super(QualifiedObservationExpressionForElevator, self).__init__(observation_expression, qualifier)

    def toSTIX21(self):
        self.observation_expression.toSTIX21()
        return self


class ParentheticalExpressionForElevator(stix2.ParentheticalExpression):
    def contains_placeholder(self):
        return self.expression.contains_placeholder()

    def contains_unconverted_term(self):
        return self.expression.contains_unconverted_term()

    def replace_placeholder_with_idref_pattern(self, idref):
        change_made, new_expression = self.expression.replace_placeholder_with_idref_pattern(idref)
        self.expression = new_expression
        if hasattr(new_expression, "root_type"):
            self.root_type = new_expression.root_type
        return change_made, self

    def collapse_reference(self, prefix):
        new_expression = self.expression.collapse_reference(prefix)
        return ParentheticalExpressionForElevator(new_expression)

    def partition_according_to_object_path(self):
        self.expression = self.expression.partition_according_to_object_path()
        return self

    def toSTIX21(self):
        self.expression.toSTIX21()
        return self


def create_boolean_expression(operator, operands):
    if len(operands) == 1:
        return operands[0]
    exp = BooleanExpressionForElevator(operator, [])
    for arg in operands:
        if not isinstance(arg, IdrefPlaceHolder) and not isinstance(arg, UnconvertedTerm) and hasattr(arg, "root_type"):
            if not hasattr(exp, "root_type"):
                exp.root_type = arg.root_type
            elif exp.root_type and (exp.root_type != arg.root_type):
                exp.root_type = None
        exp.add_operand(arg)
    return ParentheticalExpressionForElevator(exp)


###################


_PATTERN_CACHE = {}


def clear_pattern_cache():
    global _PATTERN_CACHE
    _PATTERN_CACHE = {}


def add_to_pattern_cache(key, pattern):
    global _PATTERN_CACHE
    if pattern:
        _PATTERN_CACHE[key] = pattern


def id_in_pattern_cache(id_):
    return id_ in _PATTERN_CACHE


def get_pattern_from_cache(id_):
    return _PATTERN_CACHE[id_]


def get_ids_from_pattern_cache():
    return _PATTERN_CACHE.keys()


def get_items_from_pattern_cache():
    return _PATTERN_CACHE.items()


def pattern_cache_is_empty():
    return _PATTERN_CACHE == {}


###########

_OBSERVABLE_MAPPINGS = {}


def add_to_observable_mappings(obs):
    global _OBSERVABLE_MAPPINGS
    if obs:
        _OBSERVABLE_MAPPINGS[obs.id_] = obs
        _OBSERVABLE_MAPPINGS[obs.object_.id_] = obs


def id_in_observable_mappings(id_):
    return id_ in _OBSERVABLE_MAPPINGS


def get_obs_from_mapping(id_):
    return _OBSERVABLE_MAPPINGS[id_]


def clear_observable_mappings():
    global _OBSERVABLE_MAPPINGS
    _OBSERVABLE_MAPPINGS = {}


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
                       "WinRegistryKey": "windows-registry-key",
                       "Process": "process",
                       "DomainName": "domain-name",
                       "Mutex": "mutex",
                       "WinExecutableFile": "file:extensions.'windows-pebinary-ext'",
                       "ArchiveFile": "file:extensions.'archive-ext'",
                       "NetworkConnection": "network-traffic"}

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


def is_equal_condition(cond):
    return cond == "Equals" or cond is None


def add_parens_if_needed(expr):
    if expr.find("AND") != -1 or expr.find("OR") != -1:
        return "(" + expr + ")"
    else:
        return expr


_CONDITION_OPERATOR_MAP = {
    'Equals': "=",
    "DoesNotEqual": "!=",
    "Contains": "=",
    "DoesNotContain": "!=",
    "GreaterThan": ">",
    'GreaterThanOrEqual': ">=",
    "LessThan": "<",
    "LessThanOrEqual": "<="
    # StartsWith - handled in create_term_with_regex
    # EndsWith  - handled in create_term_with_regex
    # InclusiveBetween - handled in create_term_with_range
    # ExclusiveBetween - handled in create_term_with_range
    # FitsPattern
    # BitwiseAnd
    # BitwiseOr
}


def convert_condition(condition):
    if condition is None:
        warn("No condition given for %s - assume '='", 714,
             identifying_info(get_dynamic_variable("current_observable")))
        return "="
    for cond, op in _CONDITION_OPERATOR_MAP.items():
        if cond.lower() == condition.lower():
            if cond != condition:
                warn("'%s' allowed in %s - should be '%s'", 630,
                     condition,
                     identifying_info(get_dynamic_variable("current_observable")),
                     cond)
            return op
    warn("Unknown condition given in %s - marked as 'INVALID_CONDITION'", 628,
         identifying_info(get_dynamic_variable("current_observable")))
    return "INVALID-CONDITION"


def process_boolean_negation(op, negated):
    if not negated:
        return op
    elif op == "AND":
        return "OR"
    elif op == "OR":
        return "AND"
    else:
        raise (ValueError("not a legal Boolean op: %s" % op))


def process_comparison_negation(op, negated):
    if not negated:
        return op
    elif op == "=":
        return "!="
    elif op == "!=":
        return "="
    elif op == "<":
        return ">="
    elif op == "<=":
        return ">"
    elif op == ">":
        return "<="
    elif op == ">=":
        return "<"
    else:
        raise (ValueError("not a legal Comparison op: %s" % op))


def create_term_with_regex(lhs, condition, rhs, negated):
    # TODO: escape characters
    if condition == "StartsWith":
        rhs.value = "^%s" % rhs.value
    elif condition == "EndsWith":
        rhs.value = "$%s" % rhs.value
    return ComparisonExpressionForElevator("MATCHES", lhs, rhs, negated)


def create_term_with_range(lhs, condition, rhs, negated=False):
    # TODO: handle negated
    if not isinstance(rhs, stix2.ListConstant) or len(rhs.value) != 2:
        error("%s was used, but two values were not provided.", 609, condition)
        return "'range term underspecified'"
    else:
        if condition == "InclusiveBetween":
            # return "(" + lhs + " GE " + text_type(rhs[0]) + " AND " + lhs + " LE " + text_type(rhs[1]) + ")"
            lower_bound = ComparisonExpressionForElevator(process_comparison_negation(">=", negated), lhs, rhs.value[0])
            upper_bound = ComparisonExpressionForElevator(process_comparison_negation("<=", negated), lhs, rhs.value[1])

        else:  # "ExclusiveBetween"
            # return "(" + lhs + " GT " + text_type(rhs[0]) + " AND " + lhs + " LT " + text_type(rhs[1]) + ")"
            lower_bound = ComparisonExpressionForElevator(process_comparison_negation(">", negated), lhs, rhs.value[0])
            upper_bound = ComparisonExpressionForElevator(process_comparison_negation("<", negated), lhs, rhs.value[1])
        return create_boolean_expression(process_boolean_negation("AND", negated), [lower_bound, upper_bound])


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
            return create_term_with_regex(lhs, condition, rhs, negated)
        elif condition == "DoesNotContain":
            warn("Used MATCHES operator for %s", 715, condition)
            return create_term_with_regex(lhs, condition, rhs, not negated)
        # return lhs + " " + negate_if_needed(convert_condition(condition), negated) + " '" + convert_to_text_type(rhs) + "'"
        return ComparisonExpressionForElevator(convert_condition(condition), lhs, rhs, negated)


def make_constant(obj):
    # TODO:  handle other Markable objects?
    if isinstance(obj, bool):
        return stix2.BooleanConstant(obj)
    elif isinstance(obj, int) or isinstance(obj, long):
        return stix2.IntegerConstant(obj)
    elif isinstance(obj, float):
        return stix2.FloatConstant(obj)
    elif isinstance(obj, str) or isinstance(obj, stixmarx.api.types.MarkableText):
        return stix2.StringConstant(obj.strip())
    elif isinstance(obj, list):
        return stix2.ListConstant([make_constant(x) for x in obj])
    elif isinstance(obj, datetime.datetime) or isinstance(obj, stixmarx.api.types.MarkableDateTime):
        return stix2.TimestampConstant(obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    else:
        raise ValueError("Can't make a constant from %s" % obj)


def add_comparison_expression(prop, object_path):
    if prop is not None and prop.value is not None:
        if hasattr(prop, "condition"):
            cond = prop.condition
        else:
            warn("No condition given - assume '='", 714)
            cond = None
        return create_term(object_path, cond, make_constant(prop.value))
    if prop is not None and prop.value is None:
        warn("No term was yielded for %s", 622, object_path)
    return None


def convert_custom_properties(cps, object_type_name):
    expressions = []
    for cp in cps.property_:
        if not re.match("[a-z0-9_]+", cp.name):
            warn("The custom property name %s does not adhere to the specification rules", 617, cp.name)
            if " " in cp.name:
                warn("The custom property name %s contains whitespace, replacing it with underscores", 624, cp.name)
        expressions.append(
            create_term(object_type_name + ":x_" + cp.name.replace(" ", "_"), cp.condition, make_constant(cp.value)))
    return create_boolean_expression("AND", expressions)


_ACCOUNT_PROPERTIES = [
    ["full_name", "user-account:display_name"],
    ["last_login", "user-account:account_last_login"],
    ["username", "user-account:account_login"],
    ["creation_time", "user-account:account_created"]
]


def convert_account_to_pattern(account):
    expressions = []
    if hasattr(account, "disabled") and account.disabled:
        expressions.append(create_term("user-account:is_disabled",
                                       "Equals",
                                       stix2.BooleanConstant(account.disabled)))
    for prop_spec in _ACCOUNT_PROPERTIES:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(account, prop_1x) and getattr(account, prop_1x):
            term = add_comparison_expression(getattr(account, prop_1x), object_path)
            if term:
                expressions.append(term)
    if account.authentication and get_option_value("spec_version") == "2.1":
        if account.authentication.authentication_data:
            expressions.append(create_term("user-account:credential",
                                           "Equals",
                                           stix2.StringConstant(account.authentication.authentication_data)))
    if isinstance(account, UnixUserAccount):
        win_process_expression = convert_unix_user_to_pattern(account)
        if win_process_expression:
            expressions.append(win_process_expression)
        else:
            warn("No UnixUserAccount properties found in %s", 615, text_type(account))
    elif isinstance(account, WinComputerAccount):
        expressions.append(create_term("user-account:account_type",
                                       "Equals",
                                       stix2.StringConstant("windows-domain" if account.domain else "windows-local")))
    if expressions:
        return create_boolean_expression("AND", expressions)


_UNIX_ACCOUNT_PROPERTIES = [
    ["group_id", "user-account:extensions.'unix-account-ext'.gid"],
    ["login_shell", "user-account:extensions.'unix-account-ext'.shell"],
    ["home_directory", "user-account:extensions.'unix-account-ext'.home_dir"],
]


def convert_unix_user_to_pattern(account):
    expressions = []
    expressions.append(create_term("user-account:account_type",
                                   "Equals",
                                   stix2.StringConstant("unix")))
    if hasattr(account, "user_id") and account.user_id:
        expressions.append(create_term("user-account:user_id",
                                       account.user_id.condition,
                                       stix2.StringConstant(text_type(account.user_id.value))))
    for prop_spec in _UNIX_ACCOUNT_PROPERTIES:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(account, prop_1x) and getattr(account, prop_1x):
            term = add_comparison_expression(getattr(account, prop_1x), object_path)
            if term:
                expressions.append(term)
    if expressions:
        return create_boolean_expression("AND", expressions)


def convert_address_to_pattern(add):
    cond = add.address_value.condition
    if add.category == add.CAT_IPV4:
        return create_term("ipv4-addr:value", cond, make_constant(add.address_value.value.strip()))
    elif add.category == add.CAT_IPV6:
        return create_term("ipv6-addr:value", cond, make_constant(add.address_value.value.strip()))
    elif add.category == add.CAT_MAC:
        return create_term("mac-addr:value", cond, make_constant(add.address_value.value.strip()))
    elif add.category == add.CAT_EMAIL:
        return create_term("email-addr:value", cond, make_constant(add.address_value.value.strip()))
    else:
        warn("The address type %s is not part of Cybox 3.0", 421, add.category)


def convert_uri_to_pattern(uri):
    return create_term("url:value", uri.value.condition, make_constant(uri.value.value.strip()))


# NOTICE:  The format of these PROPERTIES is different than the others in this file!!!!!!
_EMAIL_HEADER_PROPERTIES = [["email-message:subject", ["subject"]],
                            ["email-message:from_ref.value", ["from_", "address_value"]],
                            ["email-message:sender_ref.value", ["sender", "address_value"]],
                            ["email-message:date", ["date"]],
                            ["email-message:content_type", ["content_type"]],
                            ["email-message:to_refs[*].value", ["to*", "address_value"]],
                            ["email-message:cc_refs[*].value", ["cc*", "address_value"]],
                            ["email-message:bcc_refs[*].value", ["bcc*", "address_value"]]]

_EMAIL_ADDITIONAL_HEADERS_PROPERTIES = \
    [["email-message:additional_header_fields.Reply-To", ["reply-to*", "address_value"]],
     ["email-message:additional_header_fields.Message-ID", ["message_id"]],
     ["email-message:additional_header_fields.In-Reply-To", ["in_reply_to"]],
     ["email-message:additional_header_fields.Errors-To", ["errors_to"]],
     ["email-message:additional_header_fields.MIME-Version", ["mime_version"]],
     ["email-message:additional_header_fields.Precedence", ["precedence"]],
     ["email-message:additional_header_fields.User-Agent", ["user_agent"]],
     ["email-message:additional_header_fields.Boundary", ["boundary"]],
     ["email-message:additional_header_fields.X-Originating-IP", ["x_originating_ip", "address_value"]],
     ["email-message:additional_header_fields.X-Priority", ["x_priority"]],
     ["email-message:additional_header_fields.X-Mailer", ["x_mailer"]]]


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
                    term = add_comparison_expression(c, object_path)
                    if term:
                        prop_exprs.append(term)
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
                        term = create_terms_from_prop_list(rest_of_prop_list, c, object_path)
                        if term:
                            prop_exprs.append(term)
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


def convert_attachment_to_ref(attachment):
    return IdrefPlaceHolder(attachment.object_reference)


def convert_email_message_to_pattern(mess):
    expressions = []
    if mess.header is not None:
        expressions.append(convert_email_header_to_pattern(mess.header, _EMAIL_HEADER_PROPERTIES))
        add_headers = convert_email_header_to_pattern(mess.header, _EMAIL_ADDITIONAL_HEADERS_PROPERTIES)
        if add_headers:
            expressions.append(add_headers)
    if mess.attachments is not None:
        for attachment in mess.attachments:
            expressions.append(ComparisonExpressionForElevator("=", "email-message:body_multipart[*].body_raw_ref",
                                                               convert_attachment_to_ref(attachment)))
    if mess.raw_body is not None:
        if not mess.raw_body.value:
            warn("%s contains no value", 621, "Email raw body")
        else:
            warn("Email raw body not handled yet", 806)
    if mess.links is not None:
        warn("Email links not handled yet", 806)
    if expressions:
        return create_boolean_expression("AND", expressions)


_PE_FILE_HEADER_PROPERTIES = \
    [["machine", "file:extensions.'windows-pebinary-ext'.file_header:machine_hex"],
     ["time_date_stamp", "file:extensions.'windows-pebinary-ext'.file_header.time_date_stamp"],
     ["number_of_sections", "file:extensions.'windows-pebinary-ext'.file_header.number_of_sections"],
     ["pointer_to_symbol_table", "file:extensions.'windows-pebinary-ext'.file_header.pointer_to_symbol_table"],
     ["number_of_symbols", "file:extensions.'windows-pebinary-ext'.file_header.number_of_symbols"],
     ["size_of_optional_header", "file:extensions.'windows-pebinary-ext'.file_header.size_of_optional_header"],
     ["characteristics", "file:extensions.'windows-pebinary-ext'.file_header.characteristics_hex"]]

_PE_SECTION_HEADER_PROPERTIES = [["name", "file:extensions.'windows-pebinary-ext'.section[*].name"],
                                 ["virtual_size", "file:extensions.'windows-pebinary-ext'.section[*].size"]]

_ARCHIVE_FILE_PROPERTIES_2_0 = [["comment", "file:extensions.'archive-ext'.comment"],
                                ["version", "file:extensions.'archive-ext'.version"]]

_ARCHIVE_FILE_PROPERTIES_2_1 = [["comment", "file:extensions.'archive-ext'.comment"]]


def select_archive_file_properties():
    if get_option_value("spec_version") == "2.1":
        return _ARCHIVE_FILE_PROPERTIES_2_1
    else:
        return _ARCHIVE_FILE_PROPERTIES_2_0


def convert_windows_executable_file_to_pattern(f):
    expressions = []
    if f.headers:
        file_header = f.headers.file_header
        if file_header:
            file_header_expressions = []
            for prop_spec in _PE_FILE_HEADER_PROPERTIES:
                prop_1x = prop_spec[0]
                object_path = prop_spec[1]
                if hasattr(file_header, prop_1x) and getattr(file_header, prop_1x):
                    term = add_comparison_expression(getattr(file_header, prop_1x), object_path)
                    if term:
                        file_header_expressions.append(term)
            if file_header.hashes is not None:
                hash_expression = convert_hashes_to_pattern(file_header.hashes)
                if hash_expression:
                    file_header_expressions.append(hash_expression)
            if file_header_expressions:
                expressions.append(create_boolean_expression("AND", file_header_expressions))
        if f.headers.optional_header:
            warn("file:extensions:'windows-pebinary-ext':optional_header is not implemented yet", 807)

    if f.type_:
        expressions.append(create_term("file:extensions.'windows-pebinary-ext'.pe_type",
                                       f.type_.condition,
                                       stix2.StringConstant(map_vocabs_to_label(f.type_.value, WINDOWS_PEBINARY))))
    sections = f.sections
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
                        term = add_comparison_expression(getattr(s.section_header, prop_1x), object_path)
                        if term:
                            section_expressions.append(term)
            if s.entropy:
                if s.entropy.min:
                    warn("Entropy.min is not supported in STIX 2.0", 424)
                if s.entropy.min:
                    warn("Entropy.max is not supported in STIX 2.0", 424)
                if s.entropy.value:
                    section_expressions.append(create_term("file:extensions.'windows-pebinary-ext'.section[*].entropy",
                                                           s.entropy.value.condition,
                                                           stix2.FloatConstant(s.entropy.value.value)))
            if s.data_hashes:
                section_expressions.append(convert_hashes_to_pattern(s.data_hashes))
            if s.header_hashes:
                section_expressions.append(convert_hashes_to_pattern(s.header_hashes))
            if section_expressions:
                sections_expressions.append(create_boolean_expression("AND", section_expressions))
        if sections_expressions:
            expressions.append(create_boolean_expression("AND", sections_expressions))
    if f.exports:
        warn("The exports property of WinExecutableFileObj is not part of STIX 2.x", 418)
        expressions.append(UnconvertedTerm("WinExecutableFileObj.exports"))
    if f.imports:
        warn("The imports property of WinExecutableFileObj is not part of STIX 2.x", 418)
        expressions.append(UnconvertedTerm("WinExecutableFileObj.imports"))
    if expressions:
        return create_boolean_expression("AND", expressions)


def convert_archive_file_to_pattern(f):
    and_expressions = []
    for prop_spec in select_archive_file_properties():
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(f, prop_1x):
            term = add_comparison_expression(getattr(f, prop_1x), object_path)
            if term:
                and_expressions.append(term)
    if and_expressions:
        return create_boolean_expression("AND", and_expressions)


def convert_hashes_to_pattern(hashes):
    hash_expressions = []
    for h in hashes:
        if getattr(h, "simple_hash_value"):
            hash_value = h.simple_hash_value
        else:
            hash_value = h.fuzzy_hash_value
        if text_type(h.type_).startswith("SHA"):
            hash_type = "'" + "SHA" + "-" + text_type(h.type_)[3:] + "'"
        elif text_type(h.type_) == "SSDEEP":
            hash_type = text_type(h.type_).lower()
        else:
            hash_type = text_type(h.type_)
        try:
            hc = stix2.HashConstant(hash_value.value, text_type(h.type_))
        except ValueError as err:
            # don't cause exception if hash value isn't correct
            warn(err, 626)
            hc = make_constant(hash_value.value)
        hash_expressions.append(create_term("file:hashes" + "." + hash_type,
                                            hash_value.condition,
                                            hc))
    if hash_expressions:
        return create_boolean_expression("OR", hash_expressions)


def convert_file_name_and_file_extension(file_name, file_extension):
    if (file_extension and file_extension.value and is_equal_condition(file_name.condition) and
            is_equal_condition(file_extension.condition) and file_name.value.endswith(file_extension.value)):
        return create_term("file:name", file_name.condition, make_constant(file_name.value))
    elif (file_name.condition == "StartsWith" and file_extension and file_extension.value and
          is_equal_condition(file_extension.condition)):
        return ComparisonExpressionForElevator("MATCHES", "file:name",
                                               make_constant(
                                                   "^" + file_name.value + "*." + file_extension.value + "$"))
    elif (file_name.condition == "Contains" and file_extension and file_extension.value and
          is_equal_condition(file_extension.condition)):
        return ComparisonExpressionForElevator("MATCHES", "file:name",
                                               make_constant(
                                                   file_name.value + "*." + file_extension.value + "$"))
    else:
        warn("Unable to create a pattern for file:file_name from a File object", 620)


def convert_file_name_and_path_to_pattern(f):
    file_name_path_expressions = []
    if f.file_name and f.file_extension and f.file_extension.value:
        file_name_path_expressions.append(convert_file_name_and_file_extension(f.file_name, f.file_extension))
    elif f.file_name:
        file_name_path_expressions.append(create_term("file:name",
                                                      f.file_name.condition,
                                                      make_constant(f.file_name.value)))
    if f.file_path and f.file_path.value:
        index = f.file_path.value.rfind("/")
        if index == -1:
            index = f.file_path.value.rfind("\\")
        if index == -1:
            warn("Ambiguous file path '%s' was not processed", 816, f.file_path.value)
        else:
            if not (f.file_path.value.endswith("/") or f.file_path.value.endswith("\\")):
                file_name_path_expressions.append(create_term("file:name",
                                                              f.file_path.condition,
                                                              make_constant(f.file_path.value[index + 1:])))
                path_string_constant = make_constant(((f.device_path.value if f.device_path else "") +
                                                      f.file_path.value[0: index]))
                file_name_path_expressions.append(create_term("file:parent_directory_ref.path",
                                                              f.file_path.condition,
                                                              path_string_constant))
            else:
                path_string_constant = make_constant(((f.device_path.value if f.device_path else "") +
                                                      f.file_path.value[0: index]))
                file_name_path_expressions.append(create_term("directory:path",
                                                              f.file_path.condition,
                                                              path_string_constant))
    if f.full_path:
        warn("1.x full file paths are not processed, yet", 802)
    if file_name_path_expressions:
        return create_boolean_expression("AND", file_name_path_expressions)


_FILE_PROPERTIES_2_0 = [["size_in_bytes", "file:size"],
                        ["magic_number", "file:magic_number_hex"],
                        ["created_time", "file:created"],
                        ["modified_time", "file:modified"],
                        ["accessed_time", "file:accessed"],
                        ["encyption_algorithm", "file:encyption_algorithm"],
                        ["decryption_key", "file:decryption_key"]]
# is_encrypted

_FILE_PROPERTIES_2_1 = [["size_in_bytes", "file:size"],
                        ["magic_number", "file:magic_number_hex"],
                        ["created_time", "file:created"],
                        ["modified_time", "file:modified"],
                        ["accessed_time", "file:accessed"]]


def select_file_properties():
    if get_option_value("spec_version") == "2.1":
        return _FILE_PROPERTIES_2_1
    else:
        return _FILE_PROPERTIES_2_0


def convert_file_to_pattern(f):
    expressions = []
    if f.hashes is not None:
        hash_expression = convert_hashes_to_pattern(f.hashes)
        if hash_expression:
            expressions.append(hash_expression)
    file_name_and_path_expression = convert_file_name_and_path_to_pattern(f)
    if file_name_and_path_expression:
        expressions.append(file_name_and_path_expression)
    properties_expressions = []
    for prop_spec in select_file_properties():
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(f, prop_1x) and getattr(f, prop_1x):
            term = add_comparison_expression(getattr(f, prop_1x), object_path)
            if term:
                properties_expressions.append(term)
    if properties_expressions:
        expressions.extend(properties_expressions)
    if isinstance(f, WinExecutableFile):
        windows_executable_file_expression = convert_windows_executable_file_to_pattern(f)
        if windows_executable_file_expression:
            expressions.append(windows_executable_file_expression)
        else:
            warn("No WinExecutableFile properties found in %s", 613, text_type(f))
    if isinstance(f, ArchiveFile):
        archive_file_expressions = convert_archive_file_to_pattern(f)
        if archive_file_expressions:
            expressions.append(archive_file_expressions)
        else:
            warn("No ArchiveFile properties found in %s", 614, text_type(f))
    if expressions:
        return create_boolean_expression("AND", expressions)


_REGISTRY_KEY_VALUES_PROPERTIES = [["data", "windows-registry-key:values[*].data"],
                                   ["name", "windows-registry-key:values[*].name"],
                                   ["datatype", "windows-registry-key:values[*].data_type"]]


def convert_registry_key_to_pattern(reg_key):
    expressions = []
    if reg_key.key:
        key_value_term = ""
        if reg_key.hive:
            if reg_key.hive.condition is None or is_equal_condition(reg_key.hive.condition):
                key_value_term += reg_key.hive.value + "\\"
            else:
                warn("Condition %s on a hive property not handled", 812, reg_key.hive.condition)
            if reg_key.key.value.startswith(reg_key.hive.value):
                warn("Hive property, %s, is already a prefix of the key property, %s", 623, reg_key.hive.value,
                     reg_key.key.value)
                key_value_term = reg_key.key.value
            else:
                key_value_term += reg_key.key.value
        else:
            key_value_term = reg_key.key.value
        expressions.append(create_term("windows-registry-key:key",
                                       reg_key.key.condition,
                                       make_constant(key_value_term)))
    if reg_key.values:
        values_expressions = []
        for v in reg_key.values:
            value_expressions = []
            for prop_spec in _REGISTRY_KEY_VALUES_PROPERTIES:
                prop_1x = prop_spec[0]
                object_path = prop_spec[1]
                if hasattr(v, prop_1x) and getattr(v, prop_1x):
                    term = add_comparison_expression(getattr(v, prop_1x), object_path)
                    if term:
                        value_expressions.append(term)
            if value_expressions:
                values_expressions.append(create_boolean_expression("OR", value_expressions))
        expressions.extend(values_expressions)
    if expressions:
        return create_boolean_expression("AND", expressions)


def convert_image_info_to_pattern(image_info):
    expressions = []
    if image_info.command_line:
        expressions.append(add_comparison_expression(image_info.command_line, "process:command_line"))
    if image_info.current_directory:
        expressions.append(add_comparison_expression(image_info.current_directory, "process:cwd"))
    if expressions:
        return create_boolean_expression("AND", expressions)


_PROCESS_PROPERTIES_2_0 = [
    ["is_hidden", "process:is_hidden"],
    ["pid", "process:pid"],
    ["name", "process:name"],
    ["parent_pid", "process:parent_ref.pid"],
    ["username", "process:creator_user_ref.user_id"],
    ["creation_time", "process:created"]
]

_PROCESS_PROPERTIES_2_1 = [
    ["is_hidden", "process:is_hidden"],
    ["pid", "process:pid"],
    ["parent_pid", "process:parent_ref.pid"],
    ["username", "process:creator_user_ref.user_id"],
    ["creation_time", "process:created"]
]


def select_process_properties():
    if get_option_value("spec_version") == "2.1":
        return _PROCESS_PROPERTIES_2_1
    else:
        return _PROCESS_PROPERTIES_2_0


def convert_process_to_pattern(process):
    expressions = []
    for prop_spec in select_process_properties():
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(process, prop_1x) and getattr(process, prop_1x):
            term = add_comparison_expression(getattr(process, prop_1x), object_path)
            if term:
                expressions.append(term)
    if process.image_info:
        process_info = convert_image_info_to_pattern(process.image_info)
        if process_info:
            expressions.append(process_info)
    if hasattr(process, "argument_list") and process.argument_list:
        if get_option_value("spec_version") == "2.0":
            argument_expressions = []
            for a in process.argument_list:
                argument_expressions.append(create_term("process:arguments[*]",
                                                        a.condition,
                                                        stix2.StringConstant(a.value)))
            if argument_expressions:
                expressions.append(create_boolean_expression("AND", argument_expressions))
        else:
            warn("The argument_list property of ProcessObj is not part of STIX 2.1", 418)
            expressions.append(UnconvertedTerm("ProcessObj.argument_list"))
    if hasattr(process, "environment_variable_list") and process.environment_variable_list:
        ev_expressions = []
        for ev in process.environment_variable_list:
            # TODO: handle variable names with '-'
            ev_expressions.append(create_term("process:environment_variables[*]." + str(ev.name),
                                              ev.value.condition,
                                              stix2.StringConstant(str(ev.value))))
        if ev_expressions:
            expressions.append(create_boolean_expression("AND", ev_expressions))
    if hasattr(process, "child_pid_list") and process.child_pid_list:
        child_pids_expressions = []
        for cp in process.child_pid_list:
            child_pids_expressions.append(create_term("process:child_refs[*].pid",
                                                      cp.condition,
                                                      stix2.IntegerConstant(cp.value)))
        if child_pids_expressions:
            expressions.append(create_boolean_expression("AND", child_pids_expressions))
    if hasattr(process, "network_connection_list") and process.network_connection_list:
        network_connection_expressions = []
        for nc in process.network_connection_list:
            new_pattern = convert_network_connection_to_pattern(nc)
            network_connection_expressions.append(
                new_pattern.collapse_reference(stix2.ObjectPath.make_object_path("process:opened_connection_refs[*]")))
        if network_connection_expressions:
            expressions.append(create_boolean_expression("AND", network_connection_expressions))
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


_WINDOWS_PROCESS_PROPERTIES = [
    ["aslr_enabled", "process:extensions.'windows-process-ext'.aslr_enabled"],
    ["dep_enabled", "process:extensions.'windows-process-ext'.dep_enabled"],
    ["priority", "process:extensions.'windows-process-ext'.priority"],
    ["security_id", "process:extensions.'windows-process-ext'.owner_sid"],
    ["window_title", "process:extensions.'windows-process-ext'.window_title"]
]


def convert_windows_process_to_pattern(process):
    expressions = []
    for prop_spec in _WINDOWS_PROCESS_PROPERTIES:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(process, prop_1x) and getattr(process, prop_1x):
            term = add_comparison_expression(getattr(process, prop_1x), object_path)
            if term:
                expressions.append(term)
    if process.handle_list:
        for h in process.handle_list:
            warn("Windows Handles are not a part of STIX 2.0", 420)
    if process.startup_info:
        warn("The startup_info property of ProcessObj is not part of STIX 2.x", 418)
        expressions.append(UnconvertedTerm("ProcessObj.startup_info"))
    if expressions:
        return create_boolean_expression("AND", expressions)


_WINDOWS_SERVICE_PROPERTIES = \
    [["service_name", "process:extensions.'windows-service-ext'.service_name"],
     ["display_name", "process:extensions.'windows-service-ext'.display_name"],
     ["startup_command_line", "process:extensions.'windows-service-ext'.startup_command_line"],
     ["start_type", "process:extensions.'windows-service-ext'.start_type"],
     ["service_type", "process:extensions.'windows-service-ext'.service_type"],
     ["service_status", "process:extensions.'windows-service-ext'.service_status"]]


def convert_windows_service_to_pattern(service):
    expressions = []
    for prop_spec in _WINDOWS_SERVICE_PROPERTIES:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(service, prop_1x) and getattr(service, prop_1x):
            term = add_comparison_expression(getattr(service, prop_1x), object_path)
            if term:
                expressions.append(term)
    if hasattr(service, "description_list") and service.description_list:
        description_expressions = []
        for d in service.description_list:
            description_expressions.append(create_term("process:extensions.'windows-service-ext'.descriptions[*]",
                                                       d.condition,
                                                       make_constant(d.value)))
        if description_expressions:
            expressions.append(create_boolean_expression("OR", description_expressions))
    if hasattr(service, "service_dll") and service.service_dll:
        warn("The service_dll property of WinServiceObject is not part of STIX 2.x", 418)
        expressions.append(UnconvertedTerm("WinServiceObject.service_dll"))
    if expressions:
        return create_boolean_expression("AND", expressions)


def convert_related_object_to_pattern(ro):
    if ro.id_:
        new_pattern = convert_object_to_pattern(ro, ro.id_)
        if new_pattern:
            add_to_pattern_cache(ro.id_, new_pattern)
            return new_pattern
    elif ro.idref:
        if id_in_pattern_cache(ro.idref):
            return get_pattern_from_cache(ro.idref)
        else:
            if id_in_observable_mappings(ro.idref):
                return convert_observable_to_pattern(get_obs_from_mapping(ro.idref))
            return IdrefPlaceHolder(ro.idref)


def convert_domain_name_to_pattern(domain_name, related_objects):
    pattern = [
        create_term("domain-name:value", domain_name.value.condition, make_constant(domain_name.value.value))]
    if related_objects:
        for ro in related_objects:
            if ro.relationship == "Resolved_To":
                new_pattern = convert_related_object_to_pattern(ro)
                if new_pattern:
                    if isinstance(new_pattern, IdrefPlaceHolder):
                        pattern.append(ComparisonExpressionForElevator("=",
                                                                       "domain-name:resolves_to_refs[*]",
                                                                       new_pattern))
                    else:
                        pattern.append(new_pattern.collapse_reference(
                            stix2.ObjectPath.make_object_path("domain-name:resolves_to_refs[*]")))
            else:
                warn("The %s relationship involving %s is not supported in STIX 2.0", 427, ro.relationship,
                     identifying_info(ro))
    return create_boolean_expression("AND", pattern)


def convert_mutex_to_pattern(mutex):
    if mutex.name:
        return create_term("mutex:name", mutex.name.condition, make_constant(mutex.name.value))
    else:
        return None


def convert_network_connection_to_pattern(conn):
    expressions = []

    if conn.layer3_protocol is not None:
        expressions.append(create_term("network-traffic:protocols[*]",
                                       conn.layer3_protocol.condition,
                                       make_constant(conn.layer3_protocol.value.lower())))

    if conn.layer4_protocol is not None:
        expressions.append(create_term("network-traffic:protocols[*]",
                                       conn.layer4_protocol.condition,
                                       make_constant(conn.layer4_protocol.value.lower())))

    if conn.layer7_protocol is not None:
        expressions.append(create_term("network-traffic:protocols[*]",
                                       conn.layer7_protocol.condition,
                                       make_constant(conn.layer7_protocol.value.lower())))

    if conn.source_socket_address is not None:
        if conn.source_socket_address.port is not None:
            if conn.source_socket_address.port.port_value is not None:
                expressions.append(create_term("network-traffic:src_port",
                                               conn.source_socket_address.port.port_value.condition,
                                               stix2.IntegerConstant(int(conn.source_socket_address.port.port_value))))
            if conn.source_socket_address.port.layer4_protocol is not None:
                expressions.append(
                    create_term("network-traffic:protocols[*]",
                                conn.source_socket_address.port.layer4_protocol.condition,
                                make_constant(conn.source_socket_address.port.layer4_protocol.value.lower())))
        if conn.source_socket_address.ip_address is not None:
            expressions.append(
                create_term("network-traffic:src_ref.value",
                            conn.source_socket_address.ip_address.address_value.condition,
                            make_constant(conn.source_socket_address.ip_address.address_value.value)))
        elif conn.source_socket_address.hostname is not None:
            if conn.source_socket_address.hostname.is_domain_name and conn.source_socket_address.hostname.hostname_value is not None:
                expressions.append(
                    create_term("network-traffic:src_ref.value",
                                conn.source_socket_address.hostname.condition,
                                make_constant(conn.source_socket_address.hostname.hostname_value)))
            elif (conn.source_socket_address.hostname.naming_system is not None and
                  any(x.value == "DNS" for x in conn.source_socket_address.hostname.naming_system)):
                expressions.append(
                    create_term("network-traffic:src_ref.value",
                                conn.source_socket_address.hostname.condition,
                                make_constant(conn.source_socket_address.hostname.hostname_value)))

    if conn.destination_socket_address is not None:
        if conn.destination_socket_address.port is not None:
            if conn.destination_socket_address.port.port_value is not None:
                expressions.append(
                    create_term("network-traffic:dst_port",
                                conn.destination_socket_address.port.port_value.condition,
                                stix2.IntegerConstant(int(conn.destination_socket_address.port.port_value))))
            if conn.destination_socket_address.port.layer4_protocol is not None:
                expressions.append(
                    create_term("network-traffic:protocols[*]",
                                conn.destination_socket_address.port.layer4_protocol.condition,
                                make_constant(
                                    conn.destination_socket_address.port.layer4_protocol.value.lower())))
        if conn.destination_socket_address.ip_address is not None:
            expressions.append(
                create_term("network-traffic:dst_ref.value",
                            conn.destination_socket_address.ip_address.address_value.condition,
                            make_constant(conn.destination_socket_address.ip_address.address_value.value)))
        elif conn.destination_socket_address.hostname is not None:
            hostname = conn.destination_socket_address.hostname
            if hostname.is_domain_name and hostname.hostname_value is not None:
                expressions.append(
                    create_term("network-traffic:dst_ref.value",
                                conn.destination_socket_address.hostname.condition,
                                make_constant(conn.destination_socket_address.hostname.hostname_value)))
            elif (conn.destination_socket_address.hostname.naming_system is not None and
                  any(x.value == "DNS" for x in conn.destination_socket_address.hostname.naming_system)):
                expressions.append(
                    create_term("network-traffic:dst_ref.value",
                                conn.destination_socket_address.hostname.condition,
                                make_constant(conn.destination_socket_address.hostname.hostname_value)))

    if conn.layer7_connections is not None:
        if conn.layer7_connections.http_session is not None:
            extension_expressions = convert_http_session_to_pattern(conn.layer7_connections.http_session)
            if extension_expressions:
                expressions.append(extension_expressions)

    return create_boolean_expression("AND", expressions)


def convert_http_client_request_to_pattern(http_request):
    expressions = []
    if http_request.http_request_line is not None:
        if http_request.http_request_line.http_method is not None:
            term = add_comparison_expression(http_request.http_request_line.http_method,
                                             "network-traffic:extensions.'http-request-ext'.request_method")
            if term:
                expressions.append(term)
        if http_request.http_request_line.version is not None:
            term = add_comparison_expression(http_request.http_request_line.version,
                                             "network-traffic:extensions.'http-request-ext'.request_version")
            if term:
                expressions.append(term)
    if http_request.http_request_header is not None:
        if http_request.http_request_header.parsed_header is not None:
            header = http_request.http_request_header.parsed_header

            for prop_spec in _NETWORK_CONNECTION_PROPERTIES:
                prop_1x = prop_spec[0]
                object_path = prop_spec[1]
                if hasattr(header, prop_1x) and getattr(header, prop_1x):
                    value = getattr(header, prop_1x)
                    # handle non-String properties
                    if isinstance(value, Address):
                        value = getattr(value, "address_value")
                    elif isinstance(value, HostField):
                        value = getattr(value, "domain_name").value
                    elif isinstance(value, URI):
                        value = value.value
                    term = add_comparison_expression(value, object_path)
                    if term:
                        expressions.append(term)
    return create_boolean_expression("AND", expressions)


def convert_http_network_connection_extension(http):
    if http.http_client_request is not None:
        return convert_http_client_request_to_pattern(http.http_client_request)


_NETWORK_CONNECTION_PROPERTIES = [
    ["accept", "network-traffic:extensions.'http-request-ext'.request_header.Accept"],
    ["accept_charset", "network-traffic:extensions.'http-request-ext'.request_header.'Accept-Charset'"],
    ["accept_language", "network-traffic:extensions.'http-request-ext'.request_header.'Accept-Language'"],
    ["accept_datetime", "network-traffic:extensions.'http-request-ext'.request_header.'Accept-Datetime'"],
    ["accept_encoding", "network-traffic:extensions.'http-request-ext'.request_header.'Accept-Encoding'"],
    ["authorization", "network-traffic:extensions.'http-request-ext'.request_header.Authorization"],
    ["cache_control", "network-traffic:extensions.'http-request-ext'.request_header.'Cache-Control'"],
    ["connection", "network-traffic:extensions.'http-request-ext'.request_header.Connection"],
    ["cookie", "network-traffic:extensions.'http-request-ext'.request_header.Cookie"],
    ["content_length", "network-traffic:extensions.'http-request-ext'.request_header.'Content-Length'"],
    ["content_md5", "network-traffic:extensions.'http-request-ext'.request_header.'Content-MD5'"],
    ["content_type", "network-traffic:extensions.'http-request-ext'.request_header.'Content-Type'"],
    ["date", "network-traffic:extensions.'http-request-ext'.request_header.Date"],
    ["expect", "network-traffic:extensions.'http-request-ext'.request_header.Expect"],
    ["from_", "network-traffic:extensions.'http-request-ext'.request_header.From"],
    ["host", "network-traffic:extensions.'http-request-ext'.request_header.Host"],
    ["if_match", "network-traffic:extensions.'http-request-ext'.request_header.'If-Match'"],
    ["if_modified_since", "network-traffic:extensions.'http-request-ext'.request_header.'If-Modified-Since'"],
    ["if_none_match", "network-traffic:extensions.'http-request-ext'.request_header.'If-None-Match'"],
    ["if_range", "network-traffic:extensions.'http-request-ext'.request_header.'If-Range'"],
    ["if_unmodified_since", "network-traffic:extensions.'http-request-ext'.request_header.'If-Unmodified-Since'"],
    ["max_forwards", "network-traffic:extensions.'http-request-ext'.request_header.'Max-Forwards'"],
    ["pragma", "network-traffic:extensions.'http-request-ext'.request_header.Pragma"],
    ["proxy_authorization", "network-traffic:extensions.'http-request-ext'.request_header.'Proxy-Authorization'"],
    ["range", "network-traffic:extensions.'http-request-ext'.request_header.Range"],
    ["referer", "network-traffic:extensions.'http-request-ext'.request_header.Referer"],
    ["te", "network-traffic:extensions.'http-request-ext'.request_header.TE"],
    ["user_agent", "network-traffic:extensions.'http-request-ext'.request_header.'User-Agent'"],
    ["via", "network-traffic:extensions.'http-request-ext'.request_header.Via"],
    ["warning", "network-traffic:extensions.'http-request-ext'.request_header.Warning"],
    ["dnt", "network-traffic:extensions.'http-request-ext'.request_header.DNT"],
    ["x_requested_with", "network-traffic:extensions.'http-request-ext'.request_header.'X-Requested-With'"],
    ["x_forwarded_for", "network-traffic:extensions.'http-request-ext'.request_header.'X-Forwarded-For'"],
    ["x_att_deviceid", "network-traffic:extensions.'http-request-ext'.request_header.'X-ATT-DeviceId'"],
    ["x_wap_profile", "network-traffic:extensions.'http-request-ext'.request_header.'X-Wap-Profile'"],
]


def convert_network_packet_to_pattern(packet):
    if packet.internet_layer:
        internet_layer = packet.internet_layer
        if internet_layer.ipv4 or internet_layer.ipv6:
            warn("Internet_Layer/IP_Packet content not supported in STIX 2.0", 424)
        else:
            if internet_layer.icmpv4:
                icmp_header = internet_layer.icmpv4.icmpv4_header
            elif internet_layer.icmpv6:
                icmp_header = internet_layer.icmpv6.icmpv6_header
            else:
                return None
            expressions = []
            if icmp_header.type_:
                expressions.append(create_term("network-traffic:extensions.'icmp-ext'.icmp_type_hex",
                                               icmp_header.type_.condition,
                                               stix2.HexConstant(str(icmp_header.type_))))
            if icmp_header.code:
                expressions.append(create_term("network-traffic:extensions.'icmp-ext'.icmp_type_code",
                                               icmp_header.code.condition,
                                               stix2.HexConstant(str(icmp_header.code))))
            return create_boolean_expression("AND", expressions)


def convert_http_session_to_pattern(session):
    if session.http_request_response:
        requests, responses = split_into_requests_and_responses(session.http_request_response)
        if len(responses) != 0:
            warn("HTTPServerResponse type is not supported in STIX 2.0", 429)
        if len(requests) >= 1:
            expression = convert_http_client_request_to_pattern(requests[0])
            if len(requests) > 1:
                warn("Only HTTP_Request_Response used for http-request-ext, using first value", 512)
            return expression


def convert_socket_options_to_pattern(options):
    expressions = []
    for prop_name in SOCKET_OPTIONS:
        prop = getattr(options, prop_name)
        if prop:
            expressions.append(create_term("network-traffic:extensions.'socket-ext'.options." + prop_name.upper(),
                                           "Equals",
                                           prop))
    return create_boolean_expression("AND", expressions)


_SOCKET_MAP = {
    "is_blocking": "network-traffic:extensions.'socket-ext'.is_blocking",
    "is_listening": "network-traffic:extensions.'socket-ext'.is_listening",
    "type_": "network-traffic:extensions.'socket-ext'.socket_type",
    "domain": "network-traffic:extensions.'socket-ext'.socket_type",
    "socket_descriptor": "network-traffic:extensions.'socket-ext'.socket_descriptor"
}


def convert_network_socket_to_pattern(socket):
    expressions = []
    for prop_spec in _SOCKET_MAP:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(socket, prop_1x) and getattr(socket, prop_1x):
            term = add_comparison_expression(getattr(socket, prop_1x), object_path)
            if term:
                expressions.append(term)
    if socket.address_family:
        if socket.address_family in ADDRESS_FAMILY_ENUMERATION:
            expressions.append(add_comparison_expression(socket.address_family,
                                                         "network-traffic:extensions.'socket-ext'.address_family"))
        else:
            warn("%s in is not a member of the %s enumeration", 627, socket.address_family, "address family")
    if socket.options:
        expressions.append(convert_socket_options_to_pattern(socket.options))
    if socket.local_address:
        warn("Network_Socket.local_address content not supported in STIX 2.0", 424)
    if socket.remote_address:
        warn("Network_Socket.remote_address content not supported in STIX 2.0", 424)
    if socket.protocol:
        expressions.append(add_comparison_expression(socket.protocol,
                                                     "network-traffic:protocols[*]"))
    return create_boolean_expression("AND", expressions)


####################################################################################################################


def convert_observable_composition_to_pattern(obs_comp):
    expressions = []
    for obs in obs_comp.observables:
        term = convert_observable_to_pattern(obs)
        if term:
            expressions.append(term)
    if expressions:
        return create_boolean_expression(obs_comp.operator, expressions)
    else:
        return ""


def convert_object_to_pattern(obj, obs_id):
    related_objects = obj.related_objects
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
            expression = convert_domain_name_to_pattern(prop, related_objects)
        elif isinstance(prop, Mutex):
            expression = convert_mutex_to_pattern(prop)
        elif isinstance(prop, NetworkConnection):
            expression = convert_network_connection_to_pattern(prop)
        elif isinstance(prop, Account):
            expression = convert_account_to_pattern(prop)
        elif isinstance(prop, HTTPSession):
            expression = convert_http_session_to_pattern(prop)
        elif isinstance(prop, NetworkPacket):
            expression = convert_network_packet_to_pattern(prop)
        elif isinstance(prop, NetworkSocket):
            expression = convert_network_socket_to_pattern(prop)
        else:
            warn("%s found in %s cannot be converted to a pattern, yet.", 808, text_type(obj.properties), obs_id)
            expression = UnconvertedTerm(obs_id)

        if prop.custom_properties is not None:
            object_path_root = convert_cybox_class_name_to_object_path_root_name(prop)
            if object_path_root:
                if expression:
                    expression = create_boolean_expression("AND", [expression,
                                                                   convert_custom_properties(prop.custom_properties,
                                                                                             object_path_root)])
                else:
                    expression = convert_custom_properties(prop.custom_properties, object_path_root)
    if not expression:
        warn("No pattern term was created from %s", 422, obs_id)
        expression = UnconvertedTerm(obs_id)
    elif obj.id_:
        add_object_id_value(obj.id_, obs_id)
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


def convert_observable_to_pattern(obs):
    try:
        set_dynamic_variable("current_observable", obs)
        if negate_expression(obs):
            warn("Negation of %s is not handled yet", 810, obs.id_)
        return convert_observable_to_pattern_without_negate(obs)
    finally:
        pop_dynamic_variable("current_observable")


def convert_observable_to_pattern_without_negate(obs):
    if obs.observable_composition is not None:
        pattern = convert_observable_composition_to_pattern(obs.observable_composition)
        if pattern and obs.id_:
            add_to_pattern_cache(obs.id_, pattern)
        return pattern
    elif obs.object_ is not None:
        pattern = convert_object_to_pattern(obs.object_, obs.id_)
        if pattern:
            add_to_pattern_cache(obs.id_, pattern)
        if obs.object_.related_objects:
            related_patterns = []
            for o in obs.object_.related_objects:
                # save pattern for later use
                if o.id_ and not id_in_pattern_cache(o.id_):
                    new_pattern = convert_object_to_pattern(o, o.id_)
                    if new_pattern:
                        related_patterns.append(new_pattern)
                        add_to_pattern_cache(o.id_, new_pattern)
                if pattern:
                    related_patterns.append(pattern)
                return create_boolean_expression("AND", related_patterns)
        else:
            return pattern
    elif obs.idref is not None:
        if id_in_pattern_cache(obs.idref):
            return get_pattern_from_cache(obs.idref)
        else:
            # resolve now if possible, and remove from observed_data
            if id_in_observable_mappings(obs.idref):
                return convert_observable_to_pattern(get_obs_from_mapping(obs.idref))
            return IdrefPlaceHolder(obs.idref)


# patterns can contain idrefs which might need to be resolved because the order in which the ids and idrefs appear
def interatively_resolve_placeholder_refs():
    if pattern_cache_is_empty():
        return
    done = False
    while not done:
        # collect all of the fully resolved idrefs
        fully_resolved_idrefs = []
        for idref, expr in get_items_from_pattern_cache():
            if expr and not expr.contains_placeholder():
                # no PLACEHOLDER idrefs found in the expr, means this idref is fully resolved
                fully_resolved_idrefs.append(idref)
        # replace only fully resolved idrefs
        change_made = False
        for fr_idref in fully_resolved_idrefs:
            for idref, expr in get_items_from_pattern_cache():
                if expr:
                    change_made, expr = expr.replace_placeholder_with_idref_pattern(fr_idref)
                    # a change will be made, which could introduce a new placeholder id into the expr
                    if change_made:
                        add_to_pattern_cache(idref, expr)  # PATTERN_CACHE[idref] = expr
        done = not change_made


def is_placeholder(thing):
    return thing.index("PLACEHOLDER") != -1


def fix_pattern(pattern):
    if not pattern_cache_is_empty():
        # info(text_type(PATTERN_CACHE))
        # info("pattern is: " +  pattern)
        if pattern and pattern.contains_placeholder:
            for idref in get_ids_from_pattern_cache():
                pattern.replace_placeholder_with_idref_pattern(idref)
    return pattern


def convert_indicator_to_pattern(ind):
    try:
        set_dynamic_variable("current_indicator", ind)
        if ind.negate:
            warn("Negation of %s is not handled yet", 810, ind.id_)
        return convert_indicator_to_pattern_without_negate(ind)

    finally:
        pop_dynamic_variable("current_indicator")


def convert_indicator_to_pattern_without_negate(ind):
    if ind.composite_indicator_expression is not None:
        pattern = convert_indicator_composition_to_pattern(ind.composite_indicator_expression)
        if pattern and ind.id_:
            add_to_pattern_cache(ind.id_, pattern)
        return pattern
    elif ind.observable is not None:
        pattern = convert_observable_to_pattern(ind.observable)
        if pattern:
            add_to_pattern_cache(ind.id_, pattern)
        return pattern
    elif ind.idref is not None:
        if id_in_pattern_cache(ind.idref):
            return get_pattern_from_cache(ind.idref)
        else:
            # resolve now if possible, and remove from observed_data
            if id_in_observable_mappings(ind.idref):
                return convert_observable_to_pattern(get_obs_from_mapping(ind.idref))
            return IdrefPlaceHolder(ind.idref)


def convert_indicator_composition_to_pattern(ind_comp):
    expressions = []
    for ind in ind_comp.indicators:
        term = convert_indicator_to_pattern(ind)
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
    for old_id in get_ids_from_pattern_cache():
        new_id = get_id_value(old_id)
        if new_id and len(new_id) == 1:
            all_new_ids_with_patterns.append(new_id[0])

    if not KEEP_OBSERVABLE_DATA_USED_IN_PATTERNS:
        remaining_objects = []
        for obj in bundle_instance["objects"]:
            if obj["type"] != "observed-data" or obj["id"] not in all_new_ids_with_patterns:
                remaining_objects.append(obj)
            else:
                warn("%s is used as a pattern, therefore it is not included as an observed_data instance", 423,
                     obj["id"])
        bundle_instance["objects"] = remaining_objects

    if not KEEP_OBSERVABLE_DATA_USED_IN_PATTERNS:
        for obj in bundle_instance["objects"]:
            if obj["type"] == "report":
                remaining_object_refs = []
                if "object_refs" in obj:
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
