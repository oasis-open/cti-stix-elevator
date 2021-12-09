# Standard Library
import copy
import datetime
import re
import sys

# external
from cybox.common.hashes import Hash
from cybox.objects.account_object import Account
from cybox.objects.address_object import Address
from cybox.objects.archive_file_object import ArchiveFile
from cybox.objects.artifact_object import Artifact
from cybox.objects.as_object import AutonomousSystem
from cybox.objects.custom_object import Custom
from cybox.objects.domain_name_object import DomainName
from cybox.objects.email_message_object import EmailMessage
from cybox.objects.file_object import File
from cybox.objects.hostname_object import Hostname
from cybox.objects.http_session_object import HostField, HTTPSession
from cybox.objects.image_file_object import ImageFile
from cybox.objects.mutex_object import Mutex
from cybox.objects.network_connection_object import NetworkConnection
from cybox.objects.network_packet_object import NetworkPacket
from cybox.objects.network_socket_object import NetworkSocket
from cybox.objects.pdf_file_object import PDFFile
from cybox.objects.port_object import Port
from cybox.objects.process_object import Process
from cybox.objects.product_object import Product
from cybox.objects.socket_address_object import SocketAddress
from cybox.objects.unix_user_account_object import UnixUserAccount
from cybox.objects.uri_object import URI
from cybox.objects.win_computer_account_object import WinComputerAccount
from cybox.objects.win_executable_file_object import WinExecutableFile
from cybox.objects.win_process_object import WinProcess
from cybox.objects.win_registry_key_object import WinRegistryKey
from cybox.objects.win_service_object import WinService
from cybox.objects.x509_certificate_object import X509Certificate
import stix2
from stix2.patterns import (
    ListConstant, ObjectPath, ObservationExpression,
    QualifiedObservationExpression, _BooleanExpression, _ComparisonExpression,
    _CompoundObservationExpression, _Constant
)
import stixmarx

# internal
from stix2elevator.common import (
    ADDRESS_FAMILY_ENUMERATION, PDF_DOC_INFO, PDF_DOC_INFO_DICT,
    SOCKET_OPTIONS, determine_socket_address_direction
)
from stix2elevator.convert_cybox import split_into_requests_and_responses
from stix2elevator.ids import (
    add_id_value, exists_id_of_obs_in_characterizations, exists_object_id_key,
    get_id_value
)
from stix2elevator.missing_policy import (
    check_for_missing_policy, convert_to_custom_name,
    get_extension_definition_id
)
from stix2elevator.options import error, get_option_value, info, warn
from stix2elevator.utils import (
    encode_in_base64, identifying_info, map_vocabs_to_label
)
from stix2elevator.vocab_mappings import WINDOWS_PEBINARY

if sys.version_info > (3,):
    long = int

KEEP_OBSERVABLE_DATA_USED_IN_PATTERNS = False

KEEP_INDICATORS_USED_IN_COMPOSITE_INDICATOR_EXPRESSION = True


# class BasicObjectPathComponentForElevator(BasicObjectPathComponent):
#     @staticmethod
#     def create_ObjectPathComponent(component_name):
#         if component_name.endswith("_ref"):
#             return ReferenceObjectPathComponentForElevator(component_name)
#         elif component_name.find("[") != -1:
#             parse1 = component_name.split("[")
#             return ListObjectPathComponentForElevator(parse1[0], parse1[1][:-1])
#         else:
#             return BasicObjectPathComponentForElevator(component_name, False)
#
#     def get_property(self):
#         return self.component_name
#
#
# class ListObjectPathComponentForElevator(ListObjectPathComponent):
#     @staticmethod
#     def create_ObjectPathComponent(component_name):
#         if component_name.endswith("_ref"):
#             return ReferenceObjectPathComponentForElevator(component_name)
#         elif component_name.find("[") != -1:
#             parse1 = component_name.split("[")
#             return ListObjectPathComponentForElevator(parse1[0], parse1[1][:-1])
#         else:
#             return BasicObjectPathComponentForElevator(component_name, False)
#
#
# class ReferenceObjectPathComponentForElevator(ReferenceObjectPathComponent):
#     @staticmethod
#     def create_ObjectPathComponent(component_name):
#         if component_name.endswith("_ref"):
#             return ReferenceObjectPathComponentForElevator(component_name)
#         elif component_name.find("[") != -1:
#             parse1 = component_name.split("[")
#             return ListObjectPathComponentForElevator(parse1[0], parse1[1][:-1])
#         else:
#             return BasicObjectPathComponentForElevator(component_name, False)
#
#     def get_property(self):
#         return self.property_name


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
                elif x.property_name == "created":
                    x.property_name = "ctime"
                elif x.property_name == "modified":
                    x.property_name = "mtime"
                elif x.property_name == "accessed":
                    x.property_name = "atime"
            elif current_cyber_observable_type == "directory":
                if x.property_name == "contains_refs":
                    # TODO - what if it is a directory?
                    current_cyber_observable_type = "file"
                elif x.property_name == "created":
                    x.property_name = "ctime"
                elif x.property_name == "modified":
                    x.property_name = "mtime"
                elif x.property_name == "accessed":
                    x.property_name = "atime"
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
            elif current_cyber_observable_type == "windows-registry-key":
                if x.property_name == "modified":
                    x.property_name = "modified_time"
        return self

    def get_property(self):
        return str(self)

    @staticmethod
    def make_object_path(lhs):
        """Create ObjectPath from string encoded object path

        Args:
            lhs (str): object path of left-hand-side component of expression
        """
        path_as_parts = lhs.split(":")
        return ObjectPathForElevator(path_as_parts[0], path_as_parts[1].split("."))


class ComparisonExpressionForElevator(_ComparisonExpression):
    # overrides, so IdrefPlaceHolder can be handled
    def __init__(self, operator, lhs, rhs, negated=False):
        self.operator = operator
        if operator == "=" and isinstance(rhs, stix2.ListConstant):
            warn("apply_condition assumed to be 'ANY' in %s",
                 721, identifying_info(get_dynamic_variable("current_observable")))
            self.operator = "IN"
        if isinstance(lhs, ObjectPathForElevator):
            self.lhs = lhs
        else:
            self.lhs = ObjectPathForElevator.make_object_path(lhs)
        # rhs might be a reference to another object, which has its own observable pattern
        if isinstance(rhs, _Constant) or isinstance(rhs, IdrefPlaceHolder):
            self.rhs = rhs
        else:
            self.rhs = make_constant(rhs)
        self.negated = negated
        self.root_types = {self.lhs.object_type_name}

    def contains_placeholder(self):
        return isinstance(self.rhs, IdrefPlaceHolder)

    def collapse_reference(self, prefix):
        new_lhs = copy.deepcopy(prefix).merge(self.lhs)
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

    def contains_observation_expressions(self):
        return False

    def contains_unconverted_term(self):
        return False

    def get_property(self):
        return self.lhs.get_property()

    def any_operand_contains_observed_expressions(self):
        return False

    def wrap_as_observed_expression(self):
        return ObservationExpressionForElevator(self)

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


def new_property(term, current_subs):
    property_to_check = term.get_property()
    op = None
    if isinstance(term, ComparisonExpressionForElevator):
        op = term.operator
    if property_to_check and property_to_check.find("*") == -1 and op == "=":
        for sub in current_subs:
            if property_to_check == sub.get_property():
                return False
    return True


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
                if hasattr(new_operand, "root_types"):
                    if self.operator == "AND":
                        self.root_types &= new_operand.root_types
                    else:
                        self.root_types |= new_operand.root_types
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
            term = term.partition_according_to_object_path()
            # see which subexpression to add to, if any
            for sub in subexpressions:
                if self.operator == "AND":
                    new_root_types = term.root_types & sub[0].root_types
                    if new_root_types and new_property(term, sub):
                        sub.append(term)
                        for s in sub:
                            s.root_types = new_root_types.copy()
                        term_was_appended = True
                        break
                elif self.operator == "OR":
                    if sub[0].root_types and term.root_types:
                        new_root_types = term.root_types | sub[0].root_types
                        sub.append(term)
                        for s in sub:
                            s.root_types = new_root_types.copy()
                        term_was_appended = True
                        break
            # it wasn't added to any current subexpression, add it as new subexpression
            if not term_was_appended:
                subexpressions.append([term])
        for x in subexpressions:
            if len(x) == 1:
                results.append(x[0])
            else:
                results.append(create_boolean_expression(self.operator, x, use_parens=False))
        if len(results) == 1:
            return results[0]
        else:
            return CompoundObservationExpressionForElevator(self.operator, results)

    def contains_observation_expressions(self):
        return False

    def contains_unconverted_term(self):
        for args in self.operands:
            if args.contains_unconverted_term():
                return True
        return False

    def get_property(self):
        return None

    def any_operand_contains_observed_expressions(self):
        for operand in self.operands:
            if operand.any_operand_contains_observed_expressions():
                return True
        return False

    def wrap_as_observed_expression(self):
        return CompoundObservationExpressionForElevator(self.operator, self.operands)

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

    def contains_observation_expressions(self):
        return False

    def replace_placeholder_with_idref_pattern(self, idref):
        if idref == self.idref:
            return True, get_pattern_from_cache(idref)
        elif exists_object_id_key(self.idref) and idref == get_id_value(self.idref):
            return True, get_pattern_from_cache(idref)
        else:
            return False, self

    def partition_according_to_object_path(self):
        error("Placeholder %s should be resolved", 203, self.idref)
        return self

    def any_operand_contains_observed_expressions(self):
        return False

    def contains_unconverted_term(self):
        return False


class UnconvertedTerm(object):
    def __init__(self, term_info, root_type=None):
        self.term_info = term_info
        if root_type:
            self.root_types = {root_type}
        else:
            self.root_types = {"unknown"}

    def __str__(self):
        return "unconverted_term:%s" % self.term_info

    def contains_placeholder(self):
        return False

    def replace_placeholder_with_idref_pattern(self, idref):
        return False, self

    def partition_according_to_object_path(self):
        return self

    def any_operand_contains_observed_expressions(self):
        return False

    def contains_unconverted_term(self):
        return True

    def contains_observation_expressions(self):
        return False

    def get_property(self):
        return None


class ObservationExpressionForElevator(ObservationExpression):
    def toSTIX21(self):
        self.operand.toSTIX21()
        return self

    def contains_observation_expressions(self):
        return True

    def any_operand_contains_observed_expressions(self):
        return True


class CompoundObservationExpressionForElevator(_CompoundObservationExpression):
    def __str__(self):
        sub_exprs = []
        if len(self.operands) == 1:
            return "[%s]" % self.operands[0]
        for o in self.operands:
            if o.contains_observation_expressions():
                sub_exprs.append("%s" % o)
            else:
                sub_exprs.append("[%s]" % o)
        return (" " + self.operator + " ").join(sub_exprs)

    def contains_observation_expressions(self):
        return True

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

    def get_property(self):
        return None

    def replace_placeholder_with_idref_pattern(self, idref):
        new_operands = []
        change_made = False
        for args in self.operands:
            change_made_this_time, new_operand = args.replace_placeholder_with_idref_pattern(idref)
            if change_made_this_time:
                if self.root_types and hasattr(new_operand, "root_types"):
                    if self.operator == "AND":
                        self.root_types &= new_operand.root_types
                    else:
                        self.root_types |= new_operand.root_types
            change_made = change_made or change_made_this_time
            new_operands.append(new_operand)
        self.operands = new_operands
        return change_made, self

    def any_operand_contains_observed_expressions(self):
        return True

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

    def any_operand_contains_observed_expressions(self):
        return True

    def toSTIX21(self):
        self.observation_expression.toSTIX21()
        return self


class ParentheticalExpressionForElevator(stix2.ParentheticalExpression):
    def __init__(self, exp):
        super().__init__(exp)

    def contains_placeholder(self):
        return self.expression.contains_placeholder()

    def contains_unconverted_term(self):
        return self.expression.contains_unconverted_term()

    def replace_placeholder_with_idref_pattern(self, idref):
        change_made, new_expression = self.expression.replace_placeholder_with_idref_pattern(idref)
        self.expression = new_expression
        if hasattr(new_expression, "root_types"):
            self.root_types = new_expression.root_types.copy()
        return change_made, self

    def collapse_reference(self, prefix):
        new_expression = self.expression.collapse_reference(prefix)
        return ParentheticalExpressionForElevator(new_expression)

    def partition_according_to_object_path(self):
        self.expression = self.expression.partition_according_to_object_path()
        return self

    def contains_observation_expressions(self):
        return self.expression.contains_observation_expressions()

    def get_property(self):
        # TODO: there could be a similar property within the parenthetical expression
        return None

    def any_operand_contains_observed_expressions(self):
        return self.expression.any_operand_contains_observed_expressions()

    def wrap_as_observed_expression(self):
        return ObservationExpressionForElevator(self)

    def toSTIX21(self):
        self.expression.toSTIX21()
        return self


def create_boolean_expression(operator, operands, use_parens=True):
    if len(operands) == 1:
        return operands[0]
    elif len(operands) == 0:
        return None
    exp = BooleanExpressionForElevator(operator, [])
    exp.root_types = set()
    for arg in operands:
        if not isinstance(arg, IdrefPlaceHolder):
            if exp.operator == "AND":
                if not exp.root_types:
                    exp.root_types = arg.root_types.copy()
                else:
                    exp.root_types &= arg.root_types
            else:
                exp.root_types |= arg.root_types
        exp.add_operand(arg)
    if use_parens:
        pexp = ParentheticalExpressionForElevator(exp)
        if hasattr(exp, "root_types"):
            pexp.root_types = exp.root_types.copy()
        return pexp
    else:
        return exp


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
        if obs.id_:
            _OBSERVABLE_MAPPINGS[obs.id_] = obs
        if hasattr(obs.object_, "id_") and obs.object_.id_:
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
                       "URI": "url",
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
        warn("No condition given for term in %s - assume '='", 714,
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
        rhs.value = "%s$" % rhs.value
    return ComparisonExpressionForElevator("MATCHES", lhs, rhs, negated)


def create_term_with_range(lhs, condition, rhs, negated=False):
    # TODO: handle negated
    if not isinstance(rhs, stix2.ListConstant) or len(rhs.value) != 2:
        error("%s was used, but two values were not provided.", 609, condition)
        return "'range term underspecified'"
    else:
        if condition == "InclusiveBetween":
            # return "(" + lhs + " GE " + str(rhs[0]) + " AND " + lhs + " LE " + str(rhs[1]) + ")"
            lower_bound = ComparisonExpressionForElevator(process_comparison_negation(">=", negated), lhs, rhs.value[0])
            upper_bound = ComparisonExpressionForElevator(process_comparison_negation("<=", negated), lhs, rhs.value[1])

        else:  # "ExclusiveBetween"
            # return "(" + lhs + " GT " + str(rhs[0]) + " AND " + lhs + " LT " + str(rhs[1]) + ")"
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
        if condition == "Contains" and not isinstance(rhs, ListConstant):
            # for substring matches
            info("Used MATCHES operator for %s", 715, condition)
            return create_term_with_regex(lhs, condition, rhs, negated)
        elif condition == "DoesNotContain":
            info("Used MATCHES operator for %s", 715, condition)
            return create_term_with_regex(lhs, condition, rhs, not negated)
        elif condition == "FitsPattern":
            info("Used MATCHES operator for %s", 715, condition)
            return create_term_with_regex(lhs, condition, rhs, negated)
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


def convert_custom_properties(cps, object_type_name, use_custom_prefix=True):
    expressions = []
    for cp in cps.property_:
        if not re.match("[a-z0-9_]+", cp.name):
            warn("The custom property name %s does not adhere to the specification rules", 617, cp.name)
            if " " in cp.name:
                info("The custom property name %s contains whitespace, replacing it with underscores", 624, cp.name)
        custom_name = cp.name.replace(" ", "_")
        if use_custom_prefix:
            custom_name = convert_to_custom_name(cp.name.replace(" ", "_"))
        expressions.append(
            create_term(object_type_name + ":" + custom_name, cp.condition, make_constant(cp.value)))
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
            warn("No UnixUserAccount properties found in %s", 615, str(account))
    elif isinstance(account, WinComputerAccount):
        expressions.append(create_term("user-account:account_type",
                                       "Equals",
                                       stix2.StringConstant("windows-domain" if account.domain else "windows-local")))
    if expressions:
        return create_boolean_expression("AND", expressions)


def convert_artifact_to_pattern(art):
    expressions = []
    if art.content_type:
        expressions.append(create_term("artifact:mime_type", art.content_type.condition, art.content_type))
    if art.raw_artifact:
        expressions.append(create_term("artifact:payload_bin", art.raw_artifact.condition, art.raw_artifact.value))
    if art.raw_artifact_reference:
        expressions.append(create_term("artifact:url", art.raw_artifact_reference.condition, art.raw_artifact_reference.value))
    if art.hashes:
        expressions.append(convert_hashes_to_pattern(art.hashes))
    # TODO: Packaging
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
                                       stix2.StringConstant(str(account.user_id.value))))
    for prop_spec in _UNIX_ACCOUNT_PROPERTIES:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(account, prop_1x) and getattr(account, prop_1x):
            term = add_comparison_expression(getattr(account, prop_1x), object_path)
            if term:
                expressions.append(term)
    if expressions:
        return create_boolean_expression("AND", expressions)


def handle_object_reference_for_pattern(obj1x_obj_ref):
    pattern = handle_pattern_idref(obj1x_obj_ref)
    return pattern


def convert_address_to_pattern(add):
    if add.address_value is None:
        if add.object_reference is None:
            return None
        else:
            return handle_object_reference_for_pattern(add.object_reference)
    cond = add.address_value.condition
    if add.category == add.CAT_IPV4:
        return create_term("ipv4-addr:value", cond, make_constant(add.address_value.value))
    elif add.category == add.CAT_IPV6:
        return create_term("ipv6-addr:value", cond, make_constant(add.address_value.value))
    elif add.category == add.CAT_MAC:
        return create_term("mac-addr:value", cond, make_constant(add.address_value.value))
    elif add.category == add.CAT_EMAIL:
        return create_term("email-addr:value", cond, make_constant(add.address_value.value))
    else:
        warn("The address type %s is not part of Cybox 3.0", 421, add.category)


def convert_as_to_pattern(a_s):
    expressions = []
    if a_s.number:
        expressions.append(add_comparison_expression(a_s.number, "autonomous-system:number"))
    if a_s.name:
        expressions.append(add_comparison_expression(a_s.name, "autonomous-system:name"))
    if a_s.regional_internet_registry:
        expressions.append(add_comparison_expression(a_s.regional_internet_registry, "autonomous-system:rir"))
    if expressions:
        return create_boolean_expression("AND", expressions)


def convert_uri_to_pattern(uri):
    return create_term("url:value", uri.value.condition, make_constant(uri.value.value))


# NOTICE:  The format of these PROPERTIES is different than the others in this file!!!!!!
_EMAIL_HEADER_PROPERTIES = [["email-message:subject", ["subject"]],
                            ["email-message:from_ref.value", ["from_", "address_value"]],
                            ["email-message:sender_ref.value", ["sender", "address_value"]],
                            ["email-message:date", ["date"]],
                            ["email-message:content_type", ["content_type"]],
                            ["email-message:to_refs[*].value", ["to*", "address_value"]],
                            ["email-message:cc_refs[*].value", ["cc*", "address_value"]],
                            ["email-message:bcc_refs[*].value", ["bcc*", "address_value"]],
                            ]


_EMAIL_ADDITIONAL_HEADERS_PROPERTIES = \
    [["email-message:additional_header_fields.Reply-To", ["reply-to*", "address_value"]],
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
        canonical_prop1x_name = cannonicalize_prop_name(prop_1x)
        if hasattr(obj, canonical_prop1x_name):
            if multi_valued_property(prop_1x):
                prop_exprs = []
                for c in getattr(obj, canonical_prop1x_name):
                    term = add_comparison_expression(c, object_path)
                    if term:
                        prop_exprs.append(term)
                # return " OR ".join(prop_exprs)
                if prop_exprs:
                    return create_boolean_expression("OR", prop_exprs)
            else:
                return add_comparison_expression(getattr(obj, canonical_prop1x_name), object_path)
    else:
        prop_1x, rest_of_prop_list = prop_list[0], prop_list[1:]
        canonical_prop1x_name = cannonicalize_prop_name(prop_1x)
        if hasattr(obj, canonical_prop1x_name):
            if multi_valued_property(prop_1x):
                prop_exprs = []
                values = getattr(obj, canonical_prop1x_name)
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
                                                   getattr(obj, canonical_prop1x_name),
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
    return handle_object_reference_for_pattern(attachment.object_reference)


def handle_message_id_property(head):
    if head.message_id:
        if get_option_value("spec_version") == "2.1":
            lhs = "email-message:message_id"
        else:
            lhs = generate_lhs_for_missing_property("email-message:", None, "message_id", "email-message")
        if lhs:
            return create_term(lhs, head.message_id.condition, stix2.StringConstant(str(head.message_id)))


def convert_email_message_to_pattern(mess):
    expressions = []
    if mess.header is not None:
        expressions.append(convert_email_header_to_pattern(mess.header, _EMAIL_HEADER_PROPERTIES))
        message_id_term = handle_message_id_property(mess.header)
        if message_id_term:
            expressions.append(message_id_term)
        add_headers = convert_email_header_to_pattern(mess.header, _EMAIL_ADDITIONAL_HEADERS_PROPERTIES)

        if add_headers:
            expressions.append(add_headers)
    if mess.attachments is not None:
        for attachment in mess.attachments:
            new_pattern = convert_attachment_to_ref(attachment)
            if isinstance(new_pattern, IdrefPlaceHolder):
                expressions.append(ComparisonExpressionForElevator("=", "email-message:body_multipart[*].body_raw_ref",
                                                                   new_pattern))
            else:
                expressions.append(new_pattern.collapse_reference(
                    ObjectPathForElevator.make_object_path("email-message:body_multipart[*].body_raw_ref")))
    if mess.raw_body is not None:
        if not mess.raw_body.value:
            warn("%s contains no value", 621, "Email raw body")
        else:
            warn("Email raw body not handled yet", 806)
    if mess.links is not None:
        if get_option_value("spec_version") == "2.1":
            lhs = generate_lhs_for_missing_property("email-message:", None, "link_refs[*].value", "email-message")
            if lhs:
                # we use the property-name "link_refs" to be consistent with the SCO, even though here its the actual url
                for link in mess.links:
                    if id_in_observable_mappings(link.object_reference):
                        referenced_obs = get_obs_from_mapping(link.object_reference)
                        exp = convert_observable_to_pattern(referenced_obs)
                        rhs = exp.rhs
                    else:
                        rhs = IdrefPlaceHolder(link.object_reference)
                    expressions.append(
                        ComparisonExpressionForElevator("=", lhs, rhs))
            else:
                warn("Email links not handled yet", 806)
        else:
            warn("Observed Data objects cannot refer to other external objects (in STIX 2.0): %s in %s",
                 434, "links", "email-message")
    if expressions:
        return create_boolean_expression("AND", expressions)


_PE_FILE_HEADER_PROPERTIES = \
    [["machine", "file:extensions.'windows-pebinary-ext'.machine_hex"],
     ["time_date_stamp", "file:extensions.'windows-pebinary-ext'.time_date_stamp"],
     ["number_of_sections", "file:extensions.'windows-pebinary-ext'.number_of_sections"],
     ["pointer_to_symbol_table", "file:extensions.'windows-pebinary-ext'.pointer_to_symbol_table"],
     ["number_of_symbols", "file:extensions.'windows-pebinary-ext'.number_of_symbols"],
     ["size_of_optional_header", "file:extensions.'windows-pebinary-ext'.size_of_optional_header"],
     ["characteristics", "file:extensions.'windows-pebinary-ext'.characteristics_hex"]]


_PE_SECTION_HEADER_PROPERTIES = [["name", "file:extensions.'windows-pebinary-ext'.sections[*].name"],
                                 ["virtual_size", "file:extensions.'windows-pebinary-ext'.sections[*].size"]]


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
                    if check_for_missing_policy("use-custom-properties"):
                        section_expressions.append(
                            create_term("file:extensions.'windows-pebinary-ext'.sections[*]." +
                                        convert_to_custom_name("entropy_min"),
                                        s.entropy.min.condition,
                                        stix2.FloatConstant(s.entropy.min.value)))
                        warn("Used custom property for %s", 308, "entropy_min")
                    elif check_for_missing_policy("use-extensions"):
                        warn(
                            "Missing entropy min %s is ignored, because it can't be represented using the extensions policy",
                            314)
                    else:
                        warn("Entropy.min is not supported in STIX 2.x", 424)
                if s.entropy.max:
                    if check_for_missing_policy("use-custom-properties"):
                        section_expressions.append(
                            create_term("file:extensions.'windows-pebinary-ext'.sections[*]." +
                                        convert_to_custom_name("entropy_max"),
                                        s.entropy.max.condition,
                                        stix2.FloatConstant(s.entropy.max.value)))
                        warn("Used custom property for %s", 308, "entropy_max")
                    elif check_for_missing_policy("use-extensions"):
                        warn(
                            "Missing entropy max %s is ignored, because it can't be represented using the extensions policy",
                            314)
                    else:
                        warn("Entropy.max is not supported in STIX 2.x", 424)
                if s.entropy.value:
                    section_expressions.append(create_term("file:extensions.'windows-pebinary-ext'.sections[*].entropy",
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
        lhs = generate_lhs_for_missing_property("file:", "windows-pebinary-ext", "exports[*]", "file")
        if lhs:
            export_expressions = list()
            if hasattr(f.exports, "exported_functions"):
                for export_func in f.exports.exported_functions:
                    export_expressions.append(
                        create_term(lhs,
                                    export_func.function_name.condition,
                                    stix2.StringConstant(export_func.function_name.value)))
            if export_expressions:
                expressions.append(create_boolean_expression("AND", export_expressions))
        else:
            if not check_for_missing_policy("ignore"):
                expressions.append(UnconvertedTerm("WinExecutableFileObj.exports", "file"))
    if f.imports:
        warn("The imports property of WinExecutableFileObj is not part of STIX 2.x", 418)
        lhs = generate_lhs_for_missing_property("file:", "windows-pebinary-ext", "imports[*]", "file")
        if lhs:
            import_expressions = list()
            for i in f.imports:
                if hasattr(i, "imported_functions"):
                    file_name = i.file_name + ":" if hasattr(i, "file_name") and i.file_name else ""
                    for imported_func in i.imported_functions:
                        import_expressions.append(
                            create_term(lhs,
                                        imported_func.function_name.condition,
                                        stix2.StringConstant(file_name + imported_func.function_name.value)))
            if import_expressions:
                expressions.append(create_boolean_expression("AND", import_expressions))
        else:
            if not check_for_missing_policy("ignore"):
                expressions.append(UnconvertedTerm("WinExecutableFileObj.imports", "file"))
    if expressions:
        return create_boolean_expression("AND", expressions)


_ARCHIVE_FILE_PROPERTIES_2_0 = [["comment", "file:extensions.'archive-ext'.comment"],
                                ["version", "file:extensions.'archive-ext'.version"]]

_ARCHIVE_FILE_PROPERTIES_2_1 = [["comment", "file:extensions.'archive-ext'.comment"]]


def select_archive_file_properties():
    if get_option_value("spec_version") == "2.1":
        return _ARCHIVE_FILE_PROPERTIES_2_1
    else:
        return _ARCHIVE_FILE_PROPERTIES_2_0


def convert_archive_file_to_pattern(f):
    and_expressions = []
    for prop_spec in select_archive_file_properties():
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(f, prop_1x):
            term = add_comparison_expression(getattr(f, prop_1x), object_path)
            if term:
                and_expressions.append(term)
    if f.archived_file:
        archived_file_expressions = []
        for a_f in f.archived_file:
            terms = convert_file_to_pattern(a_f)
            archived_file_expressions.append(terms.collapse_reference(ObjectPathForElevator.make_object_path("file:extensions.archive-ext.contains_refs[*]")))
        if archived_file_expressions:
            and_expressions.append(create_boolean_expression("AND", archived_file_expressions))
    if and_expressions:
        return create_boolean_expression("AND", and_expressions)


_IMAGE_FILE_PROPERTIES = \
    [
        ["image_height", "file:extensions.'raster-image-ext'.image_height"],
        ["image_width", "file:extensions.'raster-image-ext'.image_width"],
        ["bits_per_pixel", "file:extensions.'raster-image-ext'.bits_per_pixel"],
    ]


def convert_image_file_to_pattern(f):
    and_expressions = []
    for prop_spec in _IMAGE_FILE_PROPERTIES:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(f, prop_1x):
            term = add_comparison_expression(getattr(f, prop_1x), object_path)
            if term:
                and_expressions.append(term)
    if and_expressions:
        return create_boolean_expression("AND", and_expressions)


def convert_pdf_file_to_pattern(f):
    and_expressions = []
    file_ids = list()
    if f.version:
        and_expressions.append(create_term("file:extensions.'pdf-ext'.version",
                                           f.version.condition,
                                           make_constant(f.version.value)))
    if f.metadata:
        if f.metadata.optimized:
            and_expressions.append(create_term("file:extensions.'pdf-ext'.is_optimized",
                                               f.metadata.optimized.condition,
                                               make_constant(f.metadata.optimized.value)))
        if f.metadata.document_information_dictionary:
            dict1x = f.metadata.document_information_dictionary
            for key in PDF_DOC_INFO:
                value = getattr(dict1x, key, None)
                if value:
                    and_expressions.append(create_term("file:extensions.'pdf-ext'.document_info_dict." + PDF_DOC_INFO_DICT[key],
                                                       value.condition,
                                                       make_constant(value.value)))
    if f.trailers:
        count = 0
        for t in f.trailers:
            if t.id_:
                for file_id in t.id_.id_string:
                    if count == 2:
                        warn("Only two pdfids are allowed for %s, dropping %s", 505, f.id_, file_id)
                    file_ids.append(file_id)
                    count += 1
        if len(file_ids) == 2:
            and_expressions.append(create_term("file:extensions.'pdf-ext'.pdfid0",
                                               file_ids[0].condition,
                                               make_constant(file_ids[0].value)))
            and_expressions.append(create_term("file:extensions.'pdf-ext'.pdfid1",
                                               file_ids[1].condition,
                                               make_constant(file_ids[1].value)))
        elif len(file_ids) == 1:
            and_expressions.append(create_term("file:extensions.'pdf-ext'.pdfid0",
                                               file_ids[0].condition,
                                               make_constant(file_ids[0].value)))
    if and_expressions:
        return create_boolean_expression("AND", and_expressions)


def determine_hash_type(hash):
    if getattr(hash, "simple_hash_value"):
        hashlen = len(hash.simple_hash_value.value)
        if hashlen == 32:
            return Hash.TYPE_MD5
        elif hashlen == 40:
            return Hash.TYPE_SHA1
        elif hashlen == 56:
            return Hash.TYPE_SHA224
        elif hashlen == 64:
            return Hash.TYPE_SHA256
        elif hashlen == 96:
            return Hash.TYPE_SHA384
        elif hashlen == 128:
            return Hash.TYPE_SHA512
        else:
            return Hash.TYPE_OTHER
    else:
        if getattr(hash, "fuzzy_hash_value"):
            return Hash.TYPE_SSDEEP
        else:
            warn("Unable to determine the hash type for %s", 640, hash)


def convert_hashes_to_pattern(hashes):
    # hash_type is used in the pattern.  The argument to stix2.HashConstant is not the same
    # if no type given, use determine_hash_type based on the size of the hash
    hash_expressions = []

    for h in hashes:
        original_hash_type = h.type_ if h.type_ else determine_hash_type(h)
        if getattr(h, "simple_hash_value"):
            hash_value = h.simple_hash_value
        else:
            hash_value = h.fuzzy_hash_value
        original_hash_type_as_string = str(original_hash_type)
        if original_hash_type_as_string.startswith("SHA"):
            hash_type = "'" + "SHA" + "-" + original_hash_type_as_string[3:] + "'"
        elif original_hash_type_as_string == "SSDEEP":
            hash_type = original_hash_type_as_string.lower()
        else:
            hash_type = original_hash_type_as_string
        try:
            hc = stix2.HashConstant(hash_value.value, original_hash_type_as_string)
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
    # TODO: do we need to handle "EndsWith"
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
            if not f.file_path.value.endswith("/") and not f.file_path.value.endswith("\\") and not f.file_name:
                file_name_path_expressions.append(create_term("file:name",
                                                              f.file_path.condition,
                                                              make_constant(f.file_path.value[index + 1:])))
                path_string_constant = make_constant(((f.device_path.value if f.device_path else "") +
                                                      f.file_path.value[0: index]))
                if path_string_constant == '':
                    warn("File path directory is empty %s", 633, f.file_path.value)
                file_name_path_expressions.append(create_term("file:parent_directory_ref.path",
                                                              f.file_path.condition,
                                                              path_string_constant))
            elif f.file_name:
                path_string_constant = make_constant(((f.device_path.value if f.device_path else "") +
                                                      f.file_path.value))
                if path_string_constant == '':
                    warn("File path directory is empty %s", 633, f.file_path.value)
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
        warn("STIX 1.x full file paths are not processed, yet", 802)
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
                        ["created_time", "file:ctime"],
                        ["modified_time", "file:mtime"],
                        ["accessed_time", "file:atime"]]


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
            warn("No WinExecutableFile properties found in %s", 613, str(f))
    if isinstance(f, ArchiveFile):
        archive_file_expressions = convert_archive_file_to_pattern(f)
        if archive_file_expressions:
            expressions.append(archive_file_expressions)
        else:
            warn("No ArchiveFile properties found in %s", 613, str(f))
    if isinstance(f, ImageFile):
        image_file_expressions = convert_image_file_to_pattern(f)
        if image_file_expressions:
            expressions.append(image_file_expressions)
        else:
            warn("No ImageFile properties found in %s", 613, str(f))
    if isinstance(f, PDFFile):
        pdf_file_expressions = convert_pdf_file_to_pattern(f)
        if pdf_file_expressions:
            expressions.append(pdf_file_expressions)
        else:
            warn("No PDFFile properties found in %s", 613, str(f))
    if expressions:
        return create_boolean_expression("AND", expressions)


_REGISTRY_KEY_VALUES_PROPERTIES = [["data", "windows-registry-key:values[*].data"],
                                   ["name", "windows-registry-key:values[*].name"],
                                   ["datatype", "windows-registry-key:values[*].data_type"]]


def convert_registry_key_to_pattern(reg_key):
    expressions = []
    if reg_key.key or reg_key.hive:
        key_value_term = ""
        if reg_key.hive:
            if reg_key.hive.condition is None or is_equal_condition(reg_key.hive.condition):
                key_value_term += reg_key.hive.value + "\\"
            else:
                warn("Condition %s on a hive property not handled", 812, reg_key.hive.condition)
            if reg_key.key and reg_key.key.value.startswith(reg_key.hive.value):
                warn("Hive property, %s, is already a prefix of the key property, %s", 623, reg_key.hive.value,
                     reg_key.key.value)
                key_value_term = reg_key.key.value
            elif reg_key.key:
                key_value_term += reg_key.key.value
        else:
            key_value_term = reg_key.key.value
        expressions.append(create_term("windows-registry-key:key",
                                       reg_key.key.condition if reg_key.key else 'Equals',
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
        argument_expressions = []
        if get_option_value("spec_version") == "2.0":
            for a in process.argument_list:
                argument_expressions.append(create_term("process:arguments[*]",
                                                        a.condition,
                                                        stix2.StringConstant(a.value)))
            if argument_expressions:
                expressions.append(create_boolean_expression("AND", argument_expressions))
        else:
            warn("The argument_list property of ProcessObj is not part of STIX 2.1", 418)
            lhs = generate_lhs_for_missing_property("process:", None, "argument_list[*]", "process")
            if lhs:
                for a in process.argument_list:
                    argument_expressions.append(create_term(lhs,
                                                            a.condition,
                                                            stix2.StringConstant(a.value)))
                if argument_expressions:
                    expressions.append(create_boolean_expression("AND", argument_expressions))
            else:
                if not check_for_missing_policy("ignore"):
                    expressions.append(UnconvertedTerm("ProcessObj.argument_list", "process"))
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
                new_pattern.collapse_reference(ObjectPathForElevator.make_object_path("process:opened_connection_refs[*]")))
        if network_connection_expressions:
            expressions.append(create_boolean_expression("AND", network_connection_expressions))
    if isinstance(process, WinProcess):
        win_process_expression = convert_windows_process_to_pattern(process)
        if win_process_expression:
            expressions.append(win_process_expression)
        else:
            warn("No WinProcess properties found in %s", 615, str(process))
        if isinstance(process, WinService):
            service_expression = convert_windows_service_to_pattern(process)
            if service_expression:
                expressions.append(service_expression)
            else:
                warn("No WinService properties found in %s", 616, str(process))
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
            warn("Windows Handles are not a part of STIX 2.x", 420)
    if process.startup_info:
        warn("The startup_info property of ProcessObj is not part of STIX 2.x", 418)
        if not check_for_missing_policy("ignore"):
            expressions.append(UnconvertedTerm("ProcessObj.startup_info", "process"))
    if expressions:
        return create_boolean_expression("AND", expressions)


_WINDOWS_SERVICE_PROPERTIES = \
    [["service_name", "process:extensions.'windows-service-ext'.service_name"],
     ["display_name", "process:extensions.'windows-service-ext'.display_name"],
     ["startup_command_line", "process:extensions.'windows-service-ext'.startup_command_line"],
     ["startup_type", "process:extensions.'windows-service-ext'.start_type"],
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
            expressions.append(create_boolean_expression("AND", description_expressions))
    if hasattr(service, "service_dll") and service.service_dll:
        # assuming its not a path
        expressions.append(create_term("process:" + "service_dll_refs[*].name",
                                       service.service_dll.condition,
                                       stix2.StringConstant(service.service_dll.value)))
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
                referenced_obs = get_obs_from_mapping(ro.idref)
                return convert_observable_to_pattern(referenced_obs)
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
                            ObjectPathForElevator.make_object_path("domain-name:resolves_to_refs[*]")))
            else:
                warn("The %s relationship involving %s is not explicitly supported in STIX 2.x", 427, ro.relationship,
                     identifying_info(ro))
    return create_boolean_expression("AND", pattern)


def convert_host_name_to_pattern(host_name, related_objects):
    pattern = [
        create_term("domain-name:value", host_name.hostname_value.condition, make_constant(host_name.hostname_value.value))]
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
                            ObjectPathForElevator.make_object_path("domain-name:resolves_to_refs[*]")))
            else:
                warn("The %s relationship involving %s is not explicitly supported in STIX 2.x", 427, ro.relationship,
                     identifying_info(ro))
    return create_boolean_expression("AND", pattern)


def convert_mutex_to_pattern(mutex):
    if mutex.name:
        return create_term("mutex:name", mutex.name.condition, make_constant(mutex.name.value))
    else:
        return None


def convert_port_to_pattern(prop):
    expressions = []
    if prop.port_value:
        warn("port number is assumed to be a destination port", 725)
        expressions.append(
            create_term("network-traffic:dst_port", prop.port_value.condition, make_constant(prop.port_value.value)))
    if prop.layer4_protocol:
        expressions.append(
            create_term("network-traffic:protocols[*]", prop.layer4_protocol.condition,
                        make_constant(prop.layer4_protocol.value)))
    return create_boolean_expression("AND", expressions)


def convert_socket_address_to_pattern(sock_add, direction):
    expressions = list()
    if sock_add.port is not None:
        if sock_add.port.port_value is not None:
            expressions.append(create_term("network-traffic:" + direction + "_port",
                                           sock_add.port.port_value.condition,
                                           stix2.IntegerConstant(int(sock_add.port.port_value))))
        if sock_add.port.layer4_protocol is not None:
            expressions.append(
                create_term("network-traffic:protocols[*]",
                            sock_add.port.layer4_protocol.condition,
                            make_constant(sock_add.port.layer4_protocol.value.lower())))
    if sock_add.ip_address is not None:
        if sock_add.ip_address.address_value:
            expressions.append(
                create_term("network-traffic:" + direction + "_ref.value",
                            sock_add.ip_address.address_value.condition,
                            make_constant(sock_add.ip_address.address_value.value)))
        elif sock_add.ip_address.object_reference:
            new_pattern = handle_object_reference_for_pattern(sock_add.ip_address.object_reference)
            if isinstance(new_pattern, IdrefPlaceHolder):
                expressions.append(new_pattern)
            else:
                expressions.append(new_pattern.collapse_reference(
                    ObjectPathForElevator.make_object_path("network-traffic:" + direction + "_ref")))
    elif sock_add.hostname is not None:
        if sock_add.hostname.is_domain_name and sock_add.hostname.hostname_value is not None:
            expressions.append(
                create_term("network-traffic:" + direction + "_ref.value",
                            sock_add.hostname.condition,
                            make_constant(sock_add.hostname.hostname_value)))
        elif (sock_add.hostname.naming_system is not None and
              any(x.value == "DNS" for x in sock_add.hostname.naming_system)):
            expressions.append(
                create_term("network-traffic:" + direction + "_ref.value",
                            sock_add.hostname.condition,
                            make_constant(sock_add.hostname.hostname_value)))
    return expressions


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
        expressions.extend(convert_socket_address_to_pattern(conn.source_socket_address, "src"))

    if conn.destination_socket_address is not None:
        expressions.extend(convert_socket_address_to_pattern(conn.destination_socket_address, "dst"))

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
        if http_request.http_request_line.value is not None:
            term = add_comparison_expression(http_request.http_request_line.value,
                                             "network-traffic:extensions.'http-request-ext'.request_value")
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
    if http_request.http_message_body is not None:
        mb = http_request.http_message_body
        if mb.length:
            term = add_comparison_expression(mb.length,
                                             "network-traffic:extensions.'http-request-ext'.message_body_length")
            if term:
                expressions.append(term)
        if mb.message_body:
            expressions.append(create_term("network-traffic:extensions.'http-request-ext'.message_body_data_ref.payload_bin",
                                           'Equals',
                                           encode_in_base64(str(mb.message_body))))
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


def generate_lhs_for_missing_property(prefix, predefined_extension_name, property_name, object_type):
    if check_for_missing_policy("use-custom-properties"):
        warn("Used custom property for %s", 308, property_name)
        if predefined_extension_name:
            return prefix + "extensions." + predefined_extension_name + "." + convert_to_custom_name(property_name)
        else:
            return prefix + convert_to_custom_name(property_name)
    elif check_for_missing_policy("use-extensions"):
        extension_definition_id = get_extension_definition_id(object_type)
        if extension_definition_id:
            lhs = prefix + "extensions." + extension_definition_id + "." + property_name
            warn("Used %s for extension property for %s", 317, lhs, property_name)
            return lhs
        else:
            warn("No extension-definition was found for STIX 1 type %s", 312, object_type)
            return None
    else:
        warn("%s not supported in STIX 2.x", 424, property_name)
        return None


def handle_missing_properties_in_expression_for_icmp_header(expressions, icmp_header):
    if icmp_header.checksum:
        lhs = generate_lhs_for_missing_property("network-traffic:", "icmp-ext", "icmp_checksum", "icmp-header")
        if lhs:
            expressions.append(create_term(lhs,
                                           icmp_header.checksum.condition,
                                           stix2.HexConstant(icmp_header.checksum.value)))


def convert_network_packet_to_pattern(packet):
    if packet.internet_layer:
        internet_layer = packet.internet_layer
        if internet_layer.ipv4 or internet_layer.ipv6:
            warn("Internet_Layer/IP_Packet content not supported in STIX 2.x", 424)
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
            handle_missing_properties_in_expression_for_icmp_header(expressions, icmp_header)
            return create_boolean_expression("AND", expressions)


def convert_http_session_to_pattern(session):
    if session.http_request_response:
        requests, responses = split_into_requests_and_responses(session.http_request_response)
        if len(responses) != 0:
            warn("HTTPServerResponse type is not supported in STIX 2.x", 429)
        if len(requests) >= 1:
            expression = convert_http_client_request_to_pattern(requests[0])
            if len(requests) > 1:
                warn("Only HTTP_Request_Response used for http-request-ext, using first value", 512)
            return expression


def convert_socket_options_to_pattern(options):
    expressions = []
    for prop_name in SOCKET_OPTIONS:
        value = getattr(options, prop_name)
        if isinstance(value, bool):
            value = 1 if value else 0
        if value:
            expressions.append(create_term("network-traffic:extensions.'socket-ext'.options." + prop_name.upper(),
                                           "Equals",
                                           value))
    return create_boolean_expression("AND", expressions)


_SOCKET_MAP = {
    "is_blocking": "network-traffic:extensions.'socket-ext'.is_blocking",
    "is_listening": "network-traffic:extensions.'socket-ext'.is_listening",
    "type_": "network-traffic:extensions.'socket-ext'.socket_type",
    "domain": "network-traffic:extensions.'socket-ext'.socket_type",
    "socket_descriptor": "network-traffic:extensions.'socket-ext'.socket_descriptor"
}


def handle_missing_properties_in_expression_for_network_socket(expressions, socket):
    if socket.local_address:
        lhs = generate_lhs_for_missing_property("network-traffic:", "socket-ext", "local_address", "network-socket")
        if lhs:
            expressions.append(create_term(lhs,
                                           socket.local_address.ip_address.condition,
                                           stix2.StringConstant(socket.local_address.ip_address.address_value.value)))
    if socket.remote_address:
        lhs = generate_lhs_for_missing_property("network-traffic:", "socket-ext", "remote_address", "network-socket")
        if lhs:
            expressions.append(create_term(lhs,
                                           socket.remote_address.ip_address.condition,
                                           stix2.StringConstant(socket.remote_address.ip_address.address_value.value)))


def convert_network_socket_to_pattern(socket):
    expressions = []
    for prop_spec in _SOCKET_MAP:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(socket, prop_1x) and getattr(socket, prop_1x):
            value = getattr(socket, prop_1x)
            if isinstance(value, bool):
                value = 1 if value else 0
            term = add_comparison_expression(value, object_path)
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

    if socket.protocol:
        expressions.append(add_comparison_expression(socket.protocol,
                                                     "network-traffic:protocols[*]"))
    handle_missing_properties_in_expression_for_network_socket(expressions, socket)
    return create_boolean_expression("AND", expressions)


def convert_product_to_pattern(prod):
    expressions = []
    if prod.product:
        expressions.append(add_comparison_expression(prod.product, "software:name"))
    if prod.vendor:
        expressions.append(add_comparison_expression(prod.vendor, "software:vendor"))
    if prod.version:
        expressions.append(add_comparison_expression(prod.version, "software:version"))
    if prod.language:
        expressions.append(add_comparison_expression(prod.language, "software:languages[*]"))
    if expressions:
        return create_boolean_expression("AND", expressions)


_X509_V3_PROPERTY_MAP = \
    [
        ["basic_constraints", "x509-certificate:x509_v3_extensions.basic_constraints"],
        ["name_constraints", "x509-certificate:x509_v3_extensions.name_constraints"],
        ["policy_constraints", "x509-certificate:x509_v3_extensions.policy_constraints"],
        ["key_usage", "x509-certificate:x509_v3_extensions.key_usage"],
        ["extended_key_usage", "x509-certificate:x509_v3_extensions.extended_key_usage"],
        ["subject_key_identifier", "x509-certificate:x509_v3_extensions.subject_key_identifier"],
        ["authority_key_identifier", "x509-certificate:x509_v3_extensions.authority_key_identifier"],
        ["subject_alternative_name", "x509-certificate:x509_v3_extensions.subject_alternative_name"],
        ["issuer_alternative_name", "x509-certificate:x509_v3_extensions.issuer_alternative_name"],
        ["subject_directory_attributes", "x509-certificate:x509_v3_extensions.subject_directory_attributes"],
        ["crl_distribution_points", "x509-certificate:x509_v3_extensions.crl_distribution_points"],
        ["inhibit_any_policy", "x509-certificate:x509_v3_extensions.inhibit_any_policy"],
        ["certificate_policies", "x509-certificate:x509_v3_extensions.certificate_policies"],
        ["policy_mappings", "x509-certificate:x509_v3_extensions.policy_mappings"],
    ]


def convert_v3_extension_to_pattern(v3_ext):
    expressions = []
    for prop_spec in _X509_V3_PROPERTY_MAP:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(v3_ext, prop_1x) and getattr(v3_ext, prop_1x):
            term = add_comparison_expression(getattr(v3_ext, prop_1x), object_path)
            if term:
                expressions.append(term)
    if v3_ext.private_key_usage_period:
        if v3_ext.private_key_usage_period.not_before:
            expressions.append(add_comparison_expression(v3_ext.private_key_usage_period.not_before,
                                                         "x509-certificate:x509_v3_extensions.private_key_usage_period_not_before"))
        if v3_ext.private_key_usage_period.not_after:
            expressions.append(add_comparison_expression(v3_ext.private_key_usage_period.not_after,
                                                         "x509-certificate:x509_v3_extensions.private_key_usage_period_not_after"))
    if expressions:
        return create_boolean_expression("AND", expressions)


_X509_PROPERTY_MAP = \
    [
        ["serial_number", "x509-certificate:serial_number"],
        ["signature_algorithm", "x509-certificate:signature_algorithm"],
        ["issuer", "x509-certificate:issuer"],
        ["subject", "x509-certificate:subject"],
        ["version", "x509--certificate:version"]
    ]

# is_self_signed
# hashes
# version


def convert_x509_certificate_to_pattern(x509):
    expressions = []
    if x509.certificate:
        cert = x509.certificate
        for prop_spec in _X509_PROPERTY_MAP:
            prop_1x = prop_spec[0]
            object_path = prop_spec[1]
            if hasattr(cert, prop_1x) and getattr(cert, prop_1x):
                term = add_comparison_expression(getattr(cert, prop_1x), object_path)
                if term:
                    expressions.append(term)
        if cert.validity:
            if cert.validity.not_before:
                expressions.append(add_comparison_expression(cert.validity.not_before,
                                                             "x509-certificate:validity_not_before"))
            if cert.validity.not_after:
                expressions.append(add_comparison_expression(cert.validity.not_after,
                                                             "x509-certificate:validity_not_after"))
        if cert.subject_public_key:
            if cert.subject_public_key.public_key_algorithm:
                add_comparison_expression(cert.subject_public_key.public_key_algorithm,
                                          "x509-certificate:subject_public_key_algorithm")
            if cert.subject_public_key.rsa_public_key:
                rsa_key = cert.subject_public_key.rsa_public_key
                if rsa_key.modulus:
                    add_comparison_expression(rsa_key.modulus,
                                              "x509-certificate:subject_public_key_modulus")
                if rsa_key.exponent:
                    add_comparison_expression(rsa_key.exponent,
                                              "x509-certificate:subject_public_key_exponent")
        if cert.standard_extensions:
            v3_expressions = convert_v3_extension_to_pattern(cert.standard_extensions)
            if v3_expressions:
                expressions.append(v3_expressions)
    if expressions:
        return create_boolean_expression("AND", expressions)


####################################################################################################################

def convert_observable_list_to_pattern(obs_list, op="AND"):
    expressions = []
    for obs in obs_list:
        term = convert_observable_to_pattern(obs)
        if term:
            expressions.append(term)
    if expressions:
        if len(expressions) == 1:
            return expressions[0]
        else:
            return create_boolean_expression(op, expressions)
    else:
        return ""


def convert_observable_composition_to_pattern(obs_comp):
    return convert_observable_list_to_pattern(obs_comp.observables, obs_comp.operator)


def determine_term_type(stix1_obj):
    if isinstance(stix1_obj, (File, WinExecutableFile)):
        return "file"
    elif isinstance(stix1_obj, (Process, WinProcess, WinService)):
        return "process"
    elif isinstance(stix1_obj, WinRegistryKey):
        return "windows-registry-key"
    else:
        return None


def convert_object_to_pattern(obj, obs_id):
    related_objects = obj.related_objects
    prop = obj.properties
    expression = None
    is_custom_object = False
    if prop:
        if isinstance(prop, Address):
            expression = convert_address_to_pattern(prop)
        elif isinstance(prop, Artifact):
            expression = convert_artifact_to_pattern(prop)
        elif isinstance(prop, AutonomousSystem):
            expression = convert_as_to_pattern(prop)
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
        elif isinstance(prop, Product):
            expression = convert_product_to_pattern(prop)
        elif isinstance(prop, DomainName):
            expression = convert_domain_name_to_pattern(prop, related_objects)
        elif isinstance(prop, Hostname):
            expression = convert_host_name_to_pattern(prop, related_objects)
        elif isinstance(prop, Mutex):
            expression = convert_mutex_to_pattern(prop)
        elif isinstance(prop, NetworkConnection):
            expression = convert_network_connection_to_pattern(prop)
        elif isinstance(prop, Account):
            expression = convert_account_to_pattern(prop)
        elif isinstance(prop, Port):
            expression = convert_port_to_pattern(prop)
        elif isinstance(prop, HTTPSession):
            expression = convert_http_session_to_pattern(prop)
        elif isinstance(prop, NetworkPacket):
            expression = convert_network_packet_to_pattern(prop)
        elif isinstance(prop, NetworkSocket):
            expression = convert_network_socket_to_pattern(prop)
        elif isinstance(prop, X509Certificate):
            expression = convert_x509_certificate_to_pattern(prop)
        elif isinstance(prop, SocketAddress):
            expression = convert_socket_address_to_pattern(prop, determine_socket_address_direction(prop, obs_id))
            if expression:
                expression = create_boolean_expression("AND", expression)
        elif isinstance(prop, Custom):
            is_custom_object = True
            if check_for_missing_policy("use-custom-properties") or check_for_missing_policy("use-extensions"):
                if prop.custom_name:
                    if check_for_missing_policy("use-custom-properties"):
                        object_path_root = convert_to_custom_name(prop.custom_name, separator="-")
                    else:  # check_for_missing_policy("use-extensions")
                        if re.search('[A-Z]', prop.custom_name):
                            warn("Custom name %s has been converted to all lower case", 727, prop.custom_name)
                        object_path_root = prop.custom_name.lower()
                    term = convert_custom_properties(prop.custom_properties, object_path_root, use_custom_prefix=False)
                    if expression:
                        expression = create_boolean_expression("AND", [expression, term])
                    else:
                        expression = term
                else:
                    warn("Custom object with no name cannot be handled yet", 811)
                    if not check_for_missing_policy("ignore"):
                        expression = UnconvertedTerm(obs_id)
            else:
                warn("Pattern expression with STIX 1.x custom objects in %s is ignored", 817, obs_id)
        else:
            warn("%s found in %s cannot be converted to a pattern, yet.", 808, str(obj.properties), obs_id)
            if not check_for_missing_policy("ignore"):
                expression = UnconvertedTerm(obs_id)
        # custom properties of custom objects handled above
        if prop.custom_properties is not None and not is_custom_object:
            if check_for_missing_policy("use-custom-properties") or check_for_missing_policy("use-extensions"):
                object_type_name = convert_cybox_class_name_to_object_path_root_name(prop)
                if check_for_missing_policy("use-custom-properties"):
                    object_path_root = object_type_name
                else:  # check_for_missing_policy("use-extensions")
                    extension_definition_id = get_extension_definition_id(object_type_name)
                    if extension_definition_id:
                        object_path_root = object_type_name + "extensions." + extension_definition_id
                        warn("Used %s for extension property for %s", 317, object_path_root, object_type_name)
                    else:
                        object_path_root = None
                        warn("No extension-definition was found for STIX 1 type %s", 312, object_type_name)
                if object_path_root:
                    term = convert_custom_properties(prop.custom_properties, object_path_root)
                    if expression:
                        expression = create_boolean_expression("AND", [expression, term])
                    else:
                        expression = term
            else:
                warn("Pattern expression with STIX 1.x custom properties in %s is ignored", 818, obs_id)
    if not expression:
        warn("No pattern term was created from %s", 422, obs_id)
        expression = UnconvertedTerm(obs_id, determine_term_type(prop))
    elif obj.id_:
        add_id_value(obj.id_, obs_id)
        add_to_pattern_cache(obj.id_, expression)
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


def handle_pattern_idref(idref):
    if id_in_pattern_cache(idref):
        return get_pattern_from_cache(idref)
    else:
        # resolve now if possible
        if id_in_observable_mappings(idref):
            referenced_obs = get_obs_from_mapping(idref)
            return convert_observable_to_pattern(referenced_obs)
        return IdrefPlaceHolder(idref)


def convert_related_objects_to_pattern(obj, obs_id):
    related_patterns = []
    for o in obj.related_objects:
        # relationship 'Resolved_To' handled elsewhere
        if not o.relationship == "Resolved_To":
            if o.id_:
                if not id_in_pattern_cache(o.id_):
                    new_pattern = convert_object_to_pattern(o, o.id_)
                    warn("Relationship '%s' in %s for %s is not explicitly supported in STIX 2.x. Expression %s is ANDed",
                         411,
                         o.relationship, obs_id, o.id_, new_pattern)
                    # A related_object may have neither an id or idref.
                    # If doesn't have idref, it belongs in the new_pattern
                    if new_pattern and not o.idref:
                        related_patterns.append(new_pattern)
                        if o.id_:
                            # save pattern for later use
                            add_to_pattern_cache(o.id_, new_pattern)

            elif o.idref:
                if id_in_pattern_cache(o.idref):
                    new_pattern = get_pattern_from_cache(o.idref)
                    related_patterns.append(new_pattern)
                    warn(
                        "Relationship '%s' in %s for %s is not explicitly supported in STIX 2.x. Expression %s is ANDed",
                        411,
                        o.relationship, obs_id, o.idref, new_pattern)
                else:
                    placeholder = IdrefPlaceHolder(o.idref)
                    related_patterns.append(placeholder)
                    warn(
                        "Relationship '%s' in %s for %s is not explicitly supported in STIX 2.x. %s will be ANDed if/when resolved",
                        412,
                        o.relationship, obs_id, o.idref, placeholder)
            else:
                new_pattern = convert_object_to_pattern(o, None)
                warn("Relationship '%s in %s for %s is not explicitly supported in STIX 2.x. Expression %s is ANDed",
                     411,
                     o.relationship, obs_id, "unknown", new_pattern)
                related_patterns.append(new_pattern)
            if o.related_objects:
                next_level_of_relationships = convert_related_objects_to_pattern(o, obs_id)
                if next_level_of_relationships:
                    related_patterns.extend(next_level_of_relationships)
    return related_patterns


def convert_observable_to_pattern_without_negate(obs):
    if obs.observable_composition is not None:
        pattern = convert_observable_composition_to_pattern(obs.observable_composition)
        if pattern and obs.id_:
            add_to_pattern_cache(obs.id_, pattern)
        return pattern
    elif obs.object_ is not None:
        if obs.object_.idref is not None:
            return handle_pattern_idref(obs.object_.idref)
        else:
            pattern = convert_object_to_pattern(obs.object_, obs.id_)
            # TODO: seems redundant
            if pattern:
                add_to_pattern_cache(obs.id_, pattern)
            if obs.object_.related_objects:
                related_patterns = convert_related_objects_to_pattern(obs.object_, obs.id_)
                if pattern:
                    if related_patterns:
                        related_patterns.append(pattern)
                        return create_boolean_expression("AND", related_patterns)
                    else:
                        return pattern
            else:
                return pattern
    elif obs.idref is not None:
        return handle_pattern_idref(obs.idref)


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
                if expr and expr.contains_placeholder():
                    change_made, expr = expr.replace_placeholder_with_idref_pattern(fr_idref)
                    # a change will be made, which could introduce a new placeholder id into the expr
                    if change_made:
                        add_to_pattern_cache(idref, expr)  # PATTERN_CACHE[idref] = expr
        done = not change_made


def is_placeholder(thing):
    return thing.index("PLACEHOLDER") != -1


def fix_pattern(pattern):
    if not pattern_cache_is_empty():
        if pattern and pattern.contains_placeholder():
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
                referenced_obs = get_obs_from_mapping(ind.idref)
                return convert_observable_to_pattern(referenced_obs)
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
    if not KEEP_OBSERVABLE_DATA_USED_IN_PATTERNS:
        # fix any ids
        obj_ids_to_delete = []
        all_new_ids_with_patterns = []
        for old_id in get_ids_from_pattern_cache():
            new_id = get_id_value(old_id)
            if new_id and len(new_id) == 1:
                all_new_ids_with_patterns.append(new_id[0])

        remaining_objects = []
        for obj in bundle_instance["objects"]:
            if obj["type"] != "observed-data" or obj["id"] not in all_new_ids_with_patterns and not exists_id_of_obs_in_characterizations(obj["id"]):
                remaining_objects.append(obj)
            elif exists_id_of_obs_in_characterizations(obj["id"]):
                warn("%s is used as a characteristic in an infrastructure object, therefore it is not included as an observed_data instance", 419,
                     obj["id"])
                obj_ids_to_delete.append(obj["id"])
            else:
                warn("%s is used as a pattern, therefore it is not included as an observed_data instance", 423, obj["id"])
                if "object_refs" in obj:
                    obj_ids_to_delete.extend(obj["object_refs"])
                obj_ids_to_delete.append(obj["id"])
        new_remaining_objects = []
        for obj in remaining_objects:
            if obj["type"] == "relationship" and "source_ref" in obj and "target_ref" in obj:
                if obj["source_ref"] not in obj_ids_to_delete and obj["target_ref"] not in obj_ids_to_delete:
                    new_remaining_objects.append(obj)
            else:
                if obj["id"] not in obj_ids_to_delete:
                    new_remaining_objects.append(obj)

        bundle_instance["objects"] = new_remaining_objects

        for obj in bundle_instance["objects"]:
            if obj["type"] == "report":
                remaining_object_refs = []
                if "object_refs" in obj:
                    for ident in obj["object_refs"]:
                        if (not ident.startswith("observed-data") or
                                (ident not in all_new_ids_with_patterns and ident not in obj_ids_to_delete)):
                            remaining_object_refs.append(ident)
                    obj["object_refs"] = remaining_object_refs

# TODO: only remove indicators that were involved ONLY as sub-indicators within composite indicator expressions
#   if not KEEP_INDICATORS_USED_IN_COMPOSITE_INDICATOR_EXPRESSION and "indicators" in bundle_instance:
#       remaining_indicators = []
#       for ind in bundle_instance["indicators"]:
#           if ind["id"] not in all_new_ids_with_patterns:
#               remaining_indicators.append(ind)
#       bundle_instance["indicators"] = remaining_indicators
