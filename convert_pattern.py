# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from cybox.core import Observable
from cybox.objects.address_object import Address
from cybox.objects.uri_object import URI
from cybox.objects.email_message_object import EmailMessage
from cybox.objects.file_object import File
from utils import info, warn, error

def convert_condition(condition):
    if condition == "Equals":
        return "EQ"
    elif condition == "DoesNotEqual":
        return "NEQ"
    elif condition == "Contains":
        return "CONTAINS"
    # DoesNotContain
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

def create_term_with_regex(lhs, condition, rhs):
    if condition == "StartsWith":
        return lhs + " MATCHES " + " /^" + rhs + "/"
    elif condition == "EndsWith":
        return lhs + " MATCHES " + " /" + rhs + "$/"

def create_term(lhs, condition, rhs):
    if condition == "StartsWith" or condition == "EndsWith":
        return create_term_with_regex(lhs, condition, rhs)
    else:
        return lhs + " " + convert_condition(condition) + " '" + rhs + "'"

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
            hash_expression = (" OR " if not first_hash else "") + \
                              create_term("file-object:hashes" + ":" + str(hash.type_).lower(),
                                          hash.simple_hash_value.condition,
                                          hash.simple_hash_value.value)
            first_hash = False
        if not first_hash:
         expression += (" AND " if not first_one else "") + hash_expression
    return expression

def convert_observable_composition_to_pattern(obs_comp):
    pass

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

def convert_observable_to_pattern(obs):
    if obs.observable_composition is not None:
        return convert_observable_composition_to_pattern( obs.observable_composition)
    elif obs.object_ is not None:
        return convert_object_to_pattern(obs.object_)
