# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import sys
import stix
import cybox
from cybox.objects.address_object import Address
from cybox.objects.uri_object import URI
from cybox.objects.file_object import File
from utils import info, warn, error

def convert_address(add):
    if add.category == add.CAT_IPV4:
       return { "type": "ipv4-address-object", "value": add.address_value.value}

def convert_uri(uri):
    return { "type": "url-object", "value": + uri.value.value }

def convert_file(file):
    first_one = True
    cybox = { "type": "file-object", "file_name": str(file.file_name) }
    if file.size is not None:
        if isinstance(file.size.value, list):
            error("file size window not allowed in top level observable, using first value")
            cybox["size"] = int(file.size.value[0])
        else:
            cybox["size"] = int(file.size)
    if file.hashes is not None:
        hashes = {}
        for hash in file.hashes:
            hashes[str(hash.type_).lower()] = hash.simple_hash_value.value
        cybox["hashes"] = hashes
    return cybox

def convert_cybox_object(obj, cyboxContainer):
    prop = obj.properties
    if isinstance(prop, Address):
        cyboxContainer["objects"] = { "0": convert_address(prop)}
    elif isinstance(prop, URI):
        cyboxContainer["objects"] = { "0": convert_uri(prop)}
    elif isinstance(prop, File):
        cyboxContainer["objects"] = { "0": convert_file(prop)}
    else:
        warn(str(type(obj)) + " not handled yet")
    return cyboxContainer


