# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import sys
import stix
import cybox
from cybox.objects.address_object import Address
from cybox.objects.uri_object import URI
from cybox.objects.file_object import File
from cybox.objects.win_registry_key_object import WinRegistryKey

from utils import info, warn, error

def convert_address(add):
    if add.category == add.CAT_IPV4:
       return { "type": "ipv4-address-object", "value": add.address_value.value}

def convert_uri(uri):
    return { "type": "url-object", "value": + uri.value.value }

def convert_file(file):
    first_one = True
    cybox = { "type": "file-object" }
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
    if file.file_name:
        cybox["file_name"] = str(file.file_name)
    # TODO: handle path properties be generating a directory object?
    return cybox

def convert_registry_key(reg_key):
    cybox = {"type": "windows-registry-key"}
    if reg_key.key or reg_key.hive:
        full_key = ""
        if reg_key.hive:
            full_key += reg_key.hive.value + "\\"
        if reg_key.key:
            full_key += reg_key.key.value
        cybox["key"] = full_key
    else:
        error("windows-registry-key is required to have a key property")
    if reg_key.values:
        cybox["values"] = []
        for v in reg_key.values:
            reg_value = {}
            if hasattr(v, "data") and v.data:
                reg_value["data"] = str(v.data)
            if hasattr(v, "name") and v.name:
                reg_value["name"] = str(v.name)
            if hasattr(v, "datatype") and v.datatype:
                reg_value["data_type"] = str(v.datatype)
            cybox["values"].append(reg_value)
    return cybox

def convert_cybox_object(obj, cyboxContainer):
    prop = obj.properties
    if isinstance(prop, Address):
        cyboxContainer["objects"] = { "0": convert_address(prop)}
    elif isinstance(prop, URI):
        cyboxContainer["objects"] = { "0": convert_uri(prop)}
    elif isinstance(prop, File):
        cyboxContainer["objects"] = { "0": convert_file(prop)}
    elif isinstance(prop, WinRegistryKey):
        cyboxContainer["objects"] = { "0": convert_registry_key(prop)}
    else:
        warn(str(type(obj)) + " not handled yet")
    return cyboxContainer


