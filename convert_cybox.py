# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import sys
import stix
import cybox
from cybox.objects.address_object import Address
from cybox.objects.uri_object import URI

def convert_address(add):
    if add.category == add.CAT_IPV4:
       return { "type": "ipv4-address-object", "value": add.address_value.value}

def convert_uri(uri):
    return { "type": "url-object", "value": + uri.value.value }

def convert_cybox_object(obj, cyboxContainer):
    prop = obj.properties
    if isinstance(prop, Address):
        cyboxContainer["objects"] = { "0": convert_address(prop)}
    elif isinstance(prop, URI):
        cyboxContainer["objects"] = { "0": convert_uri(prop)}
    return cyboxContainer


