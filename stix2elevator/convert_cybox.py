# Standard Library
import copy
from datetime import datetime
import re

# external
from cybox.common import ObjectProperties
from cybox.objects.account_object import Account
from cybox.objects.address_object import Address
from cybox.objects.archive_file_object import ArchiveFile
from cybox.objects.artifact_object import Artifact
from cybox.objects.as_object import AutonomousSystem
from cybox.objects.custom_object import Custom
from cybox.objects.domain_name_object import DomainName
from cybox.objects.email_message_object import EmailMessage
from cybox.objects.file_object import File
from cybox.objects.http_session_object import HTTPSession
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
from cybox.objects.user_account_object import UserAccount
from cybox.objects.win_computer_account_object import WinComputerAccount
from cybox.objects.win_executable_file_object import WinExecutableFile
from cybox.objects.win_process_object import WinProcess
from cybox.objects.win_registry_key_object import WinRegistryKey
from cybox.objects.win_service_object import WinService
from cybox.objects.x509_certificate_object import X509Certificate
import netaddr

# internal
from stix2elevator.common import (
    ADDRESS_FAMILY_ENUMERATION, PDF_DOC_INFO, PDF_DOC_INFO_DICT,
    SOCKET_OPTIONS, determine_socket_address_direction
)
from stix2elevator.ids import (
    add_id_value, add_object_id_value, generate_sco_id, get_id_value,
    get_object_id_value, is_stix1x_id, property_contains_stix1x_id
)
from stix2elevator.missing_policy import (
    check_for_missing_policy, convert_to_custom_name,
    determine_container_for_missing_properties, fill_in_extension_properties,
    get_extension_definition_id, handle_missing_string_property
)
from stix2elevator.options import error, get_option_value, info, warn
from stix2elevator.utils import (
    convert_timestamp_to_string, encode_in_base64, map_vocabs_to_label
)
from stix2elevator.vocab_mappings import (
    SERVICE_START_TYPE, SERVICE_STATUS, SERVICE_TYPE, WINDOWS_PEBINARY
)


def create_base_sco(sco_type, prop1x=None, other_properties=None, env=None, generate_shell=False):
    if prop1x and isinstance(prop1x, ObjectProperties):
        obj1x = prop1x.parent
        id_1x = obj1x.id_
        if prop1x.object_reference and not generate_shell:
            warn("Object reference %s may not handled correctly", 804, prop1x.object_reference)
        elif id_1x and id_1x in _OBJECT_REFERENCES_SHELLS:
            shell = _OBJECT_REFERENCES_SHELLS[id_1x]
            if other_properties:
                shell.update(other_properties)
            if env:
                # remove shell, it will be added back when more complete
                env.bundle_instance["objects"].remove(shell)
            return shell
    if other_properties:
        new_dict = other_properties
        new_dict["type"] = sco_type
    else:
        new_dict = {"type": sco_type}
    return new_dict


def generate_sco_id_for_2_1(instance, stix1x_id):
    if get_option_value("spec_version") == "2.1":
        instance["id"] = generate_sco_id(instance["type"], instance)
        if stix1x_id:
            add_id_value(stix1x_id, instance["id"])


def convert_account(acc):
    account_dict = create_base_sco("user-account", acc)
    if acc.creation_date:
        account_dict["account_created"] = acc.creation_date.value
    if acc.last_accessed_time:
        account_dict["account_last_login"] = acc.last_accessed_time
    if acc.disabled:
        account_dict["is_disabled"] = acc.disabled
    if acc.authentication and get_option_value("spec_version") == "2.1":
        if acc.authentication.authentication_data:
            account_dict["credential"] = acc.authentication.authentication_data
    if isinstance(acc, UserAccount):
        if acc.username:
            account_dict["account_login"] = acc.username.value
        if acc.full_name:
            account_dict["display_name"] = acc.full_name.value
        if acc.last_login:
            account_dict["account_last_login"] = convert_timestamp_to_string(acc.last_login.value)
        if isinstance(acc, UnixUserAccount):
            account_dict["account_type"] = "unix"
            ext_dict = {}
            if acc.group_id:
                ext_dict["gid"] = acc.group_id.value
            if acc.user_id:
                account_dict["user_id"] = str(acc.user_id.value)
            if acc.login_shell:
                ext_dict["shell"] = acc.login_shell.value
            if acc.home_directory:
                ext_dict["home_dir"] = acc.home_directory.value
            if acc.group_list:
                ext_dict["groups"] = []
                for g in acc.group_list:
                    ext_dict["groups"].append(str(g.group_id.value))
            if ext_dict != {}:
                account_dict["extensions"] = {"unix-account-ext": ext_dict}
        elif isinstance(acc, WinComputerAccount):
            if acc.domain:
                account_dict["account_type"] = "windows-domain"
            else:
                account_dict["account_type"] = "windows-local"
    generate_sco_id_for_2_1(account_dict, acc.parent.id_)
    return account_dict


def handle_inclusive_ip_addresses(add_value, obj1x_id):
    if add_value.condition == 'InclusiveBetween' and isinstance(add_value.value, list):
        x = str(netaddr.iprange_to_cidrs(str(add_value.value[0]), str(add_value.value[1])))
        m = re.match(r".*'(\d+.\d+.\d+.\d+/\d+).*", x)
        if m:
            return m.group(1)
        else:
            warn("Cannot convert range of %s to %s in %s to a CIDR", 501, add_value.value[0], add_value.value[1], obj1x_id)
            return None
    else:
        return str(add_value.value)


def handle_related_objects_as_embedded_relationships(sco, related_objects, stix1x_rel_name, stix2x_rel_name, more_than_one=True):
    if related_objects:
        for ro in related_objects:
            if ro.relationship == stix1x_rel_name and ro.idref:
                # inline objects handled in convert_stix.py
                if more_than_one:
                    if stix2x_rel_name not in sco:
                        sco[stix2x_rel_name] = list()
                    sco[stix2x_rel_name].append(str(ro.idref))
                else:
                    sco[stix2x_rel_name] = str(ro.idref)


_OBJECT_REFERENCES_SHELLS = {}


def handle_object_reference(obj1x, type_, env, property="id"):
    objs2x = get_object_id_value(obj1x.object_reference)
    if objs2x:
        # more than one - warning?
        obj2x = objs2x[0]
        return obj2x
    else:
        shell_sco = create_base_sco(type_, obj1x, other_properties={property: obj1x.object_reference}, env=env, generate_shell=True)
        _OBJECT_REFERENCES_SHELLS[obj1x.object_reference] = shell_sco
        return shell_sco


def get_address_type(add):
    if add.category == add.CAT_IPV4:
        return "ipv4-addr"
    elif add.category == add.CAT_IPV6:
        return "ipv6-addr"
    elif add.category == add.CAT_MAC:
        return "mac-addr"
    elif add.category == add.CAT_EMAIL:
        return "email-addr"


def convert_address(add, related_objects=None, env=None):
    obj1x_id = add.parent.id_
    if add.address_value is None:
        if add.object_reference is None:
            return None
        else:
            return handle_object_reference(add, get_address_type(add), env)
    if add.category == add.CAT_IPV4:
        instance = create_base_sco("ipv4-addr", add, other_properties={"value": handle_inclusive_ip_addresses(add.address_value, obj1x_id)}, env=env)
        handle_related_objects_as_embedded_relationships(instance, related_objects, "Resolved_To", "resolves_to_refs")
    elif add.category == add.CAT_IPV6:
        # TODO: handle ipv6 CIDRs
        instance = create_base_sco("ipv6-addr", add, other_properties={"value": str(add.address_value)}, env=env)
        handle_related_objects_as_embedded_relationships(instance, related_objects, "Resolved_To", "resolves_to_refs")
    elif add.category == add.CAT_MAC:
        instance = create_base_sco("mac-addr", add, other_properties={"value": str(add.address_value)}, env=env)
    elif add.category == add.CAT_EMAIL:
        instance = create_base_sco("email-addr", add, other_properties={"value": str(add.address_value)}, env=env)
        handle_related_objects_as_embedded_relationships(instance, related_objects, "Related_To", "belongs_to_ref", more_than_one=False)
    else:
        warn("The address type %s is not part of STIX 2.x", 421, add.category)
        return None
    if instance:
        generate_sco_id_for_2_1(instance, obj1x_id)
        return instance


def convert_artifact_compression(c):
    compression_dict = dict()
    if c.compression_mechanism:
        compression_dict[convert_to_custom_name("compression_mechanism")] = c.compression_mechanism
    if c.compression_mechanism_ref:
        compression_dict[convert_to_custom_name("compression_mechanism_ref")] = c.compression_mechanism_ref
    return compression_dict


def convert_artifact_encoding(e):
    encoding_dict = dict()
    if e.algorithm:
        encoding_dict[convert_to_custom_name("algorithmm")] = e.algorithm
    if e.character_set:
        encoding_dict[convert_to_custom_name("character_set")] = e.character_set
    if e.custom_character_set_ref:
        encoding_dict[convert_to_custom_name("custom_character_set_ref")] = e.custom_character_set_ref
    return encoding_dict


def convert_artifact_packaging(packaging, instance, obj1x_id):
    if not (check_for_missing_policy("add-to-description") or check_for_missing_policy("ignore")):
        if packaging.compression:
            if check_for_missing_policy("use-custom-properties"):
                property_name = convert_to_custom_name("compression")
            else:
                property_name = "compression"
            result = []
            for c in packaging.compression:
                result.append(convert_artifact_compression(c))
            instance[property_name] = result

        if packaging.encoding:
            if check_for_missing_policy("use-custom-properties"):
                property_name = convert_to_custom_name("encoding")
            else:
                property_name = "encoding"
            result = []
            for e in packaging.encoding:
                result.append(convert_artifact_encoding(e))
            instance[property_name] = result

        if packaging.encryption:
            first = True
            for e in packaging.encryption:
                if first:
                    if e.encryption_key:
                        if get_option_value("spec_version") == "2.0" and check_for_missing_policy("use-custom-properties"):
                            property_name = convert_to_custom_name("encryption_key")
                        else:
                            property_name = "decryption_key"
                        instance[property_name] = e.encryption_key
                    if e.encryption_mechanism:
                        if get_option_value("spec_version") == "2.0" and check_for_missing_policy("use-custom-properties"):
                            property_name = convert_to_custom_name("encryption_mechanism")
                        else:
                            property_name = "encryption_algorithm"
                        instance[property_name] = e.encryption_mechanism
                    if e.encryption_key_ref:
                        handle_missing_string_property(instance, "encryption_key_ref",
                                                       e.encryption_key_ref, None, is_sco=True)
                    if e.encryption_mechanism_ref:
                        handle_missing_string_property(instance, "encryption_mechanism_ref",
                                                       e.encryption_mechanism_ref, None, is_sco=True)
                    first = False
                else:
                    warn("Only one encryption algorithm or key allowed in STIX 2.1 - used %s in %s",
                         510,
                         instance[property_name],
                         obj1x_id)
    else:
        warn("Any additional artifact info on %s is not recoverable", 634, obj1x_id)


def convert_artifact(art):
    obj1x_id = art.parent.id_
    if art.object_reference:
        warn("Object references of artifact %s is not handled, yet", 0, obj1x_id)
        return None
    instance = create_base_sco("artifact", art)
    if art.content_type:
        instance["mime_type"] = art.content_type
    if art.raw_artifact:
        instance["payload_bin"] = art.raw_artifact.value
    if art.raw_artifact_reference:
        instance["url"] = art.raw_artifact_reference
    if art.hashes:
        instance["hashes"] = convert_hashes(art.hashes)
    if art.packaging:
        convert_artifact_packaging(art.packaging, instance, obj1x_id)

    generate_sco_id_for_2_1(instance, obj1x_id)
    return instance


def convert_as(a_s):
    instance = create_base_sco("autonomous-system", a_s)
    if a_s.number:
        instance["number"] = int(a_s.number.value)
    if a_s.name:
        instance["name"] = a_s.name.value
    if a_s.regional_internet_registry:
        instance["rir"] = a_s.regional_internet_registry.value
    generate_sco_id_for_2_1(instance, a_s.parent.id_)
    return instance


def convert_uri(uri):
    instance = create_base_sco("url", uri, other_properties={"value": uri.value.value})
    generate_sco_id_for_2_1(instance, uri.parent.id_)
    return instance


def convert_hashes(hashes):
    hash_dict = {}
    for h in hashes:
        if getattr(h, "simple_hash_value"):
            hash_value = h.simple_hash_value
        else:
            hash_value = h.fuzzy_hash_value
        if str(h.type_).startswith("SHA"):
            hash_type = "'" + "SHA" + "-" + str(h.type_)[3:] + "'"
        elif str(h.type_) == "SSDEEP":
            hash_type = str(h.type_).lower()
        else:
            hash_type = str(h.type_)
        hash_dict[hash_type] = hash_value.value
    return hash_dict


_IMAGE_FILE_PROPERTY_MAP = \
    [
        ["image_height", "image_height"],
        ["image_width", "image_width"],
        ["bits_per_pixel", "bits_per_pixel"],
    ]


def convert_image_file(f):
    image_file_dict = dict()
    for prop_tuple in _IMAGE_FILE_PROPERTY_MAP:
        prop_name1x = prop_tuple[0]
        prop_name2x = prop_tuple[1]
        if getattr(f, prop_name1x, None):
            image_file_dict[prop_name2x] = getattr(f, prop_name1x).value
    return image_file_dict


def convert_pdf_file(f):
    pdf_file_dict = dict()
    file_ids = list()
    if f.version:
        pdf_file_dict["version"] = str(f.version)
    if f.metadata:
        if f.metadata.optimized:
            pdf_file_dict["is_optimized"] = f.metadata.optimized
        if f.metadata.document_information_dictionary:
            dict2x = dict()
            dict1x = f.metadata.document_information_dictionary
            for key in PDF_DOC_INFO:
                value = getattr(dict1x, key, None)
                if value:
                    if isinstance(value.value, datetime):
                        dict2x[PDF_DOC_INFO_DICT[key]] = convert_timestamp_to_string(value.value)
                    else:
                        dict2x[PDF_DOC_INFO_DICT[key]] = value.value
            pdf_file_dict["document_info_dict"] = dict2x
    if f.trailers:
        count = 0
        for t in f.trailers:
            if t.id_:
                for file_id in t.id_.id_string:
                    if count == 2:
                        warn("Only two pdfids are allowed for %s, dropping %s", 505, f.id_, file_id)
                    file_ids.append(file_id.value)
                    count += 1
        if len(file_ids) == 2:
            pdf_file_dict["pdfid0"] = file_ids[0]
            pdf_file_dict["pdfid1"] = file_ids[1]
        elif len(file_ids) == 1:
            pdf_file_dict["pdfid0"] = file_ids[0]
    return pdf_file_dict


_PE_FILE_HEADER_PROPERTY_MAP = \
    [["machine", "machine_hex"],
     ["time_date_stamp", "time_date_stamp"],
     ["number_of_sections", "number_of_sections"],
     ["pointer_to_symbol_table", "pointer_to_symbol_table"],
     ["number_of_symbols", "number_of_symbols"],
     ["size_of_optional_header", "size_of_optional_header"],
     ["characteristics", "characteristics_hex"]]

_PE_SECTION_HEADER_PROPERTY_MAP = \
    [["name", "name"],
     ["virtual_size", "size"]]


def convert_windows_executable_file(f):
    w_ex_dict = {}
    if f.headers:
        file_header = f.headers.file_header
        if file_header:
            for prop_tuple in _PE_FILE_HEADER_PROPERTY_MAP:
                prop_name1x = prop_tuple[0]
                prop_name2x = prop_tuple[1]
                if getattr(file_header, prop_name1x, None):
                    w_ex_dict[prop_name2x] = getattr(file_header, prop_name1x).value
            if file_header.hashes is not None:
                w_ex_dict["file_header_hashes"] = convert_hashes(file_header.hashes)
        if f.headers.optional_header:
            warn("file:extensions:'windows-pebinary-ext':optional_header is not implemented yet", 807)

    if f.type_:
        w_ex_dict["pe_type"] = map_vocabs_to_label(f.type_.value, WINDOWS_PEBINARY)
    sections = f.sections
    if sections:
        section_objs = []
        # should order matter in patterns???
        for s in sections:
            section_dict = {}
            if s.section_header:
                for prop_tuple in _PE_SECTION_HEADER_PROPERTY_MAP:
                    prop_name1x = prop_tuple[0]
                    prop_name2x = prop_tuple[1]
                    if getattr(s.section_header, prop_name1x, None):
                        section_dict[prop_name2x] = getattr(s.section_header, prop_name1x).value
            if s.entropy:
                if s.entropy.value:
                    section_dict["entropy"] = s.entropy.value.value
                # there could be multiple sections - need to determine how to handle that for extensions
                if s.entropy.min and not check_for_missing_policy("use-extensions"):
                    handle_missing_string_property(section_dict, "entropy_min", s.entropy.min, None, is_sco=True)
                else:
                    warn("Missing entropy min %s is ignored, because it can't be represented using the extensions policy",
                         314)
                if s.entropy.max and not check_for_missing_policy("use-extensions"):
                    handle_missing_string_property(section_dict, "entropy_max", s.entropy.max, None, is_sco=True)
                else:
                    warn("Missing entropy max %s is ignored, because it can't be represented using the extensions policy",
                         314)
            # need to merge hash lists - worry about duplicate keys
            if s.data_hashes:
                section_dict["hashes"] = convert_hashes(s.data_hashes)
            if s.header_hashes:
                section_dict["hashes"] = convert_hashes(s.header_hashes)
            if section_dict:
                section_objs.append(section_dict)
        if section_objs:
            w_ex_dict["sections"] = section_objs
    if f.exports:
        warn("The exports property of WinExecutableFileObj is not part of STIX 2.x", 418)
    if f.imports:
        warn("The imports property of WinExecutableFileObj is not part of STIX 2.x", 418)
    return w_ex_dict


def convert_archive_file20(f):
    index = 0
    archive_dict = dict()
    file_objs = dict()
    if f.comment:
        archive_dict["comment"] = f.comment
    if f.version:
        archive_dict["version"] = str(f.version)
    if f.archived_file:
        archive_dict["contains_refs"] = list()
        for ar_file in f.archived_file:
            archive_dict["contains_refs"].append(str(index))
            ar_file2x, index = convert_file(ar_file, None, index)
            file_objs.update(ar_file2x)
    return archive_dict, file_objs


def convert_archive_file21(f):
    extensions_dict = dict()
    file_objs = []
    if f.comment:
        if "archive-ext" not in extensions_dict:
            extensions_dict["archive-ext"] = dict()
        extensions_dict["archive-ext"]["comment"] = f.comment
    if f.version:
        if check_for_missing_policy("use-custom-properties"):
            if "archive-ext" not in extensions_dict:
                extensions_dict["archive-ext"] = dict()
            extensions_dict["archive-ext"][convert_to_custom_name("version")] = str(f.version)
        elif check_for_missing_policy("use-extensions"):
            extension_definition_id = get_extension_definition_id("archive-file")
            if not extension_definition_id:
                warn("No extension-definition was found for STIX 1 type archive-file", 312)
            else:
                if extension_definition_id not in extensions_dict:
                    extensions_dict[extension_definition_id] = dict()
                extensions_dict[extension_definition_id]["version"] = str(f.version)
                extensions_dict[extension_definition_id]["extension_type"] = "property-extension"
    if f.archived_file:
        if "archive-ext" not in extensions_dict:
            extensions_dict["archive-ext"] = dict()
        for ar_file in f.archived_file:
            ar_file2x = convert_file(ar_file, None)
            file_objs.extend(ar_file2x)
        extensions_dict["archive-ext"]["contains_refs"] = [x["id"] for x in file_objs]
    return extensions_dict, file_objs


_DIRECTORY_SCOS = {}


def add_to_directory_mapping(id_, sco):
    global _DIRECTORY_SCOS
    _DIRECTORY_SCOS[id_] = sco


def id_in_directory_mapping(id_):
    return id_ in _DIRECTORY_SCOS


def get_sco_from_directory_mapping(id_):
    return _DIRECTORY_SCOS[id_]


def clear_directory_mappings():
    global _DIRECTORY_SCOS
    _DIRECTORY_SCOS = {}


_DIRECTORY_PATHS = {}


def add_to_directory_path_mapping(path, index):
    global _DIRECTORY_PATHS
    _DIRECTORY_PATHS[path] = index


def index_in_directory_path_mapping(path):
    return path in _DIRECTORY_PATHS


def get_index_from_directory_path_mapping(path):
    return _DIRECTORY_PATHS[path]


def clear_directory_path_mappings():
    global _DIRECTORY_PATHS
    _DIRECTORY_PATHS = {}


def convert_file_properties(f):
    file_dict = create_base_sco("file", f)
    obj1x_id = f.parent.id_
    extended_properties = {}
    dir_dict = None
    if f.size is not None:
        if isinstance(f.size.value, list):
            warn("File size 'window' not allowed in top level observable, using first value", 511)
            file_dict["size"] = int(f.size.value[0])
        else:
            file_dict["size"] = int(f.size)
    if f.created_time:
        if get_option_value("spec_version") == "2.0":
            file_dict["created"] = f.created_time
        else:
            file_dict["ctime"] = f.created_time
    if f.modified_time:
        if get_option_value("spec_version") == "2.0":
            file_dict["modified"] = f.modified_time
        else:
            file_dict["mtime"] = f.modified_time
    if f.accessed_time:
        if get_option_value("spec_version") == "2.0":
            file_dict["accessed"] = f.accessed_time
        else:
            file_dict["atime"] = f.accessed_time
    if f.hashes is not None:
        hashes = {}
        for h in f.hashes:
            if str(h.type_).startswith("SHA"):
                hash_type = "SHA" + "-" + str(h.type_)[3:]
            elif str(h.type_) == "SSDEEP":
                hash_type = str(h.type_).lower()
            else:
                hash_type = str(h.type_)
            hashes[hash_type] = h.simple_hash_value.value
        file_dict["hashes"] = hashes
    if f.file_name:
        file_dict["name"] = str(f.file_name)
        if f.file_extension:
            file_dict["name"] += "." + str(f.file_extension)
    elif f.file_path and f.file_path.value:
        # this index is an array index, not for the objects dict
        index = f.file_path.value.rfind("/")
        if index == -1:
            index = f.file_path.value.rfind("\\")
        if not (f.file_path.value.endswith("/") or f.file_path.value.endswith("\\")):
            file_dict["name"] = f.file_path.value[index + 1:]
        dir_path = f.file_path.value[0: index]
        if dir_path:
            full_path = f.device_path.value if f.device_path else ""
            dir_dict = create_base_sco("directory", other_properties={"path": full_path + dir_path})
            generate_sco_id_for_2_1(dir_dict, None)
    if f.full_path:
        warn("1.x full file paths are not processed, yet", 802)
    if isinstance(f, WinExecutableFile):
        windows_executable_file_dict = convert_windows_executable_file(f)
        if windows_executable_file_dict:
            extended_properties["windows-pebinary-ext"] = windows_executable_file_dict
        else:
            warn("No WinExecutableFile properties found in %s", 613, str(f))
    if isinstance(f, ArchiveFile):
        if get_option_value("spec_version") == "2.0":
            archive_file_dict, file_objs = convert_archive_file20(f)
            if archive_file_dict:
                extended_properties["archive-ext"] = archive_file_dict
        else:
            archive_file_dict, file_objs = convert_archive_file21(f)
            if archive_file_dict:
                extended_properties.update(archive_file_dict)
        if not archive_file_dict:
            warn("No ArchiveFile properties found in %s", 613, str(f))
    else:
        file_objs = None
    if isinstance(f, ImageFile):
        image_file_dict = convert_image_file(f)
        if image_file_dict:
            extended_properties["raster-image-ext"] = image_file_dict
        else:
            warn("No ImageFile properties found in %s", 613, str(f))
    if isinstance(f, PDFFile):
        pdf_file_dict = convert_pdf_file(f)
        if pdf_file_dict:
            extended_properties["pdf-ext"] = pdf_file_dict
        else:
            warn("No ImageFile properties found in %s", 613, str(f))
    if extended_properties:
        file_dict["extensions"] = extended_properties
    generate_sco_id_for_2_1(file_dict, obj1x_id)
    return file_dict, dir_dict, file_objs


def convert_file20(f, related_objects, index=0):
    objs = {}
    file_obj_index = index
    objs[str(index)], dir_dict, file_objs = convert_file_properties(f)
    if dir_dict:
        if index_in_directory_path_mapping(dir_dict["path"]):
            objs[str(index)]["parent_directory_ref"] = str(get_index_from_directory_path_mapping(dir_dict["path"]))
            index += 1
        else:
            objs[str(index + 1)] = dir_dict
            add_to_directory_path_mapping(dir_dict["path"], index + 1)
            objs[str(index)]["parent_directory_ref"] = str(index + 1)
            index += 2
    if file_objs:
        number_mapping = {}
        for k in sorted(file_objs.keys()):
            number_mapping[str(k)] = str(index)
            index += 1
        new_objs = renumber_objs(file_objs, number_mapping)
        objs.update(new_objs)
        renumber_co(objs[str(file_obj_index)], number_mapping)
    return objs, index


def convert_file21(f, related_objects):
    file_dict, dir_dict, file_objs = convert_file_properties(f)
    objs = [file_dict]
    if dir_dict:
        objs.append(dir_dict)
        file_dict["parent_directory_ref"] = dir_dict["id"]
    if file_objs:
        for obj in file_objs:
            if not id_in_directory_mapping(obj["id"]):
                objs.append(obj)
                add_to_directory_mapping(dir_dict["id"], dir_dict)
    handle_related_objects_as_embedded_relationships(file_dict, related_objects, "Contains", "contains_refs")
    handle_related_objects_as_embedded_relationships(file_dict, related_objects, "Contains", "content_ref")
    return objs


def convert_file(f, related_objects, index=0):
    if get_option_value("spec_version") == "2.0":
        return convert_file20(f, related_objects, index)
    else:
        return convert_file21(f, related_objects)


def convert_attachment(attachment):
    info("content_type for body_multipart of attachment %s is assumed to be 'text/plain'", 722, attachment.object_reference)
    return {"body_raw_ref": attachment.object_reference, "content_type": "text/plain"}


_EMAIL_ADDITIONAL_HEADERS_PROPERTIES = {
    "In-Reply-To": "in_reply_to",
    "Errors-To": "errors_to",
    "MIME-Version": "mime_version",
    "Precedence": "precedence",
    "User-Agent:": "user_agent",
    "Boundary": "boundary",
    "X-Priority": "x_priority",
    "X-Mailer": "x_mailer"
}


def convert_email_additional_headers(head):
    additional_header_fields_dict = dict()
    for key2x, prop1x in _EMAIL_ADDITIONAL_HEADERS_PROPERTIES.items():
        if hasattr(head, prop1x):
            value = getattr(head, prop1x)
            if value:
                additional_header_fields_dict[key2x] = str(value)
    if head.in_reply_to:
        to_list = list()
        for to in head.in_reply_to:
            to_list.append(str(to.address_value))
        additional_header_fields_dict["In-Reply-To"] = to_list
    if head.x_originating_ip:
        additional_header_fields_dict["X-Originating-IP"] = head.x_originating_ip.address_value
    if head.received_lines:
        warn("Email received lines not handled yet", 806)
    return additional_header_fields_dict


def handle_missing_properties_of_email_message(sco_instance, email_message):
    container, extension_definition_id = determine_container_for_missing_properties("email-message", sco_instance)

    if container is not None:
        if email_message.links:
            if not (check_for_missing_policy("add-to-description") or check_for_missing_policy("ignore")):
                # this would be to another observable - which is not allowed in 2.0
                if get_option_value("spec_version") == "2.1":
                    if check_for_missing_policy("use-custom-properties"):
                        property_name = convert_to_custom_name("link_refs")
                        warn("Used custom property for %s", 308, "links")
                    elif check_for_missing_policy("use-extensions"):
                        property_name = "link_refs"
                        warn("Used extension property for %s", 313, "links")
                    container[property_name] = list()
                    for link in email_message.links:
                        sco_id = get_id_value(link.object_reference)
                        container[property_name].extend(sco_id)
                else:
                    warn("Observed Data objects cannot refer to other external objects (in STIX 2.0): %s in %s",
                         434, "links", "email-message")
            else:
                warn("Missing property '%s' is ignored", 307, "links")
        if get_option_value("spec_version") == "2.0":
            if email_message.header.message_id:
                handle_missing_string_property(container, "message_id", email_message.header.message_id, None, is_sco=True)
        fill_in_extension_properties(sco_instance, container, extension_definition_id)


def convert_email_message(email_message):
    index = 0
    spec_version = get_option_value("spec_version")
    email_dict = create_base_sco("email-message", email_message, {"is_multipart": False})  # the default
    if spec_version == "2.0":
        objs = dict()
        objs[str(index)] = email_dict
    else:
        objs = [email_dict]
    index += 1
    if email_message.header:
        header = email_message.header
        if header.date:
            email_dict["date"] = convert_timestamp_to_string(header.date.value)
        if header.content_type:
            email_dict["content_type"] = str(header.content_type)
        if header.subject:
            email_dict["subject"] = str(header.subject)
        if header.from_:
            # should there ever be more than one?
            from_ref = convert_address(header.from_)
            if spec_version == "2.0":
                objs[str(index)] = from_ref
            else:
                objs.append(from_ref)
            email_dict["from_ref"] = str(index) if spec_version == "2.0" else from_ref["id"]
            index += 1
        if header.sender:
            # should there ever be more than one?
            sender_ref = convert_address(header.sender)
            if spec_version == "2.0":
                objs[str(index)] = sender_ref
            else:
                objs.append(sender_ref)
            email_dict["sender_ref"] = str(index) if spec_version == "2.0" else from_ref["id"]
            index += 1
        if header.to:
            for t in header.to:
                to_ref = convert_address(t)
                if spec_version == "2.0":
                    objs[str(index)] = to_ref

                else:
                    objs.append(to_ref)
                if "to_refs" not in email_dict:
                    email_dict["to_refs"] = []
                email_dict["to_refs"].append(str(index) if spec_version == "2.0" else to_ref["id"])
                index += 1
        if header.cc:
            for t in header.cc:
                cc_ref = convert_address(t)
                if spec_version == "2.0":
                    objs[str(index)] = cc_ref

                else:
                    objs.append(cc_ref)
                if "cc_refs" not in email_dict:
                    email_dict["cc_refs"] = []
                email_dict["cc_refs"].append(str(index) if spec_version == "2.0" else cc_ref["id"])
                index += 1
        if header.bcc:
            for t in header.bcc:
                bcc_ref = convert_address(t)
                if spec_version == "2.0":
                    objs[str(index)] = bcc_ref
                    index += 1
                else:
                    objs.append(bcc_ref)
                if "bcc_refs" not in email_dict:
                    email_dict["bcc_refs"] = []
                email_dict["bcc_refs"].append(str(index) if spec_version == "2.0" else bcc_ref["id"])
        if header.message_id:
            if spec_version == "2.1":
                email_dict["message_id"] = str(header.message_id)
        add_headers2x = convert_email_additional_headers(header)
        if add_headers2x != {}:
            email_dict["additional_header_fields"] = add_headers2x
    if email_message.attachments:
        email_dict["is_multipart"] = True
        multiparts = []
        for a in email_message.attachments:
            multiparts.append(convert_attachment(a))
        email_dict["body_multipart"] = multiparts

    if email_message.raw_body:
        raw_body_obj = create_base_sco("artifact", other_properties={"payload_bin": encode_in_base64(str(email_message.raw_body))})
        generate_sco_id_for_2_1(raw_body_obj, None)
        if get_option_value("spec_version") == "2.0":
            if raw_body_obj:
                email_dict["raw_email_ref"] = str(index)
                objs[str(index)] = raw_body_obj
                index += 1
        else:
            if raw_body_obj:
                email_dict["raw_email_ref"] = raw_body_obj["id"]
                objs.append(raw_body_obj)
    generate_sco_id_for_2_1(email_dict, email_message.parent.id_)
    handle_missing_properties_of_email_message(email_dict, email_message)
    return objs


def convert_registry_key(reg_key):
    cybox_reg = create_base_sco("windows-registry-key", reg_key)
    user_obj = None
    if reg_key.key or reg_key.hive:
        full_key = ""
        if reg_key.hive:
            full_key += reg_key.hive.value + "\\"
        if reg_key.key:
            full_key += reg_key.key.value
        cybox_reg["key"] = full_key
    else:
        error("windows-registry-key is required to have a key property", 608)
    if reg_key.values:
        cybox_reg["values"] = []
        for v in reg_key.values:
            reg_value = {}
            if hasattr(v, "data") and v.data:
                reg_value["data"] = str(v.data)
            if hasattr(v, "name") and v.name:
                reg_value["name"] = str(v.name)
            if hasattr(v, "datatype") and v.datatype:
                reg_value["data_type"] = str(v.datatype)
            cybox_reg["values"].append(reg_value)
    if reg_key.modified_time:
        if get_option_value("spec_version") == "2.0":
            cybox_reg["modified"] = convert_timestamp_to_string(reg_key.modified_time.value)
        else:
            cybox_reg["modified_time"] = convert_timestamp_to_string(reg_key.modified_time.value)
    generate_sco_id_for_2_1(cybox_reg, reg_key.parent.id_)
    if reg_key.creator_username:
        user_obj = create_base_sco("user-account", other_properties={"user_id": str(reg_key.creator_username)})
        generate_sco_id_for_2_1(user_obj, None)
    if get_option_value("spec_version") == "2.0":
        result = dict()
        result["0"] = cybox_reg
        if user_obj:
            cybox_reg["creator_user_ref"] = "1"
            result["1"] = user_obj
    else:
        result = [cybox_reg]
        if user_obj:
            cybox_reg["creator_user_ref"] = user_obj["id"]
            result.append(user_obj)
    return result


def create_process_ref(cp, process_dict, objs, index, prop):
    spec_version = get_option_value("spec_version")
    cp_ref = create_base_sco("process", other_properties={"pid": cp.value})
    if get_option_value("spec_version") == "2.0":
        objs[str(index)] = cp_ref
    else:
        generate_sco_id_for_2_1(cp_ref, None)
        objs.append(cp_ref)
    if prop == "child_refs":
        if prop not in process_dict:
            process_dict["child_refs"] = []
        if spec_version == "2.0":
            process_dict[prop].append(str(index))
        else:
            process_dict[prop].append(cp_ref["id"])
    else:  # parent_ref
        if spec_version == "2.0":
            process_dict[prop] = str(index)
        else:
            process_dict[prop] = cp_ref["id"]


def convert_port(prop):
    traffic_2x = create_base_sco("network-traffic", prop)
    if prop.port_value:
        warn("port number is assumed to be a destination port", 725)
        traffic_2x["dst_port"] = prop.port_value.value
    if prop.layer4_protocol:
        traffic_2x["protocols"] = [prop.layer4_protocol.value.lower()]
    generate_sco_id_for_2_1(traffic_2x, prop.parent.id_)
    return traffic_2x


def convert_opened_connection_refs20(process, process_dict, objs, index):
    renumbered_nc_dicts = {}
    process_dict["opened_connection_refs"] = []
    for nc in process.network_connection_list:
        nc_dicts = convert_network_connection(nc, None)
        root_obj_index = find_index_of_type(nc_dicts, "network-traffic")
        current_largest_id, number_mapping = do_renumbering(nc_dicts,
                                                            index,
                                                            root_obj_index,
                                                            renumbered_nc_dicts)
        objs.update(renumbered_nc_dicts)
        process_dict["opened_connection_refs"].append(str(number_mapping[root_obj_index]))
        index = current_largest_id
    return index


def convert_opened_connection_refs21(process, process_dict, objs):
    process_dict["opened_connection_refs"] = []
    for nc in process.network_connection_list:
        nc_dicts = convert_network_connection(nc, None)
        for obj in nc_dicts:
            objs.append(obj)
        # network-traffic is always the first obj
        process_dict["opened_connection_refs"].append(nc_dicts[0]["id"])


def convert_process(process):
    index = 0
    process_dict = create_base_sco("process", process)
    if get_option_value("spec_version") == "2.0":
        objs = dict()
        objs[str(index)] = process_dict
        index += 1
    else:
        objs = [process_dict]

    if process.name and get_option_value("spec_version") == "2.0":
        process_dict["name"] = str(process.name)
    if process.pid:
        process_dict["pid"] = process.pid.value
    if process.creation_time:
        process_dict["created" if get_option_value("spec_version") == "2.0" else "created_time"] = \
            convert_timestamp_to_string(process.creation_time.value)
    if process.argument_list and get_option_value("spec_version") == "2.0":
        process_dict["arguments"] = []
        for a in process.argument_list:
            process_dict["arguments"].append(a.value)
        # TODO: if its 2.1 and there are arguments, but no Image_Info.command_line, we could maybe create one
    if process.network_connection_list:
        if get_option_value("spec_version") == "2.0":
            index = convert_opened_connection_refs20(process, process_dict, objs, index)
        else:
            convert_opened_connection_refs21(process, process_dict, objs)
    if process.image_info:
        ii = process.image_info
        if ii.file_name:
            # TODO: check ii.current_directory and ii.path for more info
            image_obj = create_base_sco("file", other_properties={"name": str(ii.file_name)})
            generate_sco_id_for_2_1(image_obj, None)
            if get_option_value("spec_version") == "2.0":
                process_dict["image_ref"] = str(index)
                objs[str(index)] = image_obj
                index += 1
            else:
                process_dict["image_ref"] = image_obj["id"]
                objs.append(image_obj)
        if ii.command_line and get_option_value("spec_version") == "2.1":
            process_dict["command_line"] = str(ii.command_line)
    if process.username:
        user_obj = create_base_sco("user-account", other_properties={"user_id": str(process.username)})
        generate_sco_id_for_2_1(user_obj, None)
        if get_option_value("spec_version") == "2.0":
            process_dict["creator_user_ref"] = str(index)
            objs[str(index)] = user_obj
            index += 1
        else:
            process_dict["creator_user_ref"] = user_obj["id"]
            objs.append(user_obj)
    if isinstance(process, WinProcess):
        extended_properties = dict()
        process_properties = convert_windows_process(process)
        if process_properties:
            extended_properties["windows-process-ext"] = process_properties

        if isinstance(process, WinService):
            service_properties, dll_file_obj = convert_windows_service(process)
            if service_properties:
                extended_properties["windows-service-ext"] = service_properties
            if dll_file_obj:
                if get_option_value("spec_version") == "2.0":
                    objs[str(index)] = dll_file_obj
                    index += 1
                else:
                    objs.append(dll_file_obj)

        if extended_properties:
            process_dict["extensions"] = extended_properties
    generate_sco_id_for_2_1(process_dict, process.parent.id_)
    if process.child_pid_list:
        for cp in process.child_pid_list:
            create_process_ref(cp, process_dict, objs, index, "child_refs")
            index += 1
    if process.parent_pid:
        create_process_ref(process.parent_pid, process_dict, objs, index, "parent_ref")
        index += 1
    return objs


def convert_windows_process(process):
    ext = {}
    if process.handle_list:
        for h in process.handle_list:
            warn("Windows handles are not a part of STIX 2.x", 420)
    if process.aslr_enabled:
        ext["asl_enabled"] = bool(process.aslr_enabled)
    if process.dep_enabled:
        ext["dep_enabled"] = bool(process.dep_enabled)
    if process.priority:
        ext["priority"] = str(process.priority)
    if process.security_id:
        ext["owner_sid"] = str(process.security_id)
    if process.window_title:
        ext["window_title"] = str(process.window_title)
    if process.startup_info:
        warn("CybOX object %s not handled yet not handled yet", 805, "process:startup_info")
    return ext


def convert_windows_service(service):
    cybox_ws = {}
    if hasattr(service, "service_name") and service.service_name:
        cybox_ws["service_name"] = service.service_name.value
    if hasattr(service, "description_list") and service.description_list:
        descriptions = []
        for d in service.description_list:
            descriptions.append(d.value)
        cybox_ws["descriptions"] = descriptions
    if hasattr(service, "display_name") and service.display_name:
        cybox_ws["display_name"] = service.display_name.value
    if hasattr(service, "startup_command_line") and service.startup_command_line:
        cybox_ws["startup_command_line"] = service.startup_command_line.value
    if hasattr(service, "startup_type") and service.startup_type:
        cybox_ws["start_type"] = map_vocabs_to_label(service.startup_type, SERVICE_START_TYPE)
    if hasattr(service, "service_type") and service.service_type:
        cybox_ws["service_type"] = map_vocabs_to_label(service.service_type, SERVICE_TYPE)
    if hasattr(service, "service_status") and service.service_status:
        cybox_ws["service_status"] = map_vocabs_to_label(service.service_status, SERVICE_STATUS)
    if hasattr(service, "service_dll") and service.service_dll:
        # There is only one in STIX 1.x
        ddl_file2x = create_base_sco("file", other_properties={"name": str(service.service_dll)})
        generate_sco_id_for_2_1(ddl_file2x, None)
        if get_option_value("spec_version") == "2.1":
            cybox_ws["service_dll_refs"] = [ddl_file2x["id"]]
        return cybox_ws, ddl_file2x
    return cybox_ws, None


def convert_domain_name(domain_name, related_objects):
    cybox_dm = create_base_sco("domain-name", domain_name)
    if domain_name.value:
        cybox_dm["value"] = str(domain_name.value.value)
    handle_related_objects_as_embedded_relationships(cybox_dm, related_objects, "Resolved_To", "resolves_to_refs")
    generate_sco_id_for_2_1(cybox_dm, domain_name.parent.id_)
    return cybox_dm


def convert_mutex(mutex):
    cybox_mutex = create_base_sco("mutex", mutex)
    if mutex.name:
        cybox_mutex["name"] = str(mutex.name.value)
    generate_sco_id_for_2_1(cybox_mutex, mutex.parent.id_)
    return cybox_mutex


def convert_http_client_request(request):
    http_extension = {}
    body_obj = None
    if request.http_request_line is not None:
        if request.http_request_line.http_method is not None:
            http_extension["request_method"] = str(request.http_request_line.http_method.value.lower())
        if request.http_request_line.value is not None:
            http_extension["request_value"] = str(request.http_request_line.value.value.lower())
        if request.http_request_line.version is not None:
            http_extension["request_version"] = str(request.http_request_line.version.value.lower())

    if request.http_request_header is not None:
        if request.http_request_header.parsed_header is not None:
            header = {}
            if request.http_request_header.parsed_header.accept is not None:
                header["Accept"] = str(request.http_request_header.parsed_header.accept.value)
            if request.http_request_header.parsed_header.accept_charset is not None:
                header["Accept-Charset"] = str(request.http_request_header.parsed_header.accept_charset.value)
            if request.http_request_header.parsed_header.accept_language is not None:
                header["Accept-Language"] = str(request.http_request_header.parsed_header.accept_language.value)
            if request.http_request_header.parsed_header.accept_datetime is not None:
                header["Accept-Datetime"] = str(request.http_request_header.parsed_header.accept_datetime.value)
            if request.http_request_header.parsed_header.accept_encoding is not None:
                header["Accept-Encoding"] = str(request.http_request_header.parsed_header.accept_encoding.value)
            if request.http_request_header.parsed_header.authorization is not None:
                header["Authorization"] = str(request.http_request_header.parsed_header.authorization.value)
            if request.http_request_header.parsed_header.cache_control is not None:
                header["Cache-Control"] = str(request.http_request_header.parsed_header.cache_control.value)
            if request.http_request_header.parsed_header.connection is not None:
                header["Connection"] = str(request.http_request_header.parsed_header.connection.value)
            if request.http_request_header.parsed_header.cookie is not None:
                header["Cookie"] = str(request.http_request_header.parsed_header.cookie.value)
            if request.http_request_header.parsed_header.content_length is not None:
                header["Content-Length"] = str(request.http_request_header.parsed_header.content_length.value)
            if request.http_request_header.parsed_header.content_md5 is not None:
                header["Content-MD5"] = str(request.http_request_header.parsed_header.content_md5.value)
            if request.http_request_header.parsed_header.content_type is not None:
                header["Content-Type"] = str(request.http_request_header.parsed_header.content_type.value)
            if request.http_request_header.parsed_header.date is not None:
                header["Date"] = str(request.http_request_header.parsed_header.date)
            if request.http_request_header.parsed_header.expect is not None:
                header["Expect"] = str(request.http_request_header.parsed_header.expect.value)
            if request.http_request_header.parsed_header.from_ is not None:
                from_ = request.http_request_header.parsed_header.from_
                if from_.address_value is not None:
                    header["From"] = str(from_.address_value.value)
            if request.http_request_header.parsed_header.host is not None:
                host = request.http_request_header.parsed_header.host
                value = ""
                has_domain = False
                if host.domain_name is not None:
                    has_domain = True
                    value += str(host.domain_name.value)
                if host.port is not None:
                    if has_domain:
                        value += ":" + str(host.port.port_value)
                    else:
                        value += str(host.port.port_value)
                if value:
                    header["Host"] = value
            if request.http_request_header.parsed_header.if_match is not None:
                header["If-Match"] = str(request.http_request_header.parsed_header.if_match.value)
            if request.http_request_header.parsed_header.if_modified_since is not None:
                header["If-Modified-Since"] = str(
                    request.http_request_header.parsed_header.if_modified_since.value)
            if request.http_request_header.parsed_header.if_none_match is not None:
                header["If-None-Match"] = str(request.http_request_header.parsed_header.if_none_match.value)
            if request.http_request_header.parsed_header.if_range is not None:
                header["If-Range"] = str(request.http_request_header.parsed_header.if_range.value)
            if request.http_request_header.parsed_header.if_unmodified_since is not None:
                header["If-Unmodified-Since"] = str(
                    request.http_request_header.parsed_header.if_unmodified_since.value)
            if request.http_request_header.parsed_header.max_forwards is not None:
                header["Max-Forwards"] = str(request.http_request_header.parsed_header.max_forwards.value)
            if request.http_request_header.parsed_header.pragma is not None:
                header["Pragma"] = str(request.http_request_header.parsed_header.pragma.value)
            if request.http_request_header.parsed_header.proxy_authorization is not None:
                header["Proxy-Authorization"] = str(
                    request.http_request_header.parsed_header.proxy_authorization.value)
            if request.http_request_header.parsed_header.range_ is not None:
                header["Range"] = str(request.http_request_header.parsed_header.range_.value)
            if request.http_request_header.parsed_header.referer is not None:
                header["Referer"] = str(request.http_request_header.parsed_header.referer.value)
            if request.http_request_header.parsed_header.te is not None:
                header["TE"] = str(request.http_request_header.parsed_header.te.value)
            if request.http_request_header.parsed_header.user_agent is not None:
                header["User-Agent"] = str(request.http_request_header.parsed_header.user_agent.value)
            if request.http_request_header.parsed_header.via is not None:
                header["Via"] = str(request.http_request_header.parsed_header.via.value)
            if request.http_request_header.parsed_header.warning is not None:
                header["Warning"] = str(request.http_request_header.parsed_header.warning.value)
            if request.http_request_header.parsed_header.dnt is not None:
                header["DNT"] = str(request.http_request_header.parsed_header.dnt.value)
            if request.http_request_header.parsed_header.x_requested_with is not None:
                header["X-Requested-With"] = str(request.http_request_header.parsed_header.x_requested_with.value)
            if request.http_request_header.parsed_header.x_forwarded_for is not None:
                header["X-Forwarded-For"] = str(request.http_request_header.parsed_header.x_forwarded_for.value)
            if request.http_request_header.parsed_header.x_att_deviceid is not None:
                header["X-ATT-DeviceId"] = str(request.http_request_header.parsed_header.x_att_deviceid.value)
            if request.http_request_header.parsed_header.x_wap_profile is not None:
                header["X-Wap-Profile"] = str(request.http_request_header.parsed_header.x_wap_profile.value)

            http_extension["request_header"] = header
    if request.http_message_body is not None:
        mb = request.http_message_body
        if mb.length:
            http_extension["message_body_length"] = mb.length.value
        if mb.message_body:
            body_obj = create_base_sco("artifact", other_properties={"payload_bin": encode_in_base64(str(mb.message_body))})
            generate_sco_id_for_2_1(body_obj, None)
            if get_option_value("spec_version") == "2.1":
                http_extension["message_body_data_ref"] = body_obj["id"]
            else:
                http_extension["message_body_data_ref"] = "1"
    return http_extension, body_obj


def convert_http_network_connection_extension(http):
    if http is not None:
        return convert_http_client_request(http.http_client_request)


def create_domain_name_object(dn):
    instance = create_base_sco("domain-name", dn, other_properties={"value": str(dn.value)})
    generate_sco_id_for_2_1(instance, None)
    return instance


def convert_socket_address_1(sock_add_1x, cybox_traffic, objs, spec_version, index, src_or_dst, env):
    if sock_add_1x.port is not None:
        if sock_add_1x.port.port_value is not None:
            cybox_traffic[src_or_dst + "_port"] = int(sock_add_1x.port.port_value)
        if sock_add_1x.port.layer4_protocol is not None:
            cybox_traffic["protocols"].append(str(sock_add_1x.port.layer4_protocol.value.lower()))
    if sock_add_1x.ip_address is not None:
        add = convert_address(sock_add_1x.ip_address, env=env)
        if spec_version == "2.0":
            cybox_traffic[src_or_dst + "_ref"] = str(index)
            # its a 2.0 object, remove its uuid, if it has one
            if "id" in add:
                del add["id"]
            objs[str(index)] = add
            index += 1
        else:
            if add:
                cybox_traffic[src_or_dst + "_ref"] = add["id"]
                objs.append(add)

    elif sock_add_1x.hostname is not None:
        if sock_add_1x.hostname.is_domain_name and sock_add_1x.hostname.hostname_value is not None:
            domain = create_domain_name_object(sock_add_1x.hostname.hostname_value)
            cybox_traffic[src_or_dst + "_ref"] = str(index) if spec_version == "2.0" else domain["id"]
            if spec_version == "2.0":
                # its a 2.0 object, remove its uuid, if it has one
                if "id" in domain:
                    del domain["id"]
                objs[str(index)] = domain
                index += 1
            else:
                objs.append(domain)

        elif (sock_add_1x.hostname.naming_system is not None and
              any(x.value == "DNS" for x in sock_add_1x.hostname.naming_system)):
            domain = create_domain_name_object(sock_add_1x.hostname.hostname_value)
            cybox_traffic[src_or_dst + "_ref"] = str(index) if spec_version == "2.0" else domain["id"]
            if spec_version == "2.0":
                # its a 2.0 object, remove its uuid, if it has one
                if "id" in domain:
                    del domain["id"]
                objs[str(index)] = domain
                index += 1
            else:
                objs.append(domain)
    return index


def add_http_protocol(cybox_traffic, conn):
    if "http" not in cybox_traffic["protocols"] and "https" not in cybox_traffic["protocols"] and not conn.tls_used:
        cybox_traffic["protocols"].append("http")
    if "https" not in cybox_traffic["protocols"] and conn.tls_used:
        cybox_traffic["protocols"].append("https")


def convert_network_connection(conn, env=None):
    # start at 1 - the main object will be put into "0" later
    index = 1
    spec_version = get_option_value("spec_version")
    cybox_traffic = create_base_sco("network-traffic", conn)
    if spec_version == "2.0":
        objs = {}
    else:
        objs = []

    if conn.creation_time is not None:
        cybox_traffic["start"] = convert_timestamp_to_string(conn.creation_time.value, None, None)

    if conn.layer3_protocol is not None:
        if "protocols" not in cybox_traffic:
            cybox_traffic["protocols"] = []
        cybox_traffic["protocols"].append(str(conn.layer3_protocol.value).lower())

    if conn.source_socket_address is not None:
        # The source, if present will have index "0".
        index = convert_socket_address_1(conn.source_socket_address, cybox_traffic, objs, spec_version, index, "src", env)

    if conn.destination_socket_address is not None:
        # The destination will have index "1" if there is a source.
        index = convert_socket_address_1(conn.destination_socket_address, cybox_traffic, objs, spec_version, index, "dst", env)

    if conn.layer4_protocol is not None:
        if "protocols" not in cybox_traffic:
            cybox_traffic["protocols"] = []
        cybox_traffic["protocols"].append(str(conn.layer4_protocol.value).lower())

    if conn.layer7_protocol is not None:
        if "protocols" not in cybox_traffic:
            cybox_traffic["protocols"] = []
        cybox_traffic["protocols"].append(str(conn.layer7_protocol.value).lower())

    if conn.layer7_connections is not None:
        if conn.layer7_connections.http_session is not None:
            if conn.layer7_connections.http_session.object_reference:
                nt = handle_object_reference(conn.layer7_connections.http_session, "network-traffic", env, "extensions")
                add_http_protocol(cybox_traffic, conn)
                cybox_traffic["extensions"] = nt["extensions"]
            else:
                # HTTP extension
                request_responses = conn.layer7_connections.http_session.http_request_response
                if request_responses:
                    cybox_traffic["extensions"] = dict()
                    add_http_protocol(cybox_traffic, conn)
                    request_ext, body_obj = convert_http_network_connection_extension(request_responses[0])
                    cybox_traffic["extensions"]["http-request-ext"] = request_ext
                    if body_obj:
                        if get_option_value("spec_version") == "2.0":
                            objs[str(index)] = body_obj
                            request_ext["message_body_data_ref"] = str(index)
                            index += 1
                        else:
                            objs.append(body_obj)
                    if len(conn.layer7_connections.http_session.http_request_response) > 1:
                        warn("Only one HTTP_Request_Response used for http-request-ext, using first value", 512)
        if conn.layer7_connections.dns_query:
            warn("Layer7_Connections/DNS_Query content not supported in STIX 2.x", 424)

    if cybox_traffic:
        cybox_traffic["type"] = "network-traffic"
        if spec_version == "2.0":
            objs["0"] = cybox_traffic
        else:
            generate_sco_id_for_2_1(cybox_traffic, conn.parent.id_)
            # network traffic object must be first
            objs.insert(0, cybox_traffic)

    # no STIX 1.x date for the following STIX 2.x properties:
    #   end, is_active,
    # cybox_traffic["encapsulates_refs"]
    # cybox_traffic["encapsulated_by_ref"]

    # STIX 1.x network_flow might work for: ipfix, src_byte_count, dst_byte_count, src_packets, dst_packets, start?, end?

    # cybox_traffic["src_payload_ref"]?
    # cybox_traffic["dst_payload_ref"]?

    return objs


def split_into_requests_and_responses(req_resp_list):
    requests = []
    responses = []
    for r in req_resp_list:
        if r.http_client_request:
            requests.append(r.http_client_request)
        if r.http_server_response:
            responses.append(r.http_server_response)
    return requests, responses


def convert_http_session(session):
    if session.http_request_response:
        requests, responses = split_into_requests_and_responses(session.http_request_response)
        if len(responses) != 0:
            warn("HTTPServerResponse type is not supported in STIX 2.x", 429)
        if len(requests) >= 1:
            cybox_traffic = create_base_sco("network-traffic", session)
            request_ext, body_obj = convert_http_client_request(requests[0])
            cybox_traffic["extensions"] = {"http-request-ext": request_ext}
            if "protocols" not in cybox_traffic:
                cybox_traffic["protocols"] = list()
            if "http" not in cybox_traffic["protocols"] and "https" not in cybox_traffic["protocols"]:
                cybox_traffic["protocols"].append("http")
            if len(requests) > 1:
                warn("Only HTTP_Request_Response used for http-request-ext, using first value", 512)
            if get_option_value("spec_version") == "2.0":
                objs = dict()
                objs["0"] = cybox_traffic
                if body_obj:
                    objs["1"] = body_obj
                return objs
            else:
                generate_sco_id_for_2_1(cybox_traffic, session.parent.id_)
                if body_obj:
                    return [cybox_traffic, body_obj]
                else:
                    return [cybox_traffic]


def handle_extensions_of_icmp_extension(icmp_header, imcp_extension, cybox_traffic):
    container, extension_definition_id = determine_container_for_missing_properties("icmp_header", imcp_extension)

    if container is not None:
        if icmp_header.checksum:
            handle_missing_string_property(container, "checksum", icmp_header.checksum, None, is_sco=True)

        fill_in_extension_properties(cybox_traffic, container, extension_definition_id)


def create_icmp_extension(icmp_header, imcp_extension, cybox_traffic):
    if icmp_header.type_:
        imcp_extension["icmp_type_hex"] = icmp_header.type_.value
    if icmp_header.code:
        imcp_extension["icmp_code_hex"] = icmp_header.code.value
    handle_extensions_of_icmp_extension(icmp_header, imcp_extension, cybox_traffic)
    return imcp_extension


def convert_network_packet(packet):
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
            cybox_traffic = create_base_sco("network-traffic", packet)
            imcp_extension = {}
            cybox_traffic["extensions"] = {"icmp-ext": imcp_extension}
            create_icmp_extension(icmp_header, imcp_extension, cybox_traffic)
            if "protocols" not in cybox_traffic:
                cybox_traffic["protocols"] = list()
            if "icmp" not in cybox_traffic["protocols"]:
                cybox_traffic["protocols"].append("icmp")
            generate_sco_id_for_2_1(cybox_traffic, packet.parent.id_)
            return cybox_traffic


def convert_socket_options(options):
    socket_options = {}
    for prop_name in SOCKET_OPTIONS:
        if getattr(options, prop_name):
            value = getattr(options, prop_name)
            if isinstance(value, bool):
                value = 1 if value else 0
            socket_options[prop_name.upper()] = value
    return socket_options


def handle_extensions_of_network_socket(socket, socket_extension, cybox_traffic):
    container, extension_definition_id = determine_container_for_missing_properties("network-socket", socket_extension)

    if container is not None:
        sco_id = cybox_traffic["id"] if "id" in cybox_traffic else None
        if socket.domain:
            if get_option_value("spec_version") == "2.0":
                cybox_traffic["extensions"]["socket-ext"]["protocol_family"] = socket.domain
            else:
                handle_missing_string_property(container, "protocol_family", socket.domain, sco_id, is_sco=True)

        if socket.local_address:
            handle_missing_string_property(container, "local_address", socket.local_address.ip_address, sco_id, is_sco=True)
        if socket.remote_address:
            handle_missing_string_property(container, "remote_address", socket.remote_address.ip_address, sco_id, is_sco=True)

        fill_in_extension_properties(cybox_traffic, container, extension_definition_id)


def convert_network_socket(socket):
    cybox_traffic = create_base_sco("network-traffic", socket)
    if socket.protocol:
        cybox_traffic["protocols"] = [socket.protocol.value.lower()]
    socket_extension = {}
    if socket.is_blocking:
        socket_extension["is_blocking"] = socket.is_blocking
    if socket.is_listening:
        socket_extension["is_listening"] = socket.is_listening
    if socket.address_family:
        if socket.address_family in ADDRESS_FAMILY_ENUMERATION:
            socket_extension["address_family"] = socket.address_family.value
        else:
            warn("%s is not a member of the %s enumeration", 627, socket.address_family, "address family")
    if socket.type_:
        socket_extension["socket_type"] = socket.type_
    if socket.options:
        socket_extension["options"] = convert_socket_options(socket.options)
    if socket.socket_descriptor:
        socket_extension["socket_descriptor"] = socket.socket_descriptor

    cybox_traffic["extensions"] = {"socket-ext": socket_extension}
    generate_sco_id_for_2_1(cybox_traffic, socket.parent.id_)
    handle_extensions_of_network_socket(socket, socket_extension, cybox_traffic)
    return cybox_traffic


def convert_socket_address(sock_add_1x, env=None):
    spec_version = get_option_value("spec_version")
    instance = create_base_sco("network-traffic", sock_add_1x)
    if spec_version == "2.0":
        objs = {}
    else:
        objs = []

    convert_socket_address_1(sock_add_1x,
                             instance,
                             objs,
                             spec_version,
                             0,
                             determine_socket_address_direction(sock_add_1x, sock_add_1x.parent.id_),
                             env)
    return objs


def convert_product(prod):
    instance = create_base_sco("software", prod)
    if prod.product:
        instance["name"] = prod.product.value
    if prod.vendor:
        instance["vendor"] = prod.vendor.value
    if prod.version:
        instance["version"] = prod.version.value
    if prod.language:
        instance["languages"] = [prod.language.value]
    generate_sco_id_for_2_1(instance, prod.parent.id_)
    return instance


_X509_V3_PROPERTY_MAP = \
    [
        ["basic_constraints", "basic_constraints"],
        ["name_constraints", "name_constraints"],
        ["policy_constraints", "policy_constraints"],
        ["key_usage", "key_usage"],
        ["extended_key_usage", "extended_key_usage"],
        ["subject_key_identifier", "subject_key_identifier"],
        ["authority_key_identifier", "authority_key_identifier"],
        ["subject_alternative_name", "subject_alternative_name"],
        ["issuer_alternative_name", "issuer_alternative_name"],
        ["subject_directory_attributes", "subject_directory_attributes"],
        ["crl_distribution_points", "crl_distribution_points"],
        # ["inhibit_any_policy", "inhibit_any_policy"],  MUST BE A STRING
        ["certificate_policies", "certificate_policies"],
        ["policy_mappings", "policy_mappings"],
    ]


def convert_v3_extension(v3_ext):
    v3_ext_dict = dict()
    for prop_tuple in _X509_V3_PROPERTY_MAP:
        prop_name1x = prop_tuple[0]
        prop_name2x = prop_tuple[1]
        if getattr(v3_ext, prop_name1x, None):
            v3_ext_dict[prop_name2x] = getattr(v3_ext, prop_name1x).value
    if v3_ext.inhibit_any_policy:
        v3_ext_dict["inhibit_any_policy"] = str(v3_ext.inhibit_any_policy.value)
    if v3_ext.private_key_usage_period:
        if v3_ext.private_key_usage_period.not_before:
            v3_ext_dict["private_key_usage_period_not_before"] = convert_timestamp_to_string(v3_ext.private_key_usage_period.not_before.value)
        if v3_ext.private_key_usage_period.not_after:
            v3_ext_dict["private_key_usage_period_not_after"] = convert_timestamp_to_string(v3_ext.private_key_usage_period.not_after.value)
    return v3_ext_dict


_X509_PROPERTY_MAP = \
    [
        ["serial_number", "serial_number"],
        ["signature_algorithm", "signature_algorithm"],
        ["issuer", "issuer"],
        ["subject", "subject"],
    ]

# is_self_signed
# hashes
# version


def convert_x509_certificate(x509):
    x509_obj = create_base_sco("x509-certificate", x509)
    if x509.certificate:
        cert = x509.certificate
        for prop_tuple in _X509_PROPERTY_MAP:
            prop_name1x = prop_tuple[0]
            prop_name2x = prop_tuple[1]
            if getattr(cert, prop_name1x, None):
                x509_obj[prop_name2x] = getattr(cert, prop_name1x).value
        if cert.version:
            x509_obj["version"] = str(cert.version.value)
        if cert.validity:
            if cert.validity.not_before:
                x509_obj["validity_not_before"] = convert_timestamp_to_string(cert.validity.not_before.value)
            if cert.validity.not_after:
                x509_obj["validity_not_after"] = convert_timestamp_to_string(cert.validity.not_after.value)
        if cert.subject_public_key:
            if cert.subject_public_key.public_key_algorithm:
                x509_obj["subject_public_key_algorithm"] = cert.subject_public_key.public_key_algorithm.value
            if cert.subject_public_key.rsa_public_key:
                rsa_key = cert.subject_public_key.rsa_public_key
                if rsa_key.modulus:
                    x509_obj["subject_public_key_modulus"] = rsa_key.modulus.value
                if rsa_key.exponent:
                    x509_obj["subject_public_key_exponent"] = rsa_key.exponent.value
        if cert.standard_extensions:
            ext_dict = convert_v3_extension(cert.standard_extensions)
            if ext_dict:
                x509_obj["x509_v3_extensions"] = ext_dict
    generate_sco_id_for_2_1(x509_obj, x509.parent.id_)
    return x509_obj


def convert_custom_object(custom_obj1x):
    if custom_obj1x.custom_name:
        if check_for_missing_policy("use-extensions"):
            extension_obj21 = create_base_sco(custom_obj1x.custom_name, custom_obj1x)
            generate_sco_id_for_2_1(extension_obj21, custom_obj1x.parent.id_)
            container, extension_definition_id = determine_container_for_missing_properties(custom_obj1x.custom_name,
                                                                                            extension_obj21,
                                                                                            custom_object=True)
            if container is not None:
                container["extension_type"] = "new-sco"
                fill_in_extension_properties(extension_obj21, container, extension_definition_id, None)
            return extension_obj21
        elif check_for_missing_policy("use-custom-properties"):
            custom_object_type = convert_to_custom_name(custom_obj1x.custom_name, separator="-")
            custom_obj2x = create_base_sco(custom_object_type, custom_obj1x)
            generate_sco_id_for_2_1(custom_obj2x, custom_obj1x.parent.id_)
            return custom_obj2x
        else:
            warn("Custom Content %s %s is ignored",
                 316,
                 custom_obj1x.custom_name,
                 ("of " + custom_obj1x.parent.id_ if custom_obj1x.parent.id_ else ""))
    else:
        warn("Custom object with no name cannot be handled yet", 811)
    return None


# def convert_netflow_object(obj1x):
#     cybox_traffic = create_base_sco("network-traffic")
#     if obj1x.unidirectional_flow_record

def convert_cybox_object20(obj1x):
    # in 2.0 indices are local
    clear_directory_path_mappings()
    related_objects = obj1x.related_objects
    # TODO:  should related objects be handled on a case-by-case basis or just ignored
    prop = obj1x.properties
    objs = {}
    if prop is None:
        return None
    elif isinstance(prop, Address):
        objs["0"] = convert_address(prop, related_objects)
    elif isinstance(prop, Artifact):
        objs["0"] = convert_artifact(prop)
    elif isinstance(prop, AutonomousSystem):
        objs["0"] = convert_as(prop)
    elif isinstance(prop, URI):
        objs["0"] = convert_uri(prop)
    elif isinstance(prop, EmailMessage):
        # potentially returns multiple objects
        objs = convert_email_message(prop)
    elif isinstance(prop, File):
        # potentially returns multiple objects
        objs, ignore = convert_file20(prop, related_objects)
    elif isinstance(prop, WinRegistryKey):
        objs = convert_registry_key(prop)
    elif isinstance(prop, Process):
        objs = convert_process(prop)
    elif isinstance(prop, Product):
        objs["0"] = convert_product(prop)
    elif isinstance(prop, DomainName):
        objs["0"] = convert_domain_name(prop, related_objects)
    elif isinstance(prop, Mutex):
        objs["0"] = convert_mutex(prop)
    elif isinstance(prop, NetworkConnection):
        # potentially returns multiple objects
        objs = convert_network_connection(prop)
    elif isinstance(prop, Account):
        objs["0"] = convert_account(prop)
    elif isinstance(prop, Port):
        objs["0"] = convert_port(prop)
    elif isinstance(prop, HTTPSession):
        objs = convert_http_session(prop)
    elif isinstance(prop, NetworkPacket):
        objs["0"] = convert_network_packet(prop)
    elif isinstance(prop, NetworkSocket):
        objs["0"] = convert_network_socket(prop)
    elif isinstance(prop, X509Certificate):
        objs["0"] = convert_x509_certificate(prop)
    elif isinstance(prop, SocketAddress):
        # returns a dict
        objs = convert_socket_address(prop)
    elif isinstance(prop, Custom):
        cust_obj = convert_custom_object(prop)
        if cust_obj:
            if prop.custom_properties:
                for cp in prop.custom_properties.property_:
                    prop_name = convert_to_custom_name(cp.name)
                    cust_obj[prop_name] = cp.value
            objs["0"] = cust_obj
    else:
        warn("CybOX object %s not handled yet", 805, str(type(prop)))
        return None
    if not objs:
        warn("%s did not yield any STIX 2.x object", 417, str(prop))
        return None
    else:
        if prop.custom_properties is not None:
            if check_for_missing_policy("use-custom-properties") or check_for_missing_policy("use-extensions"):
                for cp in prop.custom_properties.property_:
                    handle_missing_string_property(objs["0"], cp.name, cp.value, obj1x.id_, is_sco=True)
            else:
                warn("STIX 1.x object %s contains ignored custom properties", 818, str(prop))
        if obj1x.id_:
            add_object_id_value(obj1x.id_, objs)
        return objs


def convert_cybox_object21(obj1x, env):
    # TODO:  should related objects be handled on a case-by-case basis or just ignored
    related_objects = obj1x.related_objects
    prop = obj1x.properties
    if prop is None:
        return None
    elif isinstance(prop, Address):
        objs = [convert_address(prop, related_objects, env)]
    elif isinstance(prop, Artifact):
        objs = [convert_artifact(prop)]
    elif isinstance(prop, AutonomousSystem):
        objs = [convert_as(prop)]
    elif isinstance(prop, URI):
        objs = [convert_uri(prop)]
    elif isinstance(prop, EmailMessage):
        # potentially returns multiple objects
        objs = convert_email_message(prop)
    elif isinstance(prop, File):
        # potentially returns multiple objects
        objs = convert_file21(prop, related_objects)
    elif isinstance(prop, WinRegistryKey):
        objs = convert_registry_key(prop)
    elif isinstance(prop, Process):
        objs = convert_process(prop)
    elif isinstance(prop, Product):
        objs = [convert_product(prop)]
    elif isinstance(prop, DomainName):
        objs = [convert_domain_name(prop, related_objects)]
    elif isinstance(prop, Mutex):
        objs = [convert_mutex(prop)]
    elif isinstance(prop, NetworkConnection):
        # potentially returns multiple objects
        objs = convert_network_connection(prop, env)
    elif isinstance(prop, Account):
        objs = [convert_account(prop)]
    elif isinstance(prop, Port):
        objs = [convert_port(prop)]
    elif isinstance(prop, HTTPSession):
        objs = convert_http_session(prop)
    elif isinstance(prop, NetworkPacket):
        objs = [convert_network_packet(prop)]
    elif isinstance(prop, NetworkSocket):
        objs = [convert_network_socket(prop)]
    elif isinstance(prop, X509Certificate):
        objs = [convert_x509_certificate(prop)]
    elif isinstance(prop, SocketAddress):
        objs = convert_socket_address(prop, env)
    elif isinstance(prop, Custom):
        cust_obj = convert_custom_object(prop)
        if cust_obj:
            objs = [cust_obj]
        else:
            objs = None
    else:
        warn("CybOX object %s not handled yet", 805, str(type(prop)))
        return None
    if not objs:
        warn("%s did not yield any STIX 2.x object", 417, str(prop))
        return None
    else:
        if prop.custom_properties is not None:
            if check_for_missing_policy("use-custom-properties") or check_for_missing_policy("use-extensions"):
                if isinstance(prop, Custom):
                    # new object type - extensions just has extension_type, properties are at top-level
                    for cp in prop.custom_properties.property_:
                        handle_missing_string_property(objs[0], cp.name, cp.value, obj1x.id_, is_sco=True)
                else:
                    # we assume that because this is a STIX 1.x custom property - the elevator propbably doesn't know about it,
                    # so custom_object=True
                    container, extension_definition_id = determine_container_for_missing_properties(objs[0]["type"],
                                                                                                    objs[0],
                                                                                                    custom_object=True)
                    if container is not None:
                        for cp in prop.custom_properties.property_:
                            handle_missing_string_property(container, cp.name, cp.value, obj1x.id_, is_sco=True)
                        fill_in_extension_properties(objs[0], container, extension_definition_id)
            else:
                warn("STIX 1.x object %s contains ignored custom properties", 818, str(prop))
        # remove useless SCOs
        valid_objects = list()
        for o in objs:
            if len(o.keys()) > 2:
                valid_objects.append(o)
            else:
                warn("STIX 1.x object %s contains no useful properties", 810, o["id"])
        if obj1x.id_:
            add_object_id_value(obj1x.id_, valid_objects)
        return valid_objects


def find_index_of_type(objs, stix_type):
    for k, v in objs.items():
        if v["type"] == stix_type:
            return k
    return None


def renumber_co(co, number_mapping):
    for k, v in co.items():
        if k.endswith("ref"):
            if co[k] in number_mapping:
                co[k] = number_mapping[co[k]]
        elif k.endswith("refs"):
            new_refs = []
            for ref in co[k]:
                if ref in number_mapping:
                    new_refs.append(number_mapping[ref])
            co[k] = new_refs
        elif k == "extensions":
            for ex_k, ex_v in v.items():
                renumber_co(ex_v, number_mapping)
    return co


def renumber_objs(objs, number_mapping):
    new_objects = {}
    for k, v in objs.items():
        new_objects[number_mapping[k]] = renumber_co(v, number_mapping)
    return new_objects


def do_renumbering(objs, next_id, root_obj_index, objs_to_add):
    number_mapping = {}
    for k in sorted(objs.keys()):
        number_mapping[str(k)] = str(next_id)
        next_id += 1
    new_objs = renumber_objs(objs, number_mapping)
    objs_to_add.update(new_objs)
    return next_id, number_mapping


def find_index_of_contents(root_data, objects):
    for index, value in objects.items():
        if value == root_data:
            return index
    return None


def change_1x_ids_to_2x_objs(co, stix2x_property_name, next_id, all_objs, objs_to_add, types_to_find):
    result = list()
    for id in co[stix2x_property_name]:
        if is_stix1x_id(id):
            obj = copy.deepcopy(get_object_id_value(id))
            if obj:
                for t in types_to_find:
                    root_obj_index = find_index_of_type(obj, t)
                    if root_obj_index is not None:  # 0 is a good value
                        root_data = obj[root_obj_index]
                        if root_data:
                            present_obj_index = find_index_of_contents(root_data, all_objs["objects"])
                            if present_obj_index is None:  # 0 is a good value
                                next_id, number_mapping = do_renumbering(obj,
                                                                         next_id,
                                                                         root_obj_index,
                                                                         objs_to_add)
                                index_to_use = number_mapping[root_obj_index]
                            else:
                                index_to_use = present_obj_index
                            result.append(str(index_to_use))
    # no result means they were already local indicies
    if result:
        co[stix2x_property_name] = result


def change_1x_id_to_2x_obj(mp, stix2x_property_name, next_id, all_objs, objs_to_add, types_to_find):
    id = mp[stix2x_property_name]
    if is_stix1x_id(id):
        obj = copy.deepcopy(get_object_id_value(id))
        if obj:
            for t in types_to_find:
                root_obj_index = find_index_of_type(obj, t)
                if root_obj_index is not None:  # 0 is a good value
                    root_data = obj[root_obj_index]
                    if root_data:
                        present_obj_index = find_index_of_contents(root_data, all_objs["objects"])
                        if present_obj_index is None:  # 0 is a good value
                            next_id, number_mapping = do_renumbering(obj,
                                                                     next_id,
                                                                     root_obj_index,
                                                                     objs_to_add)
                            index_to_use = number_mapping[root_obj_index]
                        else:
                            index_to_use = present_obj_index
                        mp[stix2x_property_name] = str(index_to_use)


def fix_cybox_relationships(observed_data):
    for o in observed_data:
        if not o["objects"]:
            continue
        objs_to_add = {}
        next_id = int(max(o["objects"].keys())) + 1
        for co in o["objects"].values():
            if co["type"] == "email-message":
                if "body_multipart" in co:
                    for mp in co["body_multipart"]:
                        change_1x_id_to_2x_obj(mp, "body_raw_ref", next_id, o, objs_to_add, ["artifact", "file"])
            elif co["type"] in ["domain-name", "ipv4-addr", "ipv6-addr"]:
                if "resolves_to_refs" in co and co["resolves_to_refs"]:
                    change_1x_ids_to_2x_objs(co, "resolves_to_refs", next_id, o, objs_to_add, ["domain-name", "ipv4-addr", "ipv6-addr"])
            elif co["type"] == "network-traffic":
                if "src_ref" in co:
                    change_1x_id_to_2x_obj(co, "src_ref", next_id, o, objs_to_add, ["domain-name", "ipv4-addr", "ipv6-addr"])
                if "dst_ref" in co:
                    change_1x_id_to_2x_obj(co, "dst_ref", next_id, o, objs_to_add, ["domain-name", "ipv4-addr", "ipv6-addr"])
        if objs_to_add:
            o["objects"].update(objs_to_add)


def embedded_property_ref_name(prop, relationship):
    if relationship and relationship.value:
        if isinstance(prop, Address) or isinstance(prop, DomainName):
            if relationship.value == "Resolved_To":
                return "resolves_to_refs"
        elif isinstance(prop, File):
            if relationship.value == "Contains":
                return "contains_refs"
    return None


def change_ids_from_1x_to_2x(obj, property_name):
    if property_name in obj:
        result = list()
        for ref in obj[property_name]:
            if is_stix1x_id(ref):
                new_ids = get_id_value(ref)
                if new_ids:
                    result.append(new_ids[0])
                else:
                    # TODO: warn
                    pass
            else:
                result.append(ref)
        obj[property_name] = result


def change_id_from_1x_to_2x(obj, property_name):
    if property_name in obj:
        if is_stix1x_id(obj[property_name]):
            new_ids = get_id_value(obj[property_name])
            if new_ids:
                obj[property_name] = new_ids[0]
            else:
                # TODO: warn
                pass


def fix_sco_embedded_refs(objects):
    for obj in objects:
        if obj["type"] == "email-message":
            if obj["is_multipart"]:
                for mp in obj["body_multipart"]:
                    change_id_from_1x_to_2x(mp, "body_raw_ref")
                    mp["content_type"] = "text/plain"
                    info("content_type for body_multipart of %s is assumed to be 'text/plain'", 722, obj["id"])
        elif obj["type"] in ["domain-name", "ipv4-addr", "ipv6-addr"]:
            change_ids_from_1x_to_2x(obj, "resolves_to_refs")
        elif obj["type"] == "file":
            change_ids_from_1x_to_2x(obj, "contains_refs")
            change_id_from_1x_to_2x(obj, "content_ref")
        elif obj["type"] == "network-traffic":
            change_id_from_1x_to_2x(obj, "src_ref")
            change_id_from_1x_to_2x(obj, "dst_ref")
        # TODO: other embedded refs


def resolve_object_references20(obsers):
    for obs in obsers:
        if not obs["objects"]:
            # TODO: strange that there are no objects
            return None
        new_objects = dict()
        for k, obj in obs["objects"].items():
            index_mapping = dict()
            if obj["type"] == "network-traffic":
                if "extensions" in obj and property_contains_stix1x_id(obj, "extensions"):
                    object2x = get_object_id_value(obj["extensions"])
                    if object2x:
                        if "extensions" in object2x["0"]:
                            obj["extensions"] = copy.deepcopy(object2x["0"]["extensions"])
                        if len(object2x) > 1:
                            next_id = int(max(obs["objects"].keys())) + 1
                            for k, v in object2x.items():
                                if k == "0":
                                    continue
                                new_objects[str(next_id)] = v
                                index_mapping[k] = str(next_id)
                                next_id += 1

                    else:
                        warn("Object references for http sessions in %s not handled yet", 804, obs["id"])
                    # only need to renumber the co that was subbed in for the object reference
                    for m, v in obj["extensions"].items():
                        renumber_co(v, index_mapping)
        obs["objects"].update(new_objects)


def resolve_object_references21(objects):
    for obj in objects:
        if obj["type"] == "network-traffic":
            if "extensions" in obj and property_contains_stix1x_id(obj, "extensions"):
                object2x = get_object_id_value(obj["extensions"])
                if object2x:
                    # what if more than 1?
                    if "extensions" in object2x[0]:
                        obj["extensions"] = object2x[0]["extensions"]
                    # what if no extensions property?
