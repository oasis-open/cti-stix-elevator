# internal
from stix2elevator.options import warn

SOCKET_OPTIONS = [
    "ip_multicast_if",
    "ip_multicast_if2",
    "ip_multicast_loop",
    "ip_tos",
    "so_broadcast",
    "so_conditional_accept",
    "so_keepalive",
    "so_dontroute",
    "so_linger",
    "so_dontlinger",
    "so_oobinline",
    "so_rcvbuf",
    "so_group_priority",
    "so_reuseaddr",
    "so_debug",
    "so_rcvtimeo",
    "so_sndbuf",
    "so_sndtimeo",
    "so_update_accept_context",
    "so_timeout",
    "tcp_nodelay"
]

ADDRESS_FAMILY_ENUMERATION = [
    "AF_UNSPEC",
    "AF_INET",
    "AF_IPX",
    "AF_APPLETALK",
    "AF_NETBIOS",
    "AF_INET6",
    "AF_IRDA",
    "AF_BTH",
]

PDF_DOC_INFO = [
    "author",
    "creationdate",
    "creator",
    "keywords",
    "producer",
    "moddate",
    "subject",
    "trapped"
]

PDF_DOC_INFO_DICT = {
    "author": "Author",
    "creationdate": "CreationDate",
    "creator": "Creator",
    "keywords": "Keywords",
    "producer": "Producer",
    "moddate": "ModDate",
    "subject": "Subject",
    "trapped": "Trapped"
}


def determine_socket_address_direction(sock_add_1x, obj1x_id):
    if sock_add_1x.ip_address:
        if sock_add_1x.ip_address.is_destination and not sock_add_1x.ip_address.is_source:
            return "dst"
        elif sock_add_1x.ip_address.is_source and not sock_add_1x.ip_address.is_destination:
            return "src"
        else:
            # ((sock_add_1x.ip_address.is_destination and sock_add_1x.ip_address.is_source) or
            # (not sock_add_1x.ip_address.is_destination and not sock_add_1x.ip_address.is_source)):
            warn("Address direction in %s is inconsistent, using 'src'", 614, obj1x_id)
            return "src"
    else:
        warn("Address direction in %s is not provided, using 'src'", 636, obj1x_id)
        return "src"
