Mappings from CybOX 2.x to STIX 2.x
========================================

The following table associates the CybOX 2.x object types with their STIX 2.x cyber observable types.
For each CybOX object the table also indicates if the elevator is able to convert the CybOX object to STIX 2.x.

CybOX object types not listed have no corresponding STIX 2.x cyber observable type, and therefore are not
converted by the elevator.

=============================== ============================================= ==============================================
**Cybox 2.x Object Type**       **STIX 2.x Cyber Observable Type**            **Converted in version 2.0.1 of the Elevator**
=============================== ============================================= ==============================================
``Address``                     ``email-addr``                                yes
``Address``                     ``ipv4-addr``                                 yes
``Address``                     ``ipv6-addr``                                 yes
``Address``                     ``mac-addr``                                  yes
``ArchiveFile``                 ``file:archive-ext``                          patterns only
``Artifact``                    ``artifact``                                  no
``AutonomusSystem``             ``autonomous-system``                         no
``File``                        ``directory``                                 yes
``DomainName``                  ``domain-name``                               yes
``DNSQuery``                    *none*                                        no
``EmailMessage``                ``email-message``                             yes
``File``                        ``file``                                      yes
``HTTPClientRequest``           ``network-traffic:http-request-ext``          yes
``HTTPSession``                 ``network-traffic``                           yes
``ICMP``(``v4``/``v6``)         ``network-traffic:icmp-ext``                  yes
``ImageFile``                   ``file:raster-image-ext``                     no
``Link``                        *none*                                        no
``Mutex``                       ``mutex``                                     yes
``NetworkConnection``           ``network-traffic``                           yes
``NetworkSocket``               ``network-traffic:socket-ext``                yes
``PDFFile``                     ``file:pdf-ext``                              no
``Process``                     ``process``                                   yes
``Product``                     ``software``                                  no
``SocketAddress``               ``network-traffic``                           yes
``Hostname``                    ``domain-name``                               yes
``Port``                        ``integer``                                   yes
``TCP``                         ``network-traffic:tcp-ext``                   no
``URI``                         ``url``                                       yes
``UnixUserAccount``             ``user-account:unix-account-ext``             no
``UserAccount/WinUserAccount``  ``user-account``                              no
``WindowsRegistryKey``          ``window-registry-key``                       yes
``WinExecutableFile``           ``file:window-pebinary-ext``                  patterns only
``WinFile``                     ``file:ntfs-ext``                             no
``WinProcess``                  ``process:windows-process-ext``               observables only
``WinService``                  ``process:windows-service-ext``               yes
``X509Certificate``             ``x509-certificate``                          no
``X509V3Extensions``            ``x509-certificate:x509-v3-extensions-type``  no
=============================== ============================================= ==============================================

Converting Network Cyber Observables
------------------------------------------

Most of the mappings between CybOX 2.x objects and STIX 2.x cyber
observables are straightforward, therefore, they will not be detailed in
this document. However, it would be advantageous to detail the mappings
of ``network-traffic``, a "catch-all" STIX 2.0 cyber observable type for
information previously represented in CybOX 2.x by:

- ``NetworkConnection``
- ``HTTPSessionObject``
- ``NetworkFlowObject``
- ``NetworkPacket``

This information is organized very differently than
in CybOX 2.x. In addition, many CybOX 2.x properties are not available
in the ``network-traffic`` object.

Notice that although both STIX 1.x and 2.x have object types to represent TCP packets,
they are not compatible, so no conversion is made.

+-----------------------------------------------------------+--------------------------------------+
| **CybOX 2.x Type**                                        | **STIX 2.0 mapping**                 |
+===========================================================+======================================+
| ``NetworkConnection``                                     | ``network-traffic``                  |
+-----------------------------------------------------------+--------------------------------------+
| ``HTTPSessionObject/HTTPSessionObject/HTTPClientRequest`` | ``network-traffic/http-request-ext`` |
+-----------------------------------------------------------+--------------------------------------+
| ``NetworkFlowObject/UnidirectionalRecord/IPFIXMessage``   | ``network-traffic/ipfix``            |
+-----------------------------------------------------------+--------------------------------------+
| ``NetworkPacket/InternetLayer/ICMPv(4/6)``                | ``network-traffic/icmp-ext``         |
+-----------------------------------------------------------+--------------------------------------+
