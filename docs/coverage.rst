STIX Elevator 1.1.1 Coverage of CybOX 2.x Object Types
===========================================================

The following table associates the CybOX 2.x object types with their STIX 2.0 cyber observable types.
For each CybOX object the table also indicates if the elevator is able to convert the CybOX object to STIX 2.0.

CybOX object types not listed have no corresponding STIX 2.0 cyber observable type, and therefore are not
converted by the Elevator

=========================== ========================================= ==========================================
Cybox 2.x Object Type       STIX 2.0 Cyber Observable Type            Converted in version 1.1.1 of the Elevator
=========================== ========================================= ==========================================
Address                     email-addr                                yes
Address                     ipv4-addr	                                yes
Address	                    ipv6-addr	                                yes
Address	                    mac-addr	                                yes
ArchiveFile		              file:archive-ext	                        patterns only
Artifact		                artifact	                                no
AutonomusSystem		          autonomous-system	                        no
File	                      directory	                                yes
DomainName	                domain-name	                              yes
DNSQuery	                  none	                                    no
EmailMessage	              email-message	                            yes
File	                      file	                                    yes
HTTPClientRequest           network-traffic:http-request-ext          no
HTTPSession	                network-traffic	                          no
ICMP(v4/v6)                 network-traffic:icmp-ext                  no
ImageFile		                file:raster-image-ext	                    no
Link	                      none	                                    no
Mutex	                      mutex	                                    yes
NetworkConnection	          network-traffic	                          yes
PDFFile		                  file:pdf-ext	                            no
Process	                    process	                                  yes
Product		                  software	                                no
SocketAddress	              network-traffic	                          yes
Hostname	                  domain-name	                              yes
Port	                      integer	                                  yes
TCP		                      network-traffic:tcp-ext	                  no
URI	                        url	                                      yes
UnixUserAccount		          user-account:unix-account-ext	            no
UserAccount/WinUserAccount	user-account	                            no
WindowsRegistryKey	        window-registry-key	                      yes
WinExecutableFile		        file:window-pebinary-ext	                patterns only
WinFile		                  ntfs-ext	                                no
WinProcess	                process:windows-process-ext	              observables only
WinService	                process:windows-service-ext	              yes
X509Certificate		          x509-certificate	                        no
X509V3Extensions            x509-certificate:x509-v3-extensions-type  no
=========================== ========================================= ==========================================


