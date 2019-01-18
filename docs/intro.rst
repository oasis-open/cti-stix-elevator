​Introduction
=================

The stix2-elevator is a python script written to automatically convert STIX 1.x content to STIX 2.x.  It is available at
`<https://github.com/oasis-open/cti-stix-elevator/>`_.

It important to emphasize that the elevator is not for use in a *production* system without human inspection of the results it produces.
It is more a tool to explore the differences between STIX 2.x and STIX 1.x content previously created.

While much of the conversion is straightforward, several assumptions concerning the meaning of the STIX 1.x needed to
be made.  These are discussed in :ref:`conversion_issues` section.

The elevator produces many messages during the conversion process, that can be reviewed manually to help enhance the
automatically produced content, in order to reflect the original content more accurately.  A list of these messages
can be found in :ref:`warning_messages` section.
