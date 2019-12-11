​Introduction
=================

The stix2-elevator is a python script written to automatically convert STIX 1.x content to STIX 2.x.  It is available at
`<https://github.com/oasis-open/cti-stix-elevator/>`_.

The stix2-elevator is a “best-effort” attempt to convert STIX 1.x content to STIX 2.x content.
**Caution should be taken if the elevator is to be used in a production environment as warnings
concerning the conversion are often generated.** Users should determine which warnings are acceptable
and use the --disable option in conjunction with the –error-policy option only to produce results when no other
warnings are emitted.

While much of the conversion is straightforward, several assumptions concerning the meaning of the STIX 1.x needed to
be made.  These are discussed in :ref:`conversion_issues` section.

The elevator produces many messages during the conversion process, that can be reviewed manually to help enhance the
automatically produced content, in order to reflect the original content more accurately.  A list of these messages
can be found in :ref:`warning_messages` section.
