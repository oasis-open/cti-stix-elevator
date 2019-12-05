​Command Line Interface
===========================

The elevator comes with a bundled script which you can use to elevate
STIX 1.x content to STIX 2.x content:

.. code-block:: text

    usage: stix2_elevator [-h]
              [--missing-policy {use-custom-properties, add-to-description, ignore}]
              [--custom-property-prefix CUSTOM_PROPERTY_PREFIX]
              [--infrastructure]
              [--incidents]
              [--package-created-by-id PACKAGE_CREATED_BY_ID]
              [--default-timestamp DEFAULT_TIMESTAMP]
              [--validator-args VALIDATOR_ARGS]
              [-e ENABLE] [-d DISABLE] [-s]
              [--message-log-directory MESSAGE_LOG_DIRECTORY]
              [--log-level {DEBUG,INFO,WARN,ERROR,CRITICAL}]
              [-m MARKINGS_ALLOWED] [-p {no_policy,strict_policy}]
              [-v --version VERSION]
              file


stix2-elevator v2.1

positional arguments:

.. code-block:: text

  file          The input STIX 1.x document to be elevated.

optional arguments:

.. code-block:: text

  -h, --help
                Show this help message and exit

  --missing-policy {use-custom-properties,add-to-description,ignore}
                        Policy for including STIX 1.x content that cannot be
                        represented directly in STIX 2.x. The default is 'add-
                        to-description'.

  --custom-property-prefix CUSTOM_PROPERTY_PREFIX
                        Prefix to use for custom property names when missing
                        policy is 'use-custom-properties'. The default is
                        'elevator'.

  --infrastructure
                Infrastructure will be included in the conversion.
                Default for version 2.1 is true.

  --incidents           Incidents will be included in the conversion.

  --package-created-by-id PACKAGE_CREATED_BY_ID
                Use provided identifier for "created_by_ref"
                properties.

                Example: --package-created-by-id "identity--1234abcd-1a12-12a3-0ab4-1234abcd5678"

  --default-timestamp DEFAULT_TIMESTAMP
                Use provided timestamp for properties that require a
                timestamp.

                Example: --default-timestamp "2016-11-15T13:10:35.053000Z"

  --validator-args VALIDATOR_ARGS
                Arguments to pass to stix-validator.

                Default: --strict-types

                Example: --validator-args="-v --strict-types -d 212"

  -e ENABLE, --enable ENABLE
                A comma-separated list of the stix2-elevator messages
                to enable. If the --disable option is not used, no
                other messages will be shown.

                Example: --enable 250

  -d DISABLE, --disable DISABLE
                A comma-separated list of the stix2-elevator messages
                to disable.

                Example: --disable 212,220

  -s, --silent
                If this flag is set, all stix2-elevator messages will
                be disabled.

  --message-log-directory MESSAGE_LOG_DIRECTORY
                If this flag is set, all stix2-elevator messages will
                be saved to a file. The name of the file will be the
                input file with extension .log in the specified
                directory.

                Note, make sure the directory already exists.

                Example: --message-log-directory "../logs".

  --log-level {DEBUG,INFO,WARN,ERROR,CRITICAL}
                The logging output level.

  -m MARKINGS_ALLOWED, --markings-allowed MARKINGS_ALLOWED
                Avoid error exit, if these markings types
                (as specified via their python class names) are in the
                content, but not supported by the elevator. Specify as
                a comma-separated list.

                Example: --markings-allowed "ISAMarkingsAssertion,ISAMarkings"

  -p {no_policy,strict_policy},
  --error-policy {no_policy,strict_policy},
  --policy {no_policy,strict_policy}   #deprecated
               The policy to deal with errors. The default is 'no_policy'.

  -v {2.0,2.1}, --version {2.0,2.1}
                        The version of stix 2 to be produced. The default is
                        2.1


Refer to the :ref:`warning_messages` section for all stix2-elevator messages. Use the
associated code number to ``--enable`` or ``--disable`` a message. By default, the
stix2-elevator displays all messages.

Note: disabling the message does not disable any functionality.
