​Command Line Interface
===========================

The elevator comes with a bundled script which you can use to elevate
STIX 1.1.1 - 1.2.1 content to STIX 2.0 content::

    usage: cli.py [-h] [--incidents] [--no-squirrel-gaps] [--infrastructure]
              [--package-created-by-id PACKAGE_CREATED_BY_ID]
              [--default-timestamp DEFAULT_TIMESTAMP]
              [--validator-args VALIDATOR_ARGS] [-e ENABLE] [-d DISABLE] [-s]
              [--message-log-directory MESSAGE_LOG_DIRECTORY]
              [--log-level {DEBUG,INFO,WARN,ERROR,CRITICAL}]
              [-m MARKINGS_ALLOWED] [-p {no_policy,strict_policy}]
              file

stix2-elevator v1.1.0

The stix2-elevator is a work-in-progress. It should be used to explore how
existing STIX 1.x would potentially be represented in STIX 2.0. Using the
current version of the stix2-elevator will provide insight to issues that might need
to be mitigated to convert your STIX 1.x content.

positional arguments:
  file                  The input STIX 1.x document to be elevated.

optional arguments:
  -h, --help            show this help message and exit

  --no-squirrel-gaps    Do not include STIX 1.x content that cannot be
                        represented directly in STIX 2.0 using the description
                        property.

  --package-created-by-id PACKAGE_CREATED_BY_ID
                        Use provided identifier for "created_by_ref"
                        properties. Example: --package-created-by-id "identity
                        --1234abcd-1a12-12a3-0ab4-1234abcd5678"

  --default-timestamp DEFAULT_TIMESTAMP
                        Use provided timestamp for properties that require a
                        timestamp. Example: --default-timestamp
                        "2016-11-15T13:10:35.053000Z"

  --validator-args VALIDATOR_ARGS
                        Arguments to pass to stix-validator. Default:
                        --strict-types Example: stix2_elevator.py <file>
                        --validator-args="-v --strict-types -d 212"

  -e ENABLE, --enable ENABLE
                        A comma-separated list of the stix2-elevator messages
                        to enable. If the --disable option is not used, no
                        other messages will be shown. Example:
                        stix2_elevator.py <file> --enable 250

  -d DISABLE, --disable DISABLE
                        A comma-separated list of the stix2-elevator messages
                        to disable. Example: stix2_elevator.py <file>
                        --disable 212,220

  -s, --silent          If this flag is set, all stix2-elevator messages will
                        be disabled.

  --message-log-directory MESSAGE_LOG_DIRECTORY
                        If this flag is set, all stix2-elevator messages will
                        be saved to file. The name of the file will be the
                        input file with extension .log in the specified
                        directory. Note, make sure the directory already
                        exists. Example: stix2_elevator.py <file> --message-
                        log-directory "../logs".

  --log-level {DEBUG,INFO,WARN,ERROR,CRITICAL}
                        The logging output level.

  -m MARKINGS_ALLOWED, --markings-allowed MARKINGS_ALLOWED
                        Avoid error exit, if these markings are in the
                        content, but not supported by the elevator. Specify as
                        a comma-separated list

                        Example: stix2_elevator.py <file > --markings-allowed "ISAMarkingsAssertion,ISAMarkings"

  -p {no_policy,strict_policy}, --policy {no_policy,strict_policy}
                        The policy to deal with errors

Refer to Warning Messages section for all stix2-elevator messages. Use the
associated code number to --enable or --disable a message. By default, the
stix2-elevator displays all messages. Note: disabling the message does not
disable the functionality.
