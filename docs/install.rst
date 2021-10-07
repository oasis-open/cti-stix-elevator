Installing
===============

Requirements
------------

- Python 3.6+
- `python-stix <https://stix.readthedocs.io/en/stable/>`_ and its dependencies

  .. note::

      Make sure to use either the latest version of python-stix 1.1.1.x or
      1.2.0.x, depending on whether you want to support STIX 1.1.1 or STIX 1.2.

-  `python-stix2 <https://pypi.python.org/pypi/python-stix2>`_ >= 3.0.0
-  `stix2-validator <https://pypi.python.org/pypi/stix2-validator>`_ >= 3.0.0
   and its dependencies
-  `pycountry <https://pypi.python.org/pypi/pycountry/>`_ >= 20.7.0
-  `stixmarx <https://pypi.python.org/pypi/stixmarx>`_ >= 1.0.8

Installation Steps
------------------

Install with pip

.. code-block:: bash

    $ pip install stix2-elevator

This will install all necessary dependencies, including the latest
version of python-stix.

If you need to support older STIX 1.1.1 content, install python-stix 1.1.1.x first

.. code-block:: bash

    $ pip install 'stix<1.2'
    $ pip install stix2-elevator

You can also install the stix2-elevator from GitHub to get the latest (unstable) version

.. code-block:: bash

    $ pip install git+https://github.com/oasis-open/cti-stix-elevator.git

Installation Steps for ACS Data Marking Support
-----------------------------------------------

ACS data markings correspond to the common marking scheme used by the U.S. government (e.g., U, C, S, TS).
To elevate STIX 1.x content that contains ACS data markings, it is necessary to install an additional python package
called 'stix_edh'.

Install with pip

.. code-block:: bash

    $ pip install stix2-elevator[acs]

Installation Steps for Ignoring Data Markings Not Defined in the STIX Specification
-----------------------------------------------------------------------------------

The elevator uses the -m option to declare data marking python classes that support data markings not defined within the
STIX specification.  See the Command Line Interface section for an example.

However, the elevator must import those class definitions.  The suggested way is to create a small python wrapper script
that imports the needed package.

.. code-block:: python

    import <data marking package>
    from stix2elevator import elevate

    elevate(...)