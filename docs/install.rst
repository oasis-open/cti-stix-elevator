Installing
===============

Requirements
------------

- Python 2.7, or 3.4+
- `python-stix <https://stix.readthedocs.io/en/stable/>`_ and its dependencies

  .. note::

      Make sure to use either the latest version of python-stix 1.1.1.x or
      1.2.0.x, depending on whether you want to support STIX 1.1.1 or STIX 1.2.

-  `python-stix2 <https://pypi.python.org/pypi/python-stix2>`_ >= 0.5.1
-  `stix2-validator <https://pypi.python.org/pypi/stix2-validator>`_ >= 0.4.0
   and its dependencies
-  `pycountry <https://pypi.python.org/pypi/pycountry/>`_ >= 1.20
-  `stixmarx <https://pypi.python.org/pypi/stixmarx>`_ >= 1.0.3

Installation Steps
------------------

Install with pip::

    $ pip install stix2-elevator

This will install all necessary dependencies, including the latest
version of python-stix.

If you need to support older STIX 1.1.1 content, install python-stix
1.1.1.x
first::

    $ pip install 'stix<1.2'
    $ pip install stix2-elevator

You can also install the stix2-elevator from GitHub to get the latest
(unstable)
version::

    $ pip install git+https://github.com/oasis-open/cti-stix-elevator.git
