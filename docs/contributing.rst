Contributing
============

We're thrilled that you're interested in contributing to the stix2-elevator!
Here are some things you should know:

- `contribution-guide.org <http://www.contribution-guide.org/>`_ has great ideas
  for contributing to any open-source project (not just this one).
- All contributors must sign a Contributor License Agreement. See
  `CONTRIBUTING.md <https://github.com/oasis-open/cti-stix-elevator/blob/master/CONTRIBUTING.md>`_
  in the project repository for specifics.
- If you are planning to implement a major feature (vs. fixing a bug), please
  discuss with a project maintainer first to ensure you aren't duplicating the
  work of someone else, and that the feature is likely to be accepted.

Now, let's get started!

Setting up a development environment
------------------------------------

We recommend using a `virtualenv <https://virtualenv.pypa.io/en/stable/>`_.

1. Clone the repository. If you're planning to make pull request, you should fork
the repository on GitHub and clone your fork instead of the main repo:

.. code-block:: bash

    $ git clone https://github.com/yourusername/cti-stix-elevator.git

2. Install develoment-related dependencies:

.. code-block:: bash

    $ cd cti-stix-elevator
    $ pip install -r requirements.txt

3. Install `pre-commit <http://pre-commit.com/#usage>`_ git hooks:

.. code-block:: bash

    $ pre-commit install

At this point you should be able to make changes to the code.

Code style
----------

All code should follow `PEP 8 <https://www.python.org/dev/peps/pep-0008/>`_. We
allow for line lengths up to 160 characters, but any lines over 80 characters
should be the exception rather than the rule. PEP 8 conformance will be tested
automatically by Tox and Travis-CI (see below).

Testing
-------

.. note::

    All of the tools mentioned in this section are installed when you run ``pip
    install -r requirements.txt``.

This project uses `pytest <http://pytest.org>`_ for testing.  We encourage the
use of test-driven development (TDD), where you write (failing) tests that
demonstrate a bug or proposed new feature before writing code that fixes the bug
or implements the features. Any code contributions should come with new or
updated tests.

Tests are created by creating a STIX 1.x file containing the content which will cause the elevator to execute the code you
are testing.  This file should be placed in the idioms-xml directory.  Use the elevator command line to create json "golden" files - which
contain the correct result you expect from the elevator.  You should provide golden files for each version and missing property option.
These files should be placed in the idioms-json-2.x-<missing-property option> directory.

Note: the number of test files must be the same across the idioms directories, using the same file names.

Running tests can be done using tox, discussed below.

`tox <https://tox.readthedocs.io/en/latest/>`_ allows you to test a package
across multiple versions of Python. Setting up multiple Python environments is
beyond the scope of this guide, but feel free to ask for help setting them up.
Tox should be run from the root directory of the project:

.. code-block:: bash

    $ tox

We aim for high test coverage, using the `coverage.py
<http://coverage.readthedocs.io/en/latest/>`_ library. Though it's not an
absolute requirement to maintain 100% coverage, all code contributions must
be accompanied by tests. To run coverage and look for untested lines of code,
run:

.. code-block:: bash

    $ pytest --cov=stix2elevator
    $ coverage html

then look at the resulting report in ``htmlcov/index.html``.

All commits pushed to the ``master`` branch or submitted as a pull request are
tested with `Travis-CI <https://travis-ci.org/oasis-open/cti-stix-elevator>`_
automatically.

Adding a dependency
-------------------

One of the pre-commit hooks we use in our develoment environment enforces a
consistent ordering to imports. If you need to add a new library as a dependency
please add it to the `known_third_party` section of `.isort.cfg` to make sure
the import is sorted correctly.
