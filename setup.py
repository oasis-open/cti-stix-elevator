# Standard Library
from os.path import abspath, dirname, join

# external
from setuptools import find_packages, setup

CUR_DIR = dirname(abspath(__file__))
INIT_FILE = join(CUR_DIR, 'stix2elevator', '__init__.py')
VERSION_FILE = join(CUR_DIR, 'stix2elevator', 'version.py')


def get_version():
    with open(VERSION_FILE) as f:
        for line in f:
            if not line.startswith("__version__"):
                continue

            version = line.split()[-1].strip('"')
            return version

        raise AttributeError("Package does not have a __version__")


def get_long_description():
    with open('README.rst') as f:
        return f.read()


setup(
    name='stix2-elevator',
    version=get_version(),
    description='Utility to upgrade STIX 1.X and CybOX content to STIX 2.X',
    long_description=get_long_description(),
    long_description_content_type='text/x-rst',
    url='https://oasis-open.github.io/cti-documentation/',
    author='OASIS Cyber Threat Intelligence Technical Committee',
    author_email='cti-users@lists.oasis-open.org',
    packages=find_packages(exclude=['*.test', '*.test.*']),
    python_requires='>=3.7',
    install_requires=[
        'maec',
        'netaddr',
        'pycountry>=20.7.0',
        'pluralizer',
        'stix>=1.1.1.9,<1.2.1.0',
        'stix2>=3.0.0',
        'stix2-validator>=3.0.0',
        'stixmarx>=1.0.8',
    ],
    entry_points={
        'console_scripts': [
            'stix2_elevator = stix2elevator.cli:main',
            'stix_stepper = stix2elevator.stix_stepper:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
    ],
    keywords='stix stix2 json xml cti cyber threat intelligence',
    project_urls={
        'Documentation': 'https://stix2-elevator.readthedocs.io/',
        'Source Code': 'https://github.com/oasis-open/cti-stix-elevator/',
        'Bug Tracker': 'https://github.com/oasis-open/cti-stix-elevator/issues/',
    },
    extras_require={
        'dev': [
            'bumpversion',
            'pre-commit',
        ],
        'test': [
            'coverage',
            'pytest',
            'pytest-cov',
            'tox',
        ],
        'docs': [
            'sphinx',
            'sphinx-prompt',
        ],
        "acs": [
            'stix-edh>=1.0.3',
        ]
    },
)
