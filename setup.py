from os.path import abspath, dirname, join
from setuptools import setup, find_packages

CUR_DIR = dirname(abspath(__file__))
INIT_FILE = join(CUR_DIR, 'elevator', '__init__.py')
VERSION_FILE = join(CUR_DIR, 'elevator', 'version.py')


def get_version():
    with open(VERSION_FILE) as f:
        for line in f:
            if not line.startswith("__version__"):
                continue

            version = line.split()[-1].strip('"')
            return version

        raise AttributeError("Package does not have a __version__")

with open('README.md') as f:
    readme = f.read()

setup(
    name="stix-elevator",
    version=get_version(),
    description="Utilities to upgrade STIX and CybOX content to 2.0",
    long_description=readme,
    url="http://stixproject.github.io/",
    packages=find_packages(),
    install_requires=['stix>=1.2.0.0,<1.2.1.0'],
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ]
)
