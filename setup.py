#!/usr/bin/env python

__author__ = "Andrea Fioraldi, Luigi Paolo Pileggi"
__copyright__ = "Copyright 2017, Carbonara Project"
__license__ = "BSD 2-clause"
__email__ = "andreafioraldi@gmail.com, willownoises@gmail.com"

from setuptools import setup
import os

with open('README.md') as readme_file:
    readme = readme_file.read()

capstone_pkg = "capstone"
if os.name == 'nt':
    capstone_pkg = "capstone-windows"

setup(
    name='guanciale',
    version="1.0alpha",
    license=__license__,
    description='Grab information needed by Carbonara',
    long_description=readme,
    author=__author__,
    author_email=__email__,
    url='https://github.com/Carbonara-Project/Guanciale',
    download_url = 'https://github.com/Carbonara-Project/Guanciale/archive/1.0alpha.tar.gz',
    package_dir={'guanciale': 'guanciale'},
    packages=['guanciale'],
    install_requires=[
        capstone_pkg,
        'requests',
        'python-idb',
        'archinfo',
        'pyvex'
    ]
)
