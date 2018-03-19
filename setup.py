#!/usr/bin/env python

__author__ = "Andrea Fioraldi, Luigi Paolo Pileggi"
__copyright__ = "Copyright 2017, Carbonara Project"
__license__ = "BSD 2-clause"
__email__ = "andreafioraldi@gmail.com, rop2bash@gmail.com"

from setuptools import setup

VER = "1.0.15"

setup(
    name='guanciale',
    version=VER,
    license=__license__,
    description='Grab information needed by Carbonara',
    author=__author__,
    author_email=__email__,
    url='https://github.com/Carbonara-Project/Guanciale',
    download_url = 'https://github.com/Carbonara-Project/Guanciale/archive/' + VER + '.tar.gz',
    package_dir={'guanciale': 'guanciale'},
    packages=['guanciale'],
    install_requires=[
            'requests',
            'carbonara-idb',
            'carbonara-archinfo',
            'carbonara-pyvex',
            'appdirs',
            'datasketch',
            'r2pipe'
    ]
)
