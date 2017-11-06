#!/usr/bin/env python

__author__ = "Andrea Fioraldi, Luigi Paolo Pileggi"
__copyright__ = "Copyright 2017, Carbonara Project"
__license__ = "BSD 2-clause"
__email__ = "andreafioraldi@gmail.com, willownoises@gmail.com"

from setuptools import setup

with open('README.md') as readme_file:
    readme = readme_file.read()

setup(
    name='guanciale',
    version="1.0alpha",
    license=__license__,
    description='Grab information needed by Carbonara',
    long_description=readme,
    author=__author__,
    author_email=__email__,
    url='https://github.com/Carbonara-Project/Guanciale',
    package_dir={'guanciale': 'guanciale'},
    packages=['guanciale']
)
