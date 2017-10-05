#!/usr/bin/env python

from setuptools import setup

with open('README.md') as readme_file:
    readme = readme_file.read()

setup(
    name='r2pipe',
    version="1.0alpha",
    license='BSD 2-clause',
    description='CLI interface for Carbonara',
    long_description=readme,
    author='Andrea Fioraldi, Luigi Paolo Pileggi',
    author_email='andreafioraldi@gmail.com, willownoises@gmail.com',
    url='https://github.com/andreafioraldi/Carbonara-CLI',
    package_dir={'carbonara_bininfo': 'carbonara_bininfo'},
    packages=['carbonara_bininfo'],
    scripts=['carbonara-cli', 'carbonara-cli.py'],
)
