from setuptools import setup

with open('README.md') as readme_file:
    readme = readme_file.read()

setup(
    name='r2pipe',
    version="1.0alpha",
    license='MIT',
    description='CLI interface for Carbonara',
    long_description=readme,
    author='Andrea Fioraldi, Luigi Paolo Pileggi',
    author_email='andreafioraldi@gmail.com, {LUIGIMAIL}',
    url='https://github.com/andreafioraldi/Carbonara-CLI',
    package_dir={'carbonara_bininfo': 'carbonara_bininfo'},
    packages=['carbonara_bininfo'],
    scripts=['carbonara-cli', 'carbonara-cli.py'],
    install_requires=["python-idb", "progressbar2"]
)
