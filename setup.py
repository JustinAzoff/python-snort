from setuptools import setup, find_packages
import sys, os
from glob import glob


version = '1.0.2'

setup(name='snort',
    version=version,
    description="snort database interface",
    long_description="""\
""",
    classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    keywords='snort',
    author='Justin Azoff',
    author_email='JAzoff@uamail.albany.edu',
    url='',
    license='MIT',
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    include_package_data=True,
    zip_safe=True,
    install_requires=[
        "SQLAlchemy >= 0.4",
        "IPy"
    ],
    scripts=glob('scripts/*'),
    entry_points = {
        'console_scripts': [
            'snort-rule-tester = snort.rule_tester:main',
        ]
    }
)

