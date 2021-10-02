#!/usr/bin/env python
import os
from setuptools import setup, find_packages
from securid import __version__

install_requires = [
    line.rstrip()
    for line in open(os.path.join(os.path.dirname(__file__), 'requirements.txt'))
]

setup(
    name='securid',
    version=__version__,
    description='Python RSA SecurID 128-bit compatible library',
    long_description='python-securid is a Python library for generating RSA SecurID 128-bit compatible token codes.',
    classifiers=[
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    keywords='securid otp',
    author='Andrea Bonomi',
    author_email='andrea.bonomi@gmail.com',
    url='http://github.com/andreax79/python-securid',
    license='MIT',
    packages=find_packages(exclude=['ez_setup', 'examples']),
    include_package_data=True,
    zip_safe=True,
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'securid=securid.cli:main',
        ],
    },
    test_suite='test',
    tests_require=['nose'],
)
