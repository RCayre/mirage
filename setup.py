#!/usr/bin/env python

from setuptools import setup, find_packages

import mirage

setup(

    name='mirage',

    version=mirage.__version__,

    packages=find_packages(),

    author="Romain Cayre",

    author_email="rcayre@laas.fr",

    description="Mirage is an offensive framework dedicated to the security analysis of wireless communication protocols",

    install_requires=["keyboard","terminaltables","pyusb","pyserial","pycryptodomex","psutil","scapy","matplotlib"], 

    include_package_data=True,

    url='https://redmine.laas.fr/projects/mirage',


    classifiers=[
        "Programming Language :: Python",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: French",
        "Operating System :: Linux",
        "Programming Language :: Python :: 3.6",
        "Topic :: Security",
    ],

    entry_points = {
        'console_scripts': [
            'mirage = mirage.mirage:main',
        ],
    },
)
