#! /usr/bin/env python3
from setuptools import setup

import pathlib

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

setup(
    name                =   "cyberwala",
    version             =   '1.2',
    description         =   "CyberWala Advance Vuln Scanner - The Multi-Tool Web Vulnerability Scanner.",
    long_description    =   README,
    long_description_content_type = "text/markdown",
    url                 =   "https://github.com/yourusername/cyberwala",
    author              =   "Your Name",
    py_modules          =   ['cyberwala',],
    install_requires    =   [],
    python_requires=">=3.6",
)
