#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

#with open("README.rst") as readme_file:
    #readme = readme_file.read()

#with open("HISTORY.rst") as history_file:
    #history = history_file.read()

requirements = [
    "plotly>=4.14.1",
    "click>=7.1.2",
    "lxml>=4.6.1",
    "node-semver>=0.8.0",
    "numpy>=1.19.4",
    "pandas>=1.1.4",
    "python-dateutil>=2.8.1",
    "requests>=2.24.0",
    "tqdm>=4.51.0",
    "xlrd>=1.2.0",
    "XlsxWriter>=1.3.7",
    "jinja2>=2.11.2",
    "colorama>=0.4.4",
]

setup_requirements = [
    "pytest-runner",
]

test_requirements = [
    "pytest>=3",
]

setup(
    author="Mahmoud Alfadel",
    author_email="alfadelmahmood@gmail.com",
    python_requires=">=3.5",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    description="A Command Line tool to analyze npm dependency vulnerability",
    entry_points={
        "console_scripts": ["dependency_threat=dependency_threat.cli:console",],
    },
    install_requires=requirements,
    license="MIT license",
    #long_description=readme + "\n\n" + history,
    include_package_data=True,
    keywords="dependency_threat",
    name="dependency_threat",
    packages=find_packages(include=["dependency_threat", "dependency_threat.*"]),
    setup_requires=setup_requirements,
    test_suite="tests",
    tests_require=test_requirements,
    url="https://github.com/mahmoud-alfadel/dependency_threat",
    version="0.0.1",
    zip_safe=False,
)
