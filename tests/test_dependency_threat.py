#!/usr/bin/env python

"""Tests for `dependency_threat` package."""

import pytest

from click.testing import CliRunner

from dependency_threat.dependency_threat import analyze
from dependency_threat import cli


@pytest.fixture
def response():
    """Sample pytest fixture.

    See more at: http://doc.pytest.org/en/latest/fixture.html
    """
    # import requests
    # return requests.get('https://github.com/audreyr/cookiecutter-pypackage')


def test_content(response):
    """Sample pytest test function with the pytest fixture as an argument."""
    # from bs4 import BeautifulSoup
    # assert 'GitHub' in BeautifulSoup(response.content).title.string


def test_command_line_interface():
    """Test the CLI."""
    runner = CliRunner()
    result = runner.invoke(
        cli.console, args=["https://github.com/wasi0013/online-voting-system"]
    )
    assert result.exit_code == 0
    help_result = runner.invoke(cli.console, ["--help"])
    assert help_result.exit_code == 0
