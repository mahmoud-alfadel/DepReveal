"""Console script for dependency_threat."""
import sys
import click
from .dependency_threat import analyze, generate_html
import pandas as pd
import os

@click.command()
@click.argument("url")
@click.option(
    "-i",
    "--i",
    "--interval",
    "interval",
    type=int,
    default=5,
    show_default=True,
    help="set custom commit interval",
)
@click.option(
    "-a",
    "--a",
    "--access_tokens",
    "access_tokens",
    type=str,
    multiple=True,
    required=True,
    help="Github Access Token, see: https://github.com/settings/tokens",
)


@click.option(
    "-o",
    "--o",
    "--output_file",
    "output_file",
    type=str,
    help="name & path of the output csv file. By Default it will save in the current folder.",
)
def console(url, interval, output_file, access_tokens):
    """ \n\033[1m✨ Dependency Threat ✨\033[0m - Analyze Github Repository to Find npm Vulnerabilities."""

    df = analyze(url, access_tokens, interval)
    if output_file:
        df.to_csv(output_file, index=False)
        with open(output_file.replace(".csv", ".html"), 'w') as f:
            f.write(generate_html(df))
        click.secho(
            " \n\033[1mOutput is saved in:\033[0m {}".format(output_file), fg="green"
        )
    else:
        with open('dependency_threat_report.html', 'w') as f:
            f.write(generate_html(df))
            click.secho(
            " \n\033[1mGenerated Report is saved in:\033[0m {}".format("dependency_threat_report.html"), fg="green"
        )
    return 0


if __name__ == "__main__":
    sys.exit(console())  # pragma: no cover
