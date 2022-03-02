import csv
import logging
import os
import re
from datetime import datetime
from typing import Iterator, Tuple, Optional

import click


# regular expression that detects ANSI color codes
ansi_escape_regex = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', re.VERBOSE)


def _strip_ansi_codes(message: str) -> str:
    """
    Strip ANSI sequences from a log string
    """
    return ansi_escape_regex.sub('', message)


def log_echo(message: str, log: logging.Logger, level: int = logging.DEBUG):
    """
    Write a command to STDOUT and the debug log stream.
    """
    color_message = message

    if level == logging.WARNING:
        color_message = f'\u001b[33m{color_message}\u001b[0m'
    elif level >= logging.ERROR:
        color_message = f'\u001b[31m{color_message}\u001b[0m'

    click.echo(color_message)

    # strip ANSI sequences from log string
    log.log(level, message)


def write_results(output: Optional[csv.writer], results: list[Tuple[str, str, str, str]], program: str, source: str,
                  template: Tuple[int, int, int, int, int, int] = (20, 20, 20, 20, 20, 20)):
    """
    Write results to output CSV.
    """
    template_str = f'{{:<{template[0]}}} {{:<{template[1]}}} {{:<{template[2]}}} {{:<{template[3]}}}'
    for hostname, username, path, command_line in results:
        row = [hostname, username, path, command_line, program, source]
        
        if output:
            output.writerow(row)
        else:
            # trim data to make sure it fits into table format
            for i in range(len(row)):
                if len(row[i]) > template[i]:
                    row[i] = row[i][:template[i] - 3] + '...'

            click.echo(template_str.format(*row))


def datetime_to_epoch_millis(date: datetime) -> int:
    """
    Convert a datetime object to an epoch timestamp in milliseconds.
    """
    return int((date - datetime.utcfromtimestamp(0)).total_seconds() * 1000)