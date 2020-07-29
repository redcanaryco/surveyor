import csv
import json
import os
import time
from datetime import datetime
from pprint import pprint

import click
import cbapi.errors
from cbapi.response import CbEnterpriseResponseAPI
from cbapi.response.models import Process



def convert_relative_time(self, relative_time):
    """Convert a Cb Response relative time boundary (i.e., start:-1440m) to a
    device_timestamp:
      device_timestamp:[2019-06-02T00:00:00Z TO 2019-06-03T23:59:00Z]
    """
    time_format = "%Y-%m-%dT%H:%M:%SZ"
    minus_minutes = relative_time.split(':')[1].split('m')[0].split('-')[1]
    end_time = datetime.datetime.now()
    start_time = end_time - datetime.timedelta(minutes=int(minus_minutes))
    device_timestamp = 'device_timestamp:[{0} TO {1}]'.format(start_time.strftime(time_format),
                                                              end_time.strftime(time_format))
    return device_timestamp


def build_query(filters):
    query_base = ''

    for key, value in filters.items():
        if key == 'days':
            query_base += ' start:-%dm' % (value * 1440)

        if key == 'minutes':
            query_base += ' start:-%dm' % value

        if key == 'hostname':
            query_base += ' hostname:%s' % value

        if key == 'username':
            query_base += ' username:%s' % value

    return query_base


def process_search(cb_conn, base, user_query):

    results = set()

    query = user_query + build_query(base)
    click.echo(query)

    try:
        for proc in cb_conn.select(Process).where(query):
            results.add((proc.hostname.lower(),
                         proc.username.lower(),
                         proc.path,
                         proc.cmdline))
    except KeyboardInterrupt:
        click.echo("Caught CTRL-C. Returning what we have . . .")

    return results


def nested_process_search(cb_conn, criteria, base):
    results = set()

    try:
        for search_field, terms in criteria.items():
            query = '(' + ' OR '.join('%s:%s' % (search_field, term) for term in terms) + ')'
            query += build_query(base)

            for proc in cb_conn.select(Process).where(query):
                results.add((proc.hostname.lower(),
                             proc.username.lower(),
                             proc.path,
                             proc.cmdline))
    except KeyboardInterrupt:
        click.echo("Caught CTRL-C. Returning what we have . . .")
    except Exception as e:
        click.echo(e)

    return results

