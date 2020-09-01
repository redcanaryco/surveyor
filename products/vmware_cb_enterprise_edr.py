import csv
import json
import os
import time
import datetime
from pprint import pprint

import click
import cbapi.errors
from cbapi.psc.threathunter import QueryBuilder
from cbapi.psc.threathunter import CbThreatHunterAPI, Process


def convert_relative_time(relative_time):
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
    query_base = QueryBuilder()

    for key, value in filters.items():
        if key == "days":
            minutes_back = f'start:-{value * 1440}m'
            minutes_back = convert_relative_time(minutes_back)
            query_base.and_(minutes_back)

        if key == "minutes":
            minutes_back = f'start:-{value}m'
            minutes_back = convert_relative_time(minutes_back)
            query_base.and_(minutes_back)

        if key == "hostname":
            device_name = f'device_name:{value}'
            query_base.and_(device_name)

        if key == "username":
            user_name = f'username:{value}'
            query_base.and_(user_name)

    return query_base


def process_search(cb_conn, base, user_query):
    results = set()

    if len(base) >= 1:
        base_query = build_query(base)
        string_query = base_query.where(user_query)
        # click.echo(string_query)
    else:
        string_query = user_query

    try:
        query = cb_conn.select(Process)
        for proc in query.where(string_query):
            # click.echo(f"Results: {proc} ")
            results.add((proc.device_name, proc.process_username[0], proc.process_name, proc.process_cmdline[0]))
    except KeyboardInterrupt:
        click.echo("Caught CTRL-C. Returning what we have.")

    return results


def nested_process_search(cb_conn, criteria, base):
    results = set()

    base_query = build_query(base)

    # pprint(vars(base), indent=4)
    def_query = ''
    for search_field, terms in criteria.items():
        try:
            def_query = '(' + ' OR '.join('%s:%s' % (search_field, term) for term in terms) + ')'
            # convert the legacy from CbR to CbTh
            query = cb_conn.convert_query(def_query)

            process = cb_conn.select(Process)

            full_query = base_query.where(query)
            for proc in process.where(full_query):
                # for proc in process.where(query):
                results.add(
                    (proc.device_name, proc.process_username[0], proc.process_name, proc.process_cmdline[0]))
        except cbapi.errors.ApiError as e:
            click.echo(e)
            pass
        except KeyboardInterrupt:
            click.echo("Caught CTRL-C. Returning what we have . . .")
            pass

    click.echo(len(results))

    return results
