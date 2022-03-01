from datetime import datetime, timedelta

import click
from cbapi.response import CbEnterpriseResponseAPI
from cbapi.response.models import Process

from common import Product


def _convert_relative_time(relative_time):
    """
    Convert a Cb Response relative time boundary (i.e., start:-1440m) to a device_timestamp:
    device_timestamp:[2019-06-02T00:00:00Z TO 2019-06-03T23:59:00Z]
    """
    time_format = "%Y-%m-%dT%H:%M:%SZ"
    minus_minutes = relative_time.split(':')[1].split('m')[0].split('-')[1]
    end_time = datetime.now()
    start_time = end_time - timedelta(minutes=int(minus_minutes))
    device_timestamp = 'device_timestamp:[{0} TO {1}]'.format(start_time.strftime(time_format),
                                                              end_time.strftime(time_format))
    return device_timestamp


class CbResponse(Product):
    product: str = 'cbr'
    _conn: CbEnterpriseResponseAPI  # CB Response API

    def __init__(self, profile: str):
        super().__init__(self.product, profile)

    def _authenticate(self):
        if self.profile:
            cb_conn = CbEnterpriseResponseAPI(profile=self.profile)
        else:
            cb_conn = CbEnterpriseResponseAPI()

        self._conn = cb_conn

    def build_query(self, filters: dict):
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

    def process_search(self, base_query, query):
        results = set()

        query = query + self.build_query(base_query)
        click.echo(query)

        try:
            # noinspection PyUnresolvedReferences
            for proc in self._conn.select(Process).where(query):
                results.add((proc.hostname.lower(),
                             proc.username.lower(),
                             proc.path,
                             proc.cmdline))
        except KeyboardInterrupt:
            click.echo("Caught CTRL-C. Returning what we have . . .")

        return results

    def nested_process_search(self, criteria, base_query):
        results = set()

        try:
            for search_field, terms in criteria.items():
                query = '(' + ' OR '.join('%s:%s' % (search_field, term) for term in terms) + ')'
                query += self.build_query(base_query)

                # noinspection PyUnresolvedReferences
                for proc in self._conn.select(Process).where(query):
                    results.add((proc.hostname.lower(),
                                 proc.username.lower(),
                                 proc.path,
                                 proc.cmdline))
        except Exception as e:
            click.echo(e)
            pass
        except KeyboardInterrupt:
            click.echo("Caught CTRL-C. Returning what we have . . .")

        return results
