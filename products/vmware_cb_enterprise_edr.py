import datetime
import logging

import cbc_sdk.errors
from cbc_sdk.rest_api import CBCloudAPI
from cbc_sdk.platform import Process
from cbc_sdk.base import QueryBuilder

from common import Product, Result, Tag

PARAMETER_MAPPING: dict[str, str] = {
    'process_name': 'process_name',
    'ipaddr': 'netconn_ipv4',
    'cmdline': 'process_cmdline',
    'digsig_publisher': 'process_publisher',
    'domain': 'netconn_domain',
    'internal_name': 'process_internal_name',
}

def _convert_relative_time(relative_time):
    """
    Convert a Cb Response relative time boundary (i.e., start:-1440m) to a device_timestamp:
    device_timestamp:[2019-06-02T00:00:00Z TO 2019-06-03T23:59:00Z]
    """
    time_format = "%Y-%m-%dT%H:%M:%SZ"
    minus_minutes = relative_time.split(':')[1].split('m')[0].split('-')[1]
    end_time = datetime.datetime.now()
    start_time = end_time - datetime.timedelta(minutes=int(minus_minutes))
    device_timestamp = 'device_timestamp:[{0} TO {1}]'.format(start_time.strftime(time_format),
                                                              end_time.strftime(time_format))
    return device_timestamp


class CbEnterpriseEdr(Product):
    product: str = 'cbc'
    _conn: CBCloudAPI  # CB Cloud API

    def __init__(self, profile: str, **kwargs):
        super().__init__(self.product, profile, **kwargs)

    def _authenticate(self):
        if self.profile:
            cb_conn = CBCloudAPI(profile=self.profile)
        else:
            cb_conn = CBCloudAPI()

        self._conn = cb_conn

    def build_query(self, filters: dict):
        query_base = QueryBuilder()

        for key, value in filters.items():
            if key == "days":
                minutes_back = f'start:-{value * 1440}m'
                minutes_back = _convert_relative_time(minutes_back)
                query_base.and_(minutes_back)
            elif key == "minutes":
                minutes_back = f'start:-{value}m'
                minutes_back = _convert_relative_time(minutes_back)
                query_base.and_(minutes_back)
            elif key == "hostname":
                device_name = f'device_name:{value}'
                query_base.and_(device_name)
            elif key == "username":
                user_name = f'process_username:{value}'
                query_base.and_(user_name)
            else:
                self._echo(f'Query filter {key} is not supported by product {self.product}', logging.WARNING)

        return query_base

    def process_search(self, tag: Tag, base_query: dict, query: str) -> None:
        results = set()

        if len(base_query) >= 1:
            base_query = self.build_query(base_query)
            string_query = base_query.where(query)
        else:
            string_query = query

        try:
            query = self._conn.select(Process)

            # noinspection PyUnresolvedReferences
            for proc in query.where(string_query):
                deets = proc.get_details()

                result = Result(deets['device_name'], deets['process_username'][0], deets['process_name'], deets['process_cmdline'][0],
                                (deets['device_timestamp'], deets['process_guid'],))
                results.add(result)
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Returning what we have.")

        self._add_results(list(results), tag)

    def nested_process_search(self, tag: Tag, criteria: dict, base_query: dict) -> None:
        results = set()
        base_query = self.build_query(base_query)

        for search_field, terms in criteria.items():
            try:
                # quote terms with spaces in them
                terms = [(f'"{term}"' if ' ' in term else term) for term in terms]

                if search_field not in PARAMETER_MAPPING:
                    self._echo(f'Query filter {search_field} is not supported by product {self.product}',
                               logging.WARNING)
                    continue

                query = '(' + ' OR '.join('%s:%s' % (PARAMETER_MAPPING[search_field], term) for term in terms) + ')'

                self.log.debug(f'Query {tag}: {query}')

                process = self._conn.select(Process)

                full_query = base_query.where(query)

                self.log.debug(f'Full Query: {full_query}')

                # noinspection PyUnresolvedReferences
                for proc in process.where(full_query):
                    deets = proc.get_details()
                    result = Result(deets['device_name'], deets['process_username'][0], deets['process_name'],
                                    deets['process_cmdline'][0], (deets['device_timestamp'], deets['process_guid'],))
                    results.add(result)
            except cbc_sdk.errors.ApiError as e:
                self._echo(f'CbC SDK Error (see log for details): {e}', logging.ERROR)
                self.log.exception(e)
            except KeyboardInterrupt:
                self._echo("Caught CTRL-C. Returning what we have . . .")

        self.log.debug(f'Nested search results: {len(results)}')
        self._add_results(list(results), tag)

    def get_other_row_headers(self) -> list[str]:
        return ['Device Timestamp', 'Process GUID']
