import datetime
import logging

import cbapi.errors
from cbapi.psc.threathunter import CbThreatHunterAPI, Process
from cbapi.psc.threathunter import QueryBuilder

from common import Product, Result, Tag


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
    _conn: CbThreatHunterAPI  # CB Response API

    def __init__(self, profile: str, **kwargs):
        self._device_group = kwargs['device_group']
        self._device_policy = kwargs['device_policy']

        super().__init__(self.product, profile, **kwargs)

    def _authenticate(self):
        if self.profile:
            cb_conn = CbThreatHunterAPI(profile=self.profile)
        else:
            cb_conn = CbThreatHunterAPI()

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

        if self._device_group:
            device_group = []
            for name in self._device_group:
                device_group.append(f'device_group:"{name}"')
            query_base.and_('(' + ' OR '.join(device_group) + ')')

        if self._device_policy:
            device_policy = []
            for name in self._device_policy:
                device_policy.append(f'device_policy:"{name}"')
            query_base.and_('(' + ' OR '.join(device_policy) + ')')

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
                result = Result(proc.device_name, proc.process_username[0], proc.process_name, proc.process_cmdline[0],
                                (proc.device_timestamp,))
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

                # translate search fields not handled by convert_query
                if search_field == 'username':
                    search_field = 'process_username'

                def_query = '(' + ' OR '.join('%s:%s' % (search_field, term) for term in terms) + ')'

                self.log.debug(f'Query {tag}: {def_query}')

                # convert the legacy from CbR to CbTh
                query = self._conn.convert_query(def_query)

                process = self._conn.select(Process)

                full_query = base_query.where(query)

                self.log.debug(f'Full Query: {full_query}')

                # noinspection PyUnresolvedReferences
                for proc in process.where(full_query):
                    hostname = proc.device_name if hasattr(proc, 'device_name') else 'UNKNOWN'
                    user = proc.process_username[0] if hasattr(proc, 'process_username') else 'UNKNOWN'
                    proc_name = proc.process_name if hasattr(proc, 'process_name') else 'UNKNOWN'
                    cmdline = proc.process_cmdline[0] if hasattr(proc, 'process_cmdline') else 'UNKNOWN'
                    ts = proc.device_timestamp if hasattr(proc, 'device_timestamp') else 'UNKNOWN'
                    result = Result(hostname, user, proc_name, cmdline, (ts,))
                    results.add(result)
            except cbapi.errors.ApiError as e:
                self._echo(f'Cb API Error (see log for details): {e}', logging.ERROR)
                self.log.exception(e)
            except KeyboardInterrupt:
                self._echo("Caught CTRL-C. Returning what we have . . .")

        self.log.debug(f'Nested search results: {len(results)}')
        self._add_results(list(results), tag)

    def get_other_row_headers(self) -> list[str]:
        return ['Device Timestamp']
