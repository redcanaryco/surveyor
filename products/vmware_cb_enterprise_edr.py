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
    product: str = 'cbth'
    _conn: CbThreatHunterAPI  # CB Response API

    def __init__(self, profile: str, **kwargs):
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
                user_name = f'username:{value}'
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
                result = Result(proc.device_name, proc.process_username[0], proc.process_name, proc.process_cmdline[0])
                results.add(result)
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Returning what we have.")

        self._add_results(list(results), tag)

    def nested_process_search(self, tag: Tag, criteria: dict, base_query: dict) -> None:
        results = set()
        base_query = self.build_query(base_query)

        for search_field, terms in criteria.items():
            try:
                def_query = '(' + ' OR '.join('%s:%s' % (search_field, term) for term in terms) + ')'

                # convert the legacy from CbR to CbTh
                query = self._conn.convert_query(def_query)

                process = self._conn.select(Process)

                full_query = base_query.where(query)

                # noinspection PyUnresolvedReferences
                for proc in process.where(full_query):
                    result = Result(proc.device_name, proc.process_username[0], proc.process_name,
                                    proc.process_cmdline[0])
                    results.add(result)
            except cbapi.errors.ApiError as e:
                self._echo(f'Cb API Error (see log for details): {e}', logging.ERROR)
                self.log.exception(e)
                pass
            except KeyboardInterrupt:
                self._echo("Caught CTRL-C. Returning what we have . . .")
                pass

        self._echo(f'Nested search results: {len(results)}')
        self._add_results(list(results), tag)
