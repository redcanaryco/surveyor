import logging

from cbapi.response import CbEnterpriseResponseAPI
from cbapi.response.models import Process

from common import Product, Tag, Result


class CbResponse(Product):
    product: str = 'cbr'
    _conn: CbEnterpriseResponseAPI  # CB Response API

    def __init__(self, profile: str, **kwargs):
        self._sensor_group = kwargs['sensor_group'] if 'sensor_group' in kwargs else None

        super().__init__(self.product, profile, **kwargs)

    def _authenticate(self) -> None:
        if self.profile:
            cb_conn = CbEnterpriseResponseAPI(profile=self.profile)
        else:
            cb_conn = CbEnterpriseResponseAPI()

        self._conn = cb_conn

    def build_query(self, filters: dict) -> str:
        query_base = ''

        for key, value in filters.items():
            if key == 'days':
                query_base += ' start:-%dm' % (value * 1440)
            elif key == 'minutes':
                query_base += ' start:-%dm' % value
            elif key == 'hostname':
                query_base += ' hostname:%s' % value
            elif key == 'username':
                query_base += ' username:%s' % value
            else:
                self._echo(f'Query filter {key} is not supported by product {self.product}', logging.WARNING)

        if self._sensor_group:
            sensor_group = []
            for name in self._sensor_group:
                sensor_group.append('group:"%s"' % name)            
            query_base += ' (' + ' OR '.join(sensor_group) + ')'
        
        return query_base

    def process_search(self, tag: Tag, base_query: dict, query: str) -> None:
        results = set()

        query = query + self.build_query(base_query)
        self._echo(query)

        try:
            # noinspection PyUnresolvedReferences
            for proc in self._conn.select(Process).where(query):
                result = Result(proc.hostname.lower(), proc.username.lower(), proc.path, proc.cmdline,
                                (proc.start, proc.id))
                results.add(result)
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Returning what we have . . .")

        self._add_results(list(results), tag)

    def nested_process_search(self, tag: Tag, criteria: dict, base_query: dict) -> None:
        results = set()

        try:
            for search_field, terms in criteria.items():
                if search_field == 'query':
                    if isinstance(terms, list):
                        if len(terms) > 1:
                            query = '((' + ') OR ('.join(terms) + '))'
                        else:
                            query = '(' + terms[0] + ')'
                    else:
                        query = terms
                else:
                    terms = [(f'"{term}"' if ' ' in term else term) for term in terms]

                    query = '(' + ' OR '.join('%s:%s' % (search_field, term) for term in terms) + ')'

                query += self.build_query(base_query)
                
                self.log.debug(f'Query: {query}')
                # noinspection PyUnresolvedReferences
                for proc in self._conn.select(Process).where(query):
                    result = Result(proc.hostname.lower(), proc.username.lower(), proc.path, proc.cmdline,
                                    (proc.start,))
                    results.add(result)
        except Exception as e:
            self._echo(f'Error (see log for details): {e}', logging.ERROR)
            self.log.exception(e)
            pass
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Returning what we have . . .")

        self._add_results(list(results), tag)

    def get_other_row_headers(self) -> list[str]:
        return ['Process Start', 'Process GUID']
