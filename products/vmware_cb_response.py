import logging

from cbapi.response import CbEnterpriseResponseAPI # type: ignore
from cbapi.response.models import Process # type: ignore

from common import Product, Tag, Result, Optional


class CbResponse(Product):
    product: str = 'cbr'
    profile: str = 'default'
    url: Optional[str] = None
    token: Optional[str] = None
    _sensor_group: Optional[list[str]] = None
    _conn: CbEnterpriseResponseAPI  # CB Response API
    _limit: int = -1
    _raw: bool = False

    def __init__(self, **kwargs):
        self.profile = kwargs['profile'] if 'profile' in kwargs else 'default'
        self.url = kwargs['url'] if 'url' in kwargs else None
        self.token = kwargs['token'] if 'token' in kwargs else None
        self._sensor_group = kwargs['sensor_group'] if 'sensor_group' in kwargs else None
        self._limit = int(kwargs['limit']) if 'limit' in kwargs else self._limit
        self._raw = kwargs['raw'] if 'raw' in kwargs else self._raw

        super().__init__(self.product, **kwargs)

    def _authenticate(self) -> None:
        if self.token and self.url:
            cb_conn = CbEnterpriseResponseAPI(token=self.token, url=self.url)
        elif self.profile:
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
        #raw_results = list()
        results = set()

        query = query + self.build_query(base_query)
        self._echo(query)

        try:
            # noinspection PyUnresolvedReferences
            for proc in self._conn.select(Process).where(query):
                result = Result(proc.hostname.lower(), proc.username.lower(), proc.path, proc.cmdline,
                                (proc.start, proc.id))
                
                # Raw Feature (Inactive)
                '''
                if self._raw:
                    raw_results.append(proc)
                else:
                    results.add(result)
                '''
                results.add(result)

                if self._limit > 0 and len(results)+1 > self._limit:
                        break
                
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Returning what we have . . .")
        
        # Raw Feature (Inactive)
        '''
        if self._raw: 
            self._add_results(list(raw_results), tag)
        else:
            self._add_results(list(results), tag)
        '''
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
                    if self._limit > 0 and len(results)+1 > self._limit:
                        break
                    
        except Exception as e:
            self._echo(f'Error (see log for details): {e}', logging.ERROR)
            self.log.exception(e)
            pass
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Returning what we have . . .")

        self._add_results(list(results), tag)

    def get_other_row_headers(self) -> list[str]:
        return ['Process Start', 'Process GUID']