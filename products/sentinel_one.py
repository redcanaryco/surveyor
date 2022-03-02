import configparser
import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple, Union

import requests
from requests.adapters import HTTPAdapter

from common import Product


def _get_epoch_millis(date: datetime) -> int:
    return int((date - datetime.utcfromtimestamp(0)).total_seconds() * 1000)


class SentinelOne(Product):
    """
    Surveyor implementation for product "SentinelOne"
    """
    product: str = 's1'
    creds_file: str  # path to credential configuration file
    _token: str  # AAD access token
    _url: str  # URL of SentinelOne console
    _site_id: Optional[str]  # Site ID for SentinelOne
    _account_id: Optional[str]  # Account ID for SentinelOne
    _session: requests.Session
    _queries: dict[str, list[Tuple[datetime, datetime, str]]]

    def __init__(self, profile: str, creds_file: str):
        if not os.path.isfile(creds_file):
            raise ValueError(f'Credential file {creds_file} does not exist')

        self.creds_file = creds_file
        self._queries = dict()

        super().__init__(self.product, profile)

    def _authenticate(self):
        config = configparser.ConfigParser()
        config.read(self.creds_file)

        if self.profile not in config:
            raise ValueError(f'Profile {self.profile} is not present in credential file')

        section = config[self.profile]

        # ensure configuration has required fields
        if 'url' not in section:
            raise ValueError(f'S1 configuration invalid, ensure "url" is specified')

        if 'site_id' not in section and 'account_id' not in section:
            raise ValueError(f'S1 configuration invalid, specify a site_id or account_id')

        # extract required information from configuration
        if 'token' in section:
            self._token = section['token']
        else:
            if 'S1_TOKEN' not in os.environ:
                raise ValueError(f'S1 configuration invalid, specify "token" configuration value or "S1_TOKEN" '
                                 f'environment variable')
            self._token = os.environ['S1_TOKEN']

        self._site_id = section['site_id'] if 'site_id' in section else None
        self._account_id = section['account_id'] if 'account_id' in section else None

        self._url = section['url'].rstrip('/')

        if not self._url.startswith('https://'):
            raise ValueError(f'URL must start with "https://"')

        # create a session and a pooled HTTPAdapter
        self._session = requests.session()
        self._session.mount('https://', HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=3))

        # test API key by retrieving the sensor count, which is a fast operation
        data = self._session.get(self._build_url('/web/api/v2.1/agents/count'),
                                 headers=self._get_default_header(),
                                 params=self._get_default_body()).json()

        if 'errors' in data:
            if data['code'] == 4010010:
                raise ValueError(f'Failed to authenticate to SentinelOne: {data}')
            else:
                raise ValueError(f'Error when authenticating to SentinelOne: {data}')

    def _build_url(self, stem: str):
        """
        Assemble URL for SentinelOne API query using base URI and URI stem.
        """
        if not stem.startswith('/'):
            stem = '/' + stem

        return self._url + stem

    def _get_default_body(self) -> dict:
        """
        Get the default request body for a SentinelOne API query.
        """
        return {"siteIds": [self._site_id]} if self._site_id else {"accountIds": [self._account_id]}

    def _get_default_header(self):
        """
        Get the default header for a SentinelOne API query.
        """
        return {"Authorization": f"ApiToken {self._token}", "Content-Type": "application/json"}

    def build_query(self, filters: dict) -> Tuple[str, datetime, datetime]:
        to_date = datetime.utcnow()
        from_date = to_date - timedelta(days=14)
        
        query_base = ''

        for key, value in filters.items():
            if key == 'days':
                from_date = to_date - timedelta(days=value)
            elif key == 'minutes':
                from_date = to_date - timedelta(minutes=value)
            elif key == 'hostname':
                if query_base:
                    query_base += ' AND '

                query_base += f' EndpointName containscis "{value}"'
            elif key == 'username':
                if query_base:
                    query_base += ' AND '

                query_base += f' UserName containscis "{value}"'
            else:
                self._echo(f'Query filter {key} is not supported by product {self.product}', logging.WARNING)

        # S1 requires the date range to be supplied in the query request, not the query text
        # therefore we return the from/to dates separately
        return query_base, from_date, to_date

    def _get_all_paginated_data(self, response: requests.Response, params: Optional[dict] = None,
                                key='data') -> list[dict]:
        """
        Get and return all paginated data from the response, making additional queries if necessary.
        """
        response.raise_for_status()

        data = list[dict]()
        data.extend(response.json()[key])

        pagination_info = response.json()['pagination']
        while pagination_info['nextCursor']:
            response = self._session.get(pagination_info['nextCursor'],
                                         params=params, headers=self._get_default_header())
            response.raise_for_status()
            data.extend(response.json()[key])
            pagination_info = response.json()['pagination']

        return data

    def _get_dv_events(self, query_id: str) -> list[dict]:
        """
        Retrieve events associated with a SentinelOne Deep Visibility query ID.
        """
        params = {
            'queryId': query_id,
            'limit': 1000,
        }

        while True:
            query_status_response = self._session.get(self._build_url('/web/api/v2.1/dv/query-status'),
                                                      params={'queryId': query_id}, headers=self._get_default_header())
            query_status_response.raise_for_status()
            data = query_status_response.json()['data']

            self.log.debug(str(data))

            if data['progressStatus'] == 100 or data['responseState'] == 'FAILED':
                if data['responseState'] == 'FAILED':
                    raise ValueError(f'S1QL query failed with message "{data["responseError"]}"')

                response = self._session.get(self._build_url('/web/api/v2.1/dv/events'),
                                             params=params, headers=self._get_default_header())

                return self._get_all_paginated_data(response)
            else:
                time.sleep(10)

    def process_search(self, tag: Union[str, Tuple], base_query: dict, query: str) -> None:
        build_query, from_date, to_date = self.build_query(base_query)
        query = query + build_query
        self._echo(f'Built Query: {query}')

        if tag not in self._queries:
            self._queries[tag] = list()

        self._queries[tag].append((from_date, to_date, query))

    def nested_process_search(self, tag: Union[str, Tuple], criteria: dict, base_query: dict):
        query_base, from_date, to_date = self.build_query(base_query)

        try:
            for search_field, terms in criteria.items():
                all_terms = ', '.join(f'"{term}"' for term in terms)

                if search_field == 'process_name':
                    query = f"ProcessName in contains anycase ({all_terms})"
                elif search_field == "ipaddr":
                    query = f"IP in contains anycase ({all_terms})"
                elif search_field == "cmdline":
                    query = f"CmdLine in contains anycase ({all_terms})"
                elif search_field == "digsig_publisher":
                    query = f"SrcProcPublisher in contains anycase ({all_terms})"
                elif search_field == "domain":
                    query = f"Url in contains anycase ({all_terms})"
                elif search_field == "internal_name":
                    query = f"TgtFileInternalName in contains anycase ({all_terms})"
                else:
                    self._echo(f'Query filter {search_field} is not supported by product {self.product}',
                               logging.WARNING)
                    continue

                if tag not in self._queries:
                    self._queries[tag] = list()

                self._queries[tag].append((from_date, to_date, query))
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Returning what we have...")

    def get_results(self) -> dict[Union[str, Tuple], list[Tuple[str, str, str, str]]]:
        self.log.debug('Entered get_results')

        if len(self._queries) == 0:
            return dict()

        queries = set[Tuple[str, str]]()

        min_from_date = datetime.utcnow()
        to_date = min_from_date

        for tag, values in self._queries.items():
            for from_date, _, query in values:
                if from_date < min_from_date:
                    min_from_date = from_date

                queries.add((tag, query))

        queries = list(queries)

        results = dict[Union[str, Tuple], list[Tuple[str, str, str, str]]]()
        try:
            # merge queries into one large query
            first = True
            for i in range(0, len(queries), 10):
                # do not chain more than 10 ORs in a S1QL query

                if first:
                    first = False
                else:
                    # S1 has rate limit of 1 DB search per 60 seconds
                    time.sleep(60)

                merged_tags = set()
                merged_query = ''
                for tag, query in queries[i:i + 10]:
                    if merged_query:
                        merged_query += ' OR '

                    merged_query += query
                    merged_tags.add(tag)

                merged_tag = (",".join((x[0] if isinstance(x, Tuple) else x for x in merged_tags)),
                              ",".join((x[1] if isinstance(x, Tuple) else x for x in merged_tags)))

                params = self._get_default_body()
                params.update({
                    "fromDate": _get_epoch_millis(min_from_date),
                    "isVerbose": False,
                    "queryType": ['events'],  # options: 'events', 'procesState'
                    "limit": 20000,
                    "toDate": _get_epoch_millis(to_date),
                    "query": merged_query
                })

                self.log.debug(f'Query params: {params}')

                query_response = self._session.post(self._build_url('/web/api/v2.1/dv/init-query'),
                                                    headers=self._get_default_header(), data=json.dumps(params))

                body = query_response.json()
                if 'errors' in body and any(('could not parse query' in x['detail'] for x in body['errors'])):
                    raise ValueError(f'S1 could not parse query "{merged_query}"')

                self.log.debug(query_response.json())
                query_response.raise_for_status()

                query_id = body['data']['queryId']
                self.log.info(f'Query ID is {query_id}')

                results[merged_tag] = list()
                for event in self._get_dv_events(query_id):
                    hostname = event['endpointName']
                    username = event['srcProcUser']
                    path = event['processImagePath']
                    command_line = event['srcProcCmdLine']
                    results[merged_tag].append((hostname, username, path, command_line))
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Returning what we have . . .")

        return results
