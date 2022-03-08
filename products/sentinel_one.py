import configparser
import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple, Union, Callable

import requests
from requests.adapters import HTTPAdapter

from common import Product
from help import datetime_to_epoch_millis


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
    _last_request: float

    def __init__(self, profile: str, creds_file: str, **kwargs):
        if not os.path.isfile(creds_file):
            raise ValueError(f'Credential file {creds_file} does not exist')

        self.creds_file = creds_file
        self._queries = dict()

        self._last_request = 0.0

        super().__init__(self.product, profile, **kwargs)

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

    def _get_all_paginated_data(self, url: str, params: Optional[dict] = None, headers: Optional[dict] = None,
                                key: str = 'data', after_request: Optional[Callable] = None,
                                limit: int = 1000) -> list[dict]:
        """
        Get and return all paginated data from the response, making additional queries if necessary.
        
        :param url: URL to make GET request to.

        :param params: Additional parameters for GET request

        :param limit: Number of items to query per page.

        :param headers: Additional headers for GET quest.

        :param key: Dictionary key in which result data resides.

        :param after_request: Optional callable that is executed after each pagination request. The callable is
        passed the response to the last API call.

        :returns: List containing data from all pages.
        """

        if params is None:
            params = dict()

        params.update(self._get_default_body())
        params['limit'] = limit

        if headers is None:
            headers = dict()

        headers.update(self._get_default_header())

        data = list[dict]()

        next_cursor = True
        while next_cursor:
            response = self._session.get(url, params=params, headers=headers)

            if after_request:
                # execute after request callback
                after_request(response)

            response.raise_for_status()

            call_data = response.json()[key]
            self.log.debug(f'Got {len(call_data)} results in page')
            data.extend(call_data)

            next_cursor = response.json()['pagination']['nextCursor']
            params['cursor'] = next_cursor

        return data

    def _get_dv_events(self, query_id: str) -> list[dict]:
        """
        Retrieve events associated with a SentinelOne Deep Visibility query ID.
        """
        while True:
            query_status_response = self._session.get(self._build_url('/web/api/v2.1/dv/query-status'),
                                                      params={'queryId': query_id}, headers=self._get_default_header())
            query_status_response.raise_for_status()
            data = query_status_response.json()['data']

            self.log.debug(str(data))

            if data['progressStatus'] == 100 or data['responseState'] == 'FAILED':
                if data['responseState'] == 'FAILED':
                    raise ValueError(f'S1QL query failed with message "{data["responseError"]}"')

                return self._get_all_paginated_data(self._build_url('/web/api/v2.1/dv/events'),
                                                    params={'queryId': query_id})
            else:
                # query-status endpoint has a one request per second rate limit
                time.sleep(1)

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

                if len(self._queries) == 10:
                    self._process_queries()
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Returning what we have...")

    def _process_queries(self):
        """
        Process all cached queries.
        """
        queries = set[Tuple[str, str]]()

        min_from_date = datetime.utcnow()
        to_date = min_from_date

        for tag, values in self._queries.items():
            for from_date, _, query in values:
                if from_date < min_from_date:
                    min_from_date = from_date

                queries.add((tag, query))

        queries = list(queries)

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

                merged_tag = (",".join(set(x[0] if isinstance(x, Tuple) else x for x in merged_tags)),
                              ",".join(set(x[1] if isinstance(x, Tuple) else x for x in merged_tags)))

                params = self._get_default_body()
                params.update({
                    "fromDate": datetime_to_epoch_millis(min_from_date),
                    "isVerbose": False,
                    "queryType": ['events'],  # options: 'events', 'procesState'
                    "limit": 20000,
                    "toDate": datetime_to_epoch_millis(to_date),
                    "query": merged_query
                })

                self.log.debug(f'Query params: {params}')

                # ensure we do not submit more than one request every 60 seconds to comply with rate limit
                seconds_sice_last_request = time.time() - self._last_request
                if seconds_sice_last_request < 60:
                    sleep_seconds = 60 - seconds_sice_last_request
                    self.log.debug(f'Sleeping for {sleep_seconds}')
                    time.sleep(sleep_seconds)

                query_response = self._session.post(self._build_url('/web/api/v2.1/dv/init-query'),
                                                    headers=self._get_default_header(), data=json.dumps(params))
                self._last_request = time.time()

                body = query_response.json()
                if 'errors' in body and any(('could not parse query' in x['detail'] for x in body['errors'])):
                    raise ValueError(f'S1 could not parse query "{merged_query}"')

                self.log.debug(query_response.json())
                query_response.raise_for_status()

                query_id = body['data']['queryId']
                self.log.info(f'Query ID is {query_id}')

                events = self._get_dv_events(query_id)
                self.log.debug(f'Got {len(events)} events')

                self._results[merged_tag] = list()
                for event in events:
                    hostname = event['endpointName']
                    username = event['srcProcUser']
                    path = event['processImagePath']
                    command_line = event['srcProcCmdLine']
                    self._results[merged_tag].append((hostname, username, path, command_line))

            self._queries.clear()
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Returning what we have . . .")

    def get_results(self, final_call: bool = True) -> dict[Union[str, Tuple], list[Tuple[str, str, str, str]]]:
        self.log.debug('Entered get_results')

        # process any unprocessed queries
        if final_call and len(self._queries) > 0:
            self.log.debug(f'Executing additional _process_queries')
            self._process_queries()

        return self._results
