import concurrent.futures
import configparser
import json
import logging
import os
import time
from concurrent.futures import Future
from math import ceil
from threading import Event

import click
from tqdm import tqdm
from dataclasses import dataclass
from datetime import datetime, timedelta

from typing import Optional, Tuple, Callable, Any, cast
import re

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import HTTPError

from common import Product, Tag, Result, AuthenticationError
from help import datetime_to_epoch_millis


@dataclass
class Query:
    start_date: datetime
    end_date: datetime
    parameter: Optional[str]
    operator: Optional[str]
    search_value: Optional[str]
    full_query: Optional[str] = None


PARAMETER_MAPPING_DV: dict[str, list[str]] = {
    'query': ['query'], # non-existent field to specify a fully defined query string in a definition file.
    'process_name': ['ProcessName'],
    'ipaddr': ['IP'],
    'cmdline': ['CmdLine'],
    'digsig_publisher': ['Publisher'],
    'domain': ['DNS'],
    'internal_name': ['TgtFileInternalName'],
    'url': ['Url'],
    'filemod': ['FilePath'],
    'modload': ['ModulePath'],
    'process_file_description': ['SrcProcDisplayName'],
    'md5': ['Md5'],
    'sha1':['Sha1'],
    'sha256':['Sha256']
}

PARAMETER_MAPPING_PQ: dict[str, list[str]] = {
    'query': ['query'],
    'process_name': ['src.process.name'],
    'ipaddr': ['dst.ip.address'],
    'url': ['url.address'],
    'cmdline': ['src.process.cmdline'],
    'digsig_publisher': ['src.process.publisher'],
    'domain': ['url.address'],
    'filemod': ['tgt.file.path'],
    'internal_name': ['tgt.file.internalName'],
    'modload': ['module.path'],
    'process_file_description': ['src.process.displayName'],
    'md5': ['src.process.image.md5', 'tgt.file.md5', 'module.md5'],
    'sha256':['src.process.image.sha256','tgt.file.sha256'],
    'sha1':['src.process.image.sha1','tgt.file.sha1','module.sha1']
}

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
    _queries: dict[Tag, list[Query]]
    _last_request: float
    _site_ids: list[str]
    _query_base: Optional[str]
    _pq: bool  # Run queries using PowerQuery instead of DeepVisibility

    def __init__(self, profile: str, creds_file: str, account_id: Optional[list[str]] = None,
                 site_id: Optional[list[str]] = None, account_name: Optional[list[str]] = None, pq: bool = False,
                 **kwargs):
        if not os.path.isfile(creds_file):
            raise ValueError(f'Credential file {creds_file} does not exist')

        self.creds_file = creds_file
        self._queries = dict()
        self._query_base = None
        self._pq = pq

        self._last_request = 0.0

        # Save these values to `self` for reference in _authenticate()
        self.site_id = site_id
        self.account_id = account_id
        self.account_name = account_name

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

        # extract required information from configuration
        if 'token' in section:
            self._token = section['token']
        else:
            if 'S1_TOKEN' not in os.environ:
                raise ValueError(f'S1 configuration invalid, specify "token" configuration value or "S1_TOKEN" '
                                 f'environment variable')
            self._token = os.environ['S1_TOKEN']

        self._url = section['url'].rstrip('/')

        if not self._url.startswith('https://'):
            raise ValueError(f'URL must start with "https://"')

        # create a session and a pooled HTTPAdapter
        self._session = requests.session()
        self._session.mount('https://', HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=3))

        # generate a list of site_ids based on config file and cmdline input
        # this will also test API keys as it goes
        self._get_site_ids(self.site_id, self.account_id, self.account_name)

        if len(self._site_ids) < 1 and len(self._account_ids) < 1:
            raise ValueError(f'S1 configuration invalid, specify a site_id, account_id, or account_name')

    def _get_site_ids(self, site_id, account_id, account_name):
        config = configparser.ConfigParser()
        config.read(self.creds_file)

        # check if any cmdline stuff was input - that will take precedence over config file stuff
        site_ids = site_id if site_id else list()
        account_ids = account_id if account_id else list()
        account_names = account_name if account_name else list()

        if not site_ids and not account_ids and not account_names:
            # extract account/site ID from configuration if set
            if 'account_id' in config[self.profile]:
                for scope_id in config[self.profile]['account_id'].split(','):
                    if scope_id not in account_ids:
                        account_ids.append(scope_id.strip())

            if 'site_id' in config[self.profile]:
                for scope_id in config[self.profile]['site_id'].split(','):
                    if scope_id not in site_ids:
                        site_ids.append(scope_id.strip())

            if 'account_name' in config[self.profile]:
                for name in config[self.profile]['account_name'].split(','):
                    if name not in account_names:
                        account_names.append(name.strip())

        # determine site and account IDs to query (default is all)
        self._site_ids = list()
        self._account_ids = list()

        if account_ids:  # verify provided account IDs are valid
            # create batch of 10 account IDs per call
            counter = 0
            temp_list = []
            i = 0
            while i < len(account_ids):
                temp_list.append(account_ids[i])
                counter += 1
                if counter == 10 or i == len(account_ids) - 1:
                    try:
                        response = self._get_all_paginated_data(self._build_url(f'/web/api/v2.1/accounts'),
                                                                params={'states': "active", 'ids': ','.join(temp_list)},
                                                                add_default_params=False)
                    except HTTPError as e:
                        if e.response.status_code == 401:
                            raise AuthenticationError('Failed to authenticate to SentinelOne API') from e
                        raise

                    for account in response:
                        if account['id'] not in self._account_ids:
                            self._account_ids.append(account['id'])

                    counter = 0
                    temp_list = []
                i += 1

            diff = list(set(account_ids) - set(self._account_ids))
            if len(diff) > 0:
                self.log.warning(f'Account IDs {",".join(diff)} not found.')

        if account_names:  # verify provided account names are valid
            temp_account_name = list()
            for name in account_names:
                try:
                    response = self._get_all_paginated_data(self._build_url('/web/api/v2.1/accounts'),
                                                            params={'states': "active", 'name': name},
                                                            add_default_params=False)
                except HTTPError as e:
                    if e.response.status_code == 401:
                        raise AuthenticationError('Failed to authenticate to SentinelOne API') from e
                    raise

                for account in response:
                    temp_account_name.append(account['name'])
                    if account['id'] not in self._account_ids:
                        self._account_ids.append(account['id'])

            diff = list(set(account_names) - set(temp_account_name))
            if len(diff) > 0:
                self.log.warning(f'Account names {",".join(diff)} not found')

        if site_ids:  # ensure specified site IDs are valid and not already covered by the account_ids listed above
            temp_site_ids = list()
            # create batches of 10 site_ids
            counter = 0
            temp_list = []
            i = 0
            while i < len(site_ids):
                temp_list.append(site_ids[i])
                counter += 1
                if counter == 10 or i == len(site_ids) - 1:
                    try:
                        response = self._get_all_paginated_data(self._build_url('/web/api/v2.1/sites'),
                                                                params={'state': "active",
                                                                        'siteIds': ','.join(site_ids)},
                                                                add_default_params=False)
                    except HTTPError as e:
                        if e.response.status_code == 401:
                            raise AuthenticationError('Failed to authenticate to SentinelOne API') from e
                        raise

                    for item in response:
                        for site in item['sites']:
                            temp_site_ids.append(site['id'])

                            if self._pq and site['id'] not in self._site_ids:
                                self._site_ids.append(site['id'])

                                if site['accountId'] not in self._account_ids:
                                    # PowerQuery won't honor Site ID filters unless the parent account ID is also
                                    # included in the request body
                                    self._account_ids.append(site['accountId'])
                            elif site['accountId'] not in self._account_ids and site['id'] not in self._site_ids:
                                self._site_ids.append(site['id'])
                    counter = 0
                    temp_list = []
                i += 1

            diff = list(set(site_ids) - set(temp_site_ids))
            if len(diff) > 0:
                self.log.warning(f'Site IDs {",".join(diff)} not found')

        # remove unnecessary variables from self
        self.__dict__.pop('site_id', None)
        self.__dict__.pop('account_id', None)
        self.__dict__.pop('account_name', None)

        self.log.debug(f'Site IDs: {self._site_ids}')
        self.log.debug(f'Account IDs: {self._account_ids}')

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
        body = {}
        if self._site_ids:
            body['siteIds'] = self._site_ids
        if self._account_ids:
            body['accountIds'] = self._account_ids
        return body

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
                if self._pq:
                    if query_base: 
                        query_base += ' and '
                    query_base += f'endpoint.name contains "{value}"'
                else:
                    if query_base:
                        query_base += ' AND '
                    query_base += f'EndpointName containscis "{value}"'
            elif key == 'username':
                if self._pq:
                    if query_base:
                        query_base += ' and '
                    query_base += f'src.process.user contains "{value}"'
                else:
                    if query_base:
                        query_base += ' AND '
                    query_base += f'UserName containscis "{value}"'
            else:
                self._echo(f'Query filter {key} is not supported by product {self.product}', logging.WARNING)

        # S1 requires the date range to be supplied in the query request, not the query text
        # therefore we return the from/to dates separately
        return query_base, from_date, to_date

    def _get_all_paginated_data(self, url: str, params: Optional[dict] = None, headers: Optional[dict] = None,
                                key: str = 'data', after_request: Optional[Callable] = None, limit: int = 1000,
                                no_progress: bool = True, progress_desc: str = 'Retrieving data',
                                add_default_params: bool = True) -> list[dict]:
        """
        Get and return all paginated data from the response, making additional queries if necessary.
        
        :param url: URL to make GET request to.

        :param params: Additional parameters for GET request

        :param limit: Number of items to query per page.

        :param headers: Additional headers for GET quest.

        :param key: Dictionary key in which result data resides.

        :param after_request: Optional callable that is executed after each pagination request. The callable is
        passed the response to the last API call.

        :param no_progress: Suppress progress bar.

        :param progress_desc: Specify description for progress bar.

        :param add_default_params: Whether _get_default_body() should be added to parameter set.

        :returns: List containing data from all pages.
        """
        if params is None:
            params = dict()

        if add_default_params:
            params.update(self._get_default_body())

        params['limit'] = limit

        if headers is None:
            headers = dict()

        headers.update(self._get_default_header())

        data = list[dict]()
        total: int = 0

        next_cursor = True
        with tqdm(desc=progress_desc, disable=not self._tqdm_echo or no_progress) as p_bar:
            while next_cursor:
                response = self._session.get(url, params=params, headers=headers)

                if after_request:
                    # execute after request callback
                    after_request(response)

                response.raise_for_status()

                call_data = response.json()[key]

                if not isinstance(call_data, list):
                    call_data = [call_data]

                self.log.debug(f'Got {len(call_data)} results in page')
                data.extend(call_data)
                pagination_data = response.json()['pagination']

                # update progress bar
                if pagination_data['totalItems'] > total:
                    total = pagination_data['totalItems']
                    p_bar.reset(total=total)

                p_bar.update(len(call_data))

                next_cursor = pagination_data['nextCursor']
                params['cursor'] = next_cursor

            return data

    def _get_dv_events(self, query_id: str, cancel_event: Event, p_bar_needed: bool = True) -> list[dict]:
        """
        Retrieve events associated with a SentinelOne Deep Visibility query ID.
        """
        p_bar = tqdm(desc='Running query',
                     disable=not self._tqdm_echo or not p_bar_needed,
                     total=100)

        def errors(_response_data: dict[str, Any]):
            return _response_data['errors'] if self._pq else _response_data['data']['responseError']

        def current_progress(_response_data: dict[str, Any]) -> int:
            return _response_data['data']['progress'] if self._pq else _response_data['data']['progressStatus']

        def current_status(_response_data: dict[str, Any]) -> int:
            return _response_data['data']['status'] if self._pq else _response_data['data']['responseState']

        try:
            last_progress_status = 0
            while not cancel_event.is_set():
                url = '/web/api/v2.1/dv/events/pq-ping' if self._pq else '/web/api/v2.1/dv/query-status'
                query_status_response = self._session.get(self._build_url(url),
                                                          params={'queryId': query_id},
                                                          headers=self._get_default_header())
                query_status_response.raise_for_status()
                response_data = query_status_response.json()

                p_bar.update((progress := current_progress(response_data)) - last_progress_status)
                last_progress_status = progress

                status = current_status(response_data)

                if progress == 100 or status == 'FAILED':
                    if status == 'FAILED':
                        raise ValueError(f'S1 query failed with message "{errors(response_data)}"')

                    p_bar.close()

                    if self._pq:
                        # PQ returns results in ping response when query is complete
                        return response_data['data']['data']
                    else:
                        # DV requires fetching results when query is complete
                        return self._get_all_paginated_data(self._build_url('/web/api/v2.1/dv/events'),
                                                            params={'queryId': query_id},
                                                            no_progress=False,
                                                            add_default_params=False,
                                                            progress_desc='Retrieving query results')
                else:
                    # query-status endpoint has a one request per second rate limit
                    time.sleep(1)

            return list()
        except Exception as e:
            p_bar.close()
            raise e

    def divide_chunks(self, l: list, n: int):
        for i in range(0, len(l), n):
            yield l[i:i + n]

    def process_search(self, tag: Tag, base_query: dict, query: str) -> None:
        build_query, from_date, to_date = self.build_query(base_query)
        self._query_base = build_query
        self._echo(f'Built Query: {query}')

        if tag not in self._queries:
            self._queries[tag] = list()

        built_query = Query(from_date, to_date, None, None, None, query)
        self._queries[tag].append(built_query)

    @property
    def parameter_mapping(self) -> dict[str, list[str]]:
        return PARAMETER_MAPPING_PQ if self._pq else PARAMETER_MAPPING_DV

    def nested_process_search(self, tag: Tag, criteria: dict, base_query: dict) -> None:
        query_base, from_date, to_date = self.build_query(base_query)
        self._query_base = query_base
        try:
            for search_field, terms in criteria.items():
                if search_field not in self.parameter_mapping:
                    self._echo(f'Query filter {search_field} is not supported by product {self.product}',
                               logging.WARNING)
                    continue

                parameter = self.parameter_mapping[search_field]

                if tag not in self._queries:
                    self._queries[tag] = list()

                if self._pq:
                    for param in parameter:
                        if param == 'query':
                            if len(terms) > 1:
                                search_value = '(' + ') or ('.join(terms) + ')'
                            else:
                                search_value = terms[0]
                            self._queries[tag].append(Query(from_date, to_date, None, None, None, search_value))
                        else:
                            search_value = '(' + ', '.join(f'"{x}"' for x in terms) + ')'
                            self._queries[tag].append(Query(from_date, to_date, param, 'in', search_value))
                else:
                    # play nice with 100 item limit per search field
                    chunked_terms = list(self.divide_chunks(terms, 100))
                    for chunk in chunked_terms:
                        search_value = ', '.join(f'"{x}"' for x in chunk)

                        for param in parameter:
                            if param == 'query':
                                # Formats queries as (a) OR (b) OR (c) OR (d)
                                if len(chunk) > 1:
                                    search_value = '(' + ') OR ('.join(chunk) + ')'
                                else:
                                    search_value = terms[0]
                                operator = 'raw'
                            elif len(terms) > 1:
                                search_value = f'({search_value})'
                                operator = 'in contains anycase'
                            elif not re.findall(r'\w+\.\w+', search_value) and tag.tag.startswith("IOC - "):
                                operator = 'regexp'
                            else:
                                operator = 'containscis'

                            self._queries[tag].append(Query(from_date, to_date, param, operator, search_value))
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Returning what we have...")

    def _get_query_text(self) -> list[Tuple[Tag, str]]:
        # tuple contains tag and full query
        # these chunks will be combined with OR statements and executed
        query_text = list[Tuple[Tag, str]]()

        if self._pq:
            query_text = list[Tuple[Tag, str]]()

            for tag, queries in self._queries.items():
                for query in queries:
                    if query.full_query is not None:
                        query_text.append((tag, query.full_query))
                    else:
                        full_query = f'{query.parameter} {query.operator} {query.search_value}'
                        query_text.append((tag, full_query))
        else:
            # key is a tuple of the query operator and parameter
            # value is a list of Tuples where each tuple contains the query tag and search value
            combined_queries = dict[Tuple[str, str], list[Tuple[Tag, str]]]()

            for tag, queries in self._queries.items():
                for query in queries:
                    if query.operator in ('contains', 'containscis', 'contains anycase'):
                        key = (cast(str, query.operator), cast(str, query.parameter))
                        if key not in combined_queries:
                            combined_queries[key] = list()

                        combined_queries[key].append((tag, cast(str, query.search_value)))
                    elif query.full_query is not None:
                        query_text.append((tag, query.full_query))
                    elif query.operator == 'raw':
                        full_query = f'({query.search_value})'
                        query_text.append((tag, full_query))
                    else:
                        full_query = f'{query.parameter} {query.operator} {query.search_value}'
                        query_text.append((tag, full_query))

            # merge combined queries and add them to query_text
            data: list[Tuple[Tag, str]]
            for (operator, parameter), data in combined_queries.items():
                if operator in ('contains', 'containscis', 'contains anycase'):
                    full_query = f'{parameter} in contains anycase ({", ".join(x[1] for x in data)})'

                    tag = Tag(','.join(tag[0].tag for tag in data),
                              ','.join(tag[0].data if tag[0].data else '' for tag in data))
                    query_text.append((tag, full_query))
                else:
                    raise NotImplementedError(f'Combining operator "{operator}" queries is not support')

        return query_text

    def _run_query(self, merged_query: str, start_date: datetime, end_date: datetime, merged_tag: Tag,
                   cancel_event: Event, p_bar_needed: bool = True) -> None:
        try:
            if cancel_event.is_set():
                return

            # build request body for DV API call
            params = self._get_default_body()
            params.update({
                "fromDate": datetime_to_epoch_millis(start_date),
                "toDate": datetime_to_epoch_millis(end_date),
                "limit": 20000,
                "query": merged_query
            })

            if not self._pq:
                params.update({
                    "isVerbose": False,
                    "queryType": ['events'],  # options: 'events', 'procesState'
                })

            self.log.debug(f'Query params: {params}')

            if not self._pq:
                # ensure we do not submit more than one request every 60 seconds to comply with rate limit
                seconds_sice_last_request = time.time() - self._last_request
                if seconds_sice_last_request < 60:
                    sleep_seconds = 60 - seconds_sice_last_request
                    self.log.debug(f'Sleeping for {sleep_seconds}')

                    cancel_event.wait(ceil(sleep_seconds))

            # start deep visibility API call
            url = '/web/api/v2.1/dv/events/pq' if self._pq else '/web/api/v2.1/dv/init-query'
            query_response = self._session.post(self._build_url(url),
                                                headers=self._get_default_header(), data=json.dumps(params))
            self._last_request = time.time()

            body = query_response.json()
            if 'errors' in body and any(('could not parse query' in x['detail'] for x in body['errors'])):
                raise ValueError(f'S1 could not parse query "{merged_query}"')

            self.log.debug(query_response.json())
            query_response.raise_for_status()

            query_id = body['data']['queryId']
            self.log.info(f'Query ID is {query_id}')

            if self._pq and body['data']['status'] == 'FINISHED': # If using PQ, the results can be returned immediately
                events = body['data']['data']
            else:
                events = self._get_dv_events(query_id, p_bar_needed=p_bar_needed, cancel_event=cancel_event)
            self.log.debug(f'Got {len(events)} events')

            self._results[merged_tag] = list()

            for event in events:
                if self._pq:
                    hostname = event[0]
                    username = event[1]
                    path = event[2]
                    command_line = event[3]
                    additional_data = (event[8], event[9], event[10], event[11],'None','None','None','None','None','None','None','None','None','None','None','None')
                else:
                    hostname = event['endpointName']
                    username = event['srcProcUser']
                    path = event['srcProcImagePath']
                    srcprocstorylineid = event['srcProcStorylineId'] if 'srcProcStorylineId' in event else 'None'
                    srcprocdisplayname = event['srcProcDisplayName'] if 'srcProcDisplayName' in event else 'None'
                    tgtprocdisplayname = event['tgtProcDisplayName'] if 'tgtProcDisplayName' in event else 'None'
                    tgtfilepath = event['tgtFilePath'] if 'tgtFilePath' in event else 'None'
                    tgtfilesha1 = event['fileSha1'] if 'fileSha1' in event else 'None'
                    tgtfilesha256 = event['fileSha256'] if 'fileSha256' in event else 'None'
                    scrprocparentimagepath = event['srcProcParentImagePath'] if 'srcProcParentImagePath' in event else 'None'
                    tgtprocimagepath = event['tgtProcImagePath'] if 'tgtProcImagePath' in event else 'None'
                    url = event['networkUrl'] if 'networkUrl' in event else 'None'
                    srcip = event['srcIp'] if 'srcIp' in event else 'None'
                    dstip = event['dstIp'] if 'dstIp' in event else 'None'
                    dnsrequest = event['dnsRequest'] if 'dnsRequest' in event else 'None'
                    command_line = event['srcProcCmdLine']
                    additional_data = (event['eventTime'], event['siteId'], event['siteName'], srcprocstorylineid, srcprocdisplayname, scrprocparentimagepath, tgtprocdisplayname, tgtprocimagepath, tgtfilepath, tgtfilesha1, tgtfilesha256, url, srcip, dstip, dnsrequest, event['eventType'])

                result = Result(hostname, username, path, command_line, additional_data)

                self._results[merged_tag].append(result)
        except Exception as e:
            self.log.error(e)
            click.secho(f'Error in query thread: {e}', fg='red')

    def _process_queries(self) -> None:
        """
        Process all cached queries.
        """
        start_date = datetime.utcnow()
        end_date = start_date

        # determine earliest start date
        for tag, queries in self._queries.items():
            for query in queries:
                if query.start_date < start_date:
                    start_date = query.start_date

        cancel_event = Event()

        # queries with certain operators can be combined into a more compact query format
        query_text = self._get_query_text()

        # all queries that need to be executed are now in query_text
        # execute queries in chunks
        # do not chunk if processing an IOC file
        ioc_hunt = list(self._queries.keys())
        chunk_size = 1 if self._pq or (len(ioc_hunt) == 1 and ioc_hunt[0].tag.startswith('IOC - ')) else 10

        with concurrent.futures.ThreadPoolExecutor(max_workers=25 if self._pq else 1) as executor:
            futures = list[Future]()

            # merge queries into one large query and execute it
            for i in range(0, len(query_text), chunk_size):
                # do not chain more than 10 ORs in a S1QL query
                merged_tags = set[Tag]()
                merged_query = ''
                for tag, query_str in query_text[i:i + chunk_size]:
                    # combine queries with ORs
                    if merged_query:
                        merged_query += ' OR '

                    merged_query += query_str

                    # add tags to set to de-duplicate
                    merged_tags.add(tag)

                # merge all query tags into a single string
                merged_tag = Tag(','.join(tag.tag for tag in merged_tags),
                                 ','.join(str(tag.data) for tag in merged_tags))

                if self._query_base is not None and len(self._query_base):
                    # add base_query filter to merged query string
                    merged_query = f'{self._query_base} AND ({merged_query})'

                if self._pq:
                    # PQ seems to not honor site IDs provided in POST request body
                    if len(self._site_ids):
                        # restrict query to specified sites
                        merged_query = f'({merged_query}) AND ('
                        first = True
                        for site_id in self._site_ids:
                            if not first:
                                merged_query += ' OR '
                            else:
                                first = False

                            merged_query += f'site.id = {site_id}'
                        merged_query += ')'

                    merged_query += ' | group count() by endpoint.name, src.process.user, ' \
                                    'src.process.image.path, src.process.cmdline, src.process.name, ' \
                                    'src.process.publisher, url.address, tgt.file.internalName, src.process.startTime, ' \
                                    'site.id, site.name, src.process.storyline.id'

                futures.append(executor.submit(self._run_query, merged_query, start_date, end_date, merged_tag,
                                               cancel_event, not self._pq))

            p_bar = tqdm(desc='Running queries',
                         disable=not self._tqdm_echo,
                         total=len(futures))

            try:
                completed_futures = set[Future]()
                while not cancel_event.is_set() and len(completed_futures) != len(futures):
                    for future in futures:
                        if future not in completed_futures and future.done():
                            completed_futures.add(future)
                            p_bar.update()

                    cancel_event.wait(1)
            except KeyboardInterrupt:
                self._echo("Caught CTRL-C. Returning what we have . . .")
                cancel_event.set()

            p_bar.close()

        self._queries.clear()

    def get_results(self, final_call: bool = True) -> dict[Tag, list[Result]]:
        self.log.debug('Entered get_results')

        # process any unprocessed queries
        if final_call and len(self._queries) > 0:
            self.log.debug(f'Executing additional _process_queries')
            self._process_queries()

        return self._results

    def get_other_row_headers(self) -> list[str]:
        return ['Event Time', 'Site ID', 'Site Name', 'SrcProcStorylineId', 'SrcProcDisplayName', 'SrcProcParentImagePath', 'TgtProcDisplayName', 'TgtProcPath', 'TgtFilePath', 'TgtFileSHA1', 'TgtFileSHA256', 'Network URL', 'Source IP', 'Dest IP', 'DNS Request', 'EventType']