import configparser
import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
import secrets
import hashlib
import string
from typing import Optional, Tuple

import requests
from requests.adapters import HTTPAdapter

from common import Product, Tag, Result


@dataclass
class Query:
    relative_time_ms: int
    parameter: Optional[str]
    operator: Optional[str]
    search_value: Optional[str]
    full_query: Optional[str] = None


PARAMETER_MAPPING: dict[str, str] = {
    'process_name': 'action_process_image_name',
    'ipaddr': 'action_remote_ip',
    'cmdline': 'action_process_command_line',
    'digsig_publisher': 'action_file_signature_vendor',
    'modload': 'action_module_path',
    'filemod': 'action_file_path',
    'regmod': 'action_registry_key_name',
    'md5': 'action_process_image_md5',
    'sha256': 'action_process_image_sha256',
    'ipport': 'action_remote_port',
    'filewrite_md5': 'action_file_md5',
    'filewrite_sha256': 'action_file_sha256'
}


class CortexXDR(Product):
    """
    Surveyor implementation for product "CortexXDR"
    """
    product: str = 'cortex'
    creds_file: str  # path to credential configuration file
    _api_key: str  # Required API key
    _api_key_id: str  # Required API key ID
    _url: str  # URL of CortexXDR console
    _auth_type: Optional[str] = 'standard'  # Either standard or advanced, default is standard
    _tenant_ids: list[str] = []  # tenant ID list
    _session: requests.Session
    _queries: dict[Tag, list[Query]]
    _last_request: float

    def __init__(self, profile: str, creds_file: str, **kwargs):
        if not os.path.isfile(creds_file):
            raise ValueError(f'Credential file {creds_file} does not exist')

        self.creds_file = creds_file
        self._queries = dict()

        self._last_request = 0.0

        super().__init__(self.product, profile, **kwargs)

    def _authenticate(self) -> None:
        config = configparser.ConfigParser()
        config.read(self.creds_file)

        if self.profile not in config:
            raise ValueError(f'Profile {self.profile} is not present in credential file')

        section = config[self.profile]

        # ensure configuration has required fields
        if 'url' not in section:
            raise ValueError(f'Cortex XDR configuration invalid, ensure "url" is specified')

        # extract required information from configuration
        if 'api_key' in section:
            self._api_key = section['api_key']
        else:
            raise ValueError(f'Cortex XDR configuration invalid, ensure "api_key" is specified')

        if 'api_key_id' in section:
            self._api_key_id = section['api_key_id']
        else:
            raise ValueError(f'Cortex XDR configuration invalid, ensure "api_key_id" is specified')

        if 'auth_type' in section:
            if section['auth_type'].lower() in ['standard', 'advanced']:
                self._auth_type = section['auth_type'].lower()
            else:
                raise ValueError(
                    f'Cortex XDR configuration invalid, ensure "auth_type" is one of ["standard","advanced"]')

        if 'tenant_id' in section:
            self._tenant_ids = section['tenant_id'].split(',')

        self._url = section['url'].rstrip('/')

        if not self._url.startswith('https://'):
            raise ValueError(f'URL must start with "https://"')

        # create a session and a pooled HTTPAdapter
        self._session = requests.session()
        self._session.mount('https://', HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=3))

        # Run a check to make sure creds actually work
        auth_check = self._session.post(self._build_url('/public_api/v1/xql/get_quota'),
                                        headers=self._get_default_header(), params={})
        resp = auth_check.json()
        if 'reply' not in resp:
            raise ValueError(
                f'Cortex could not validate credentials. Please check your configuration file and try again.')
        else:
            self.log.debug(f"Query quota: {resp}")

    def _build_url(self, stem: str) -> str:
        """
        Assemble URL for Cortex XDR API query using base URI and URI stem.
        """
        if not stem.startswith('/'):
            stem = '/' + stem

        return self._url + stem

    def _get_default_body(self) -> dict:
        """
        Get the default request body for a Cortex XDR API query.
        """
        body: dict = {}
        return body

    def _get_default_header(self) -> dict:
        """
        Get the default header for a Cortex XDR API query.
        """
        if self._auth_type == 'advanced':
            # Generate a 64 bytes random string
            nonce = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
            # Get the current timestamp as milliseconds.
            timestamp = int(datetime.now(timezone.utc).timestamp()) * 1000
            # Generate the auth key and convert to bytes object:
            auth_key = ("%s%s%s" % (self._api_key, nonce, timestamp)).encode("utf-8")
            # Calculate sha256:
            api_key_hash = hashlib.sha256(auth_key).hexdigest()
            # Generate HTTP call headers
            return {"x-xdr-timestamp": str(timestamp), "x-xdr-nonce": nonce, "x-xdr-auth-id": str(self._api_key_id),
                    "Authorization": api_key_hash}
        else:
            return {"Authorization": f"{self._api_key}", "x-xdr-auth-id": f"{self._api_key_id}",
                    "Content-Type": "application/json"}

    def build_query(self, filters: dict) -> Tuple[str, int]:
        # default to the last 14 days
        relative_time_ms: int = 14 * 24 * 60 * 60 * 1000

        query_base = ''

        for key, value in filters.items():
            if key == 'days':
                relative_time_ms = value * 24 * 60 * 60 * 1000
            elif key == 'minutes':
                relative_time_ms = value * 60 * 1000
            elif key == 'hostname':
                query_base += f' | filter lowercase(agent_hostname) contains "{value.lower()}"'
            elif key == 'username':
                # Need to look at both actor and action in case action is actually a filemod,netconn,regmod rather than proc
                query_base += f' | filter lowercase(action_process_username) contains "{value.lower()}" or lowercase(actor_primary_username) contains "{value.lower()}"'
            else:
                self._echo(f'Query filter {key} is not supported by product {self.product}', logging.WARNING)

        # Cortex XDR requires the date range to be supplied in the query request, not the query text
        # therefore we return the relative time separately
        return query_base, relative_time_ms

    def process_search(self, tag: Tag, base_query: dict, query: str) -> None:
        self._base_query, relative_time_ms = self.build_query(base_query)

        if tag not in self._queries:
            self._queries[tag] = list()

        full_query = Query(relative_time_ms, None, None, None, f'dataset=xdr_data {query}')
        self._queries[tag].append(full_query)

    def nested_process_search(self, tag: Tag, criteria: dict, base_query: dict) -> None:
        self._base_query, relative_time_ms = self.build_query(base_query)

        try:
            for search_field, terms in criteria.items():
                if search_field == 'query':
                    operator = 'raw'
                    parameter = 'query'
                    if isinstance(terms, list):
                        if len(terms) > 1:
                            search_value = ' '.join(terms)
                        else:
                            search_value = terms[0]
                    else:
                        search_value = terms
                else:
                    all_terms = ', '.join((f'"*{term}*"').replace("**", "*") for term in terms)

                    if search_field not in PARAMETER_MAPPING:
                        self._echo(f'Query filter {search_field} is not supported by product {self.product}',
                                   logging.WARNING)
                        continue

                    parameter = PARAMETER_MAPPING[search_field]
                    search_value = all_terms

                    if len(terms) > 1:
                        search_value = f'({all_terms})'
                        operator = 'in'
                    else:
                        operator = 'contains'

                if tag not in self._queries:
                    self._queries[tag] = list()

                self._queries[tag].append(Query(relative_time_ms, parameter, operator, search_value))
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Returning what we have...")

    def _get_xql_results(self, query_id: str, limit: int = 1000) -> Tuple[dict, int]:
        actual_limit = limit if limit < 1000 else 1000  # Max is 1000 results otherwise have to get the results via stream
        params = {
            'request_data': {
                'query_id': query_id,
                'pending_flag': True,
                'limit': actual_limit,
                'format': 'json'
            }
        }
        try:
            while True:
                query_status_response = self._session.post(self._build_url('/public_api/v1/xql/get_query_results'),
                                                           headers=self._get_default_header(), json=params)
                query_status_response.raise_for_status()
                data = query_status_response.json()['reply']

                if data['status'] == 'SUCCESS':
                    self.log.debug(
                        f'Query ID {query_id} completed at cost {data["query_cost"]} with remaining quota {data["remaining_quota"]}')

                    return data['results']['data'], data['number_of_results']
                else:
                    # Add a sleep function to avoid 429 errors
                    time.sleep(1)
        except Exception as e:
            raise e

    def _process_queries(self) -> None:
        for tag, queries in self._queries.items():
            for query in queries:
                if query.full_query is not None:
                    query_string = query.full_query
                else:
                    query_string = 'dataset=xdr_data'

                    if query.operator in ('contains', 'in'):
                        # Fix the query to be case-insensitive if using `contains`
                        query_string += f' | filter lowercase({query.parameter}) {query.operator} {str(query.search_value).lower()}'
                    elif query.operator == 'raw':
                        query_string += f' {query.search_value}'
                    else:
                        query_string += f' | filter {query.parameter} {query.operator} {query.search_value}'

                query_string += f' {self._base_query} | fields agent_hostname, action_process_image_path, action_process_username, action_process_image_command_line, actor_process_image_path, actor_primary_username, actor_process_command_line, event_id'

                # Run that query!
                params = self._get_default_body()
                params.update({
                    "request_data": {
                        "query": query_string,
                        "tenants": self._tenant_ids,
                        "timeframe": {"relativeTime": query.relative_time_ms}
                    }
                })

                self.log.debug(f'Query params: {params}')

                query_response = self._session.post(self._build_url('/public_api/v1/xql/start_xql_query/'),
                                                    headers=self._get_default_header(), data=json.dumps(params))

                body = query_response.json()
                if 'reply' not in body:
                    raise ValueError(f'Cortex encountered an error and could not process query "{query_string}"')

                self.log.debug(query_response.json())
                query_response.raise_for_status()

                query_id = body['reply']
                self.log.info(f'Query ID is {query_id}')

                events, count = self._get_xql_results(query_id)
                self.log.debug(f'Got {count} events')
                self._results[tag] = list()
                for event in events:
                    hostname = event['agent_hostname'] if 'agent_hostname' in event else ''

                    # If the event is not a process execution, we need to see what process initiated the filemod, regmod, netconn, etc.
                    username = event['action_process_username'] if 'action_process_username' in event else \
                        event['actor_primary_username']
                    path = event['action_process_image_path'] if 'action_process_image_path' in event else \
                        event['actor_process_image_path']
                    commandline = event['action_process_command_line'] if 'action_process_command_line' in event else \
                        event['actor_process_command_line']
                    additional_data = (event['_time'], event['event_id'])

                    result = Result(hostname, username, path, commandline, additional_data)
                    self._results[tag].append(result)
        self._queries.clear()

    def get_results(self, final_call: bool = True) -> dict[Tag, list[Result]]:
        self.log.debug('Entered get_results')

        # process any unprocessed queries
        if final_call and len(self._queries) > 0:
            self.log.debug(f'Executing additional _process_queries')
            self._process_queries()

        return self._results

    def get_other_row_headers(self) -> list[str]:
        return ['Event Time', 'Event ID']
