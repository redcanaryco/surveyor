import configparser
import json
import logging
import os

import requests
from typing import Union,Optional
from common import Product, Tag, Result

PARAMETER_MAPPING: dict[str, dict[str, Union[str, list[str]]]] = {
    'process_name': {'table':'DeviceProcessEvents','field':'FolderPath',
                     'projections':['DeviceName','AccountName','FolderPath','ProcessCommandLine']},
    'filemod': {'table':'DeviceFileEvents','field':'FolderPath', 
                'projections':['DeviceName', 'InitiatingProcessAccountName','InitiatingProcessFolderPath','InitiatingProcessCommandLine']},
    'ipaddr': {'table':'DeviceNetworkEvents','field':'RemoteIP', 
               'projections':['DeviceName', 'InitiatingProcessAccountName','InitiatingProcessFolderPath','InitiatingProcessCommandLine']},
    'ipport': {'table':'DeviceNetworkEvents','field':'RemotePort', 
               'projections':['DeviceName', 'InitiatingProcessAccountName','InitiatingProcessFolderPath','InitiatingProcessCommandLine']},
    'cmdline': {'table':'DeviceProcessEvents','field':'ProcessCommandLine', 
                'projections':['DeviceName','AccountName','FolderPath','ProcessCommandLine']},
    'digsig_publisher': {'table':'DeviceFileCertificateInfo','field':'Signer', 
                         'additional':'| join kind=inner DeviceProcessEvents on $left.SHA1 == $right.SHA1',
                         'projections':['DeviceName', 'AccountName','FolderPath','ProcessCommandLine']},
    'domain': {'table':'DeviceNetworkEvents','field':'RemoteUrl', 
               'projections':['DeviceName', 'InitiatingProcessAccountName','InitiatingProcessFolderPath','InitiatingProcessCommandLine']},
    'internal_name': {'table':'DeviceProcessEvents','field':'ProcessVersionInfoInternalFileName', 
                      'projections':['DeviceName','AccountName','FolderPath','ProcessCommandLine']},
    'md5': {'table':'DeviceProcessEvents','field':'MD5',
            'projections':['DeviceName','AccountName','FolderPath','ProcessCommandLine']},
    'sha1':{'table':'DeviceProcessEvents','field':'SHA1',
            'projections':['DeviceName','AccountName','FolderPath','ProcessCommandLine']},
    'sha256':{'table':'DeviceProcessEvents','field':'SHA256',
              'projections':['DeviceName','AccountName','FolderPath','ProcessCommandLine']},
    'modload':{'table': 'DeviceImageLoadEvents', 'field':'FolderPath',
               'projections':['DeviceName', 'InitiatingProcessAccountName', 'InitiatingProcessFolderPath', 'InitiatingProcessCommandLine']},
    'regmod':{'table':'DeviceRegistryEvents','field':'RegistryKey',
              'projections':['DeviceName', 'InitiatingProcessAccountName', 'InitiatingProcessFolderPath', 'InitiatingProcessCommandLine', 'RegistryValueName', 'RegistryValueData']}
}

class DefenderForEndpoints(Product):
    """
    Surveyor implementation for product "Microsoft Defender For Endpoint"
    """
    profile: str = 'default'
    product: str = 'dfe'
    creds_file: str  # path to credential configuration file
    _token: str  # AAD access token
    _limit: int = -1
    _tenantId: Optional[str] = None 
    _appId: Optional[str] = None
    _appSecret: Optional[str] = None
    _raw: bool = False

    def __init__(self, **kwargs):

        self.profile = kwargs['profile'] if 'profile' in kwargs else 'default'
        self.creds_file = kwargs['creds_file'] if 'creds_file' in kwargs else ''
        self._token = kwargs['token'] if 'token' in kwargs else ''
        self._tenantId = kwargs['tenantId'] if 'tenantId' in kwargs else None
        self._appId = kwargs['appId'] if 'appId' in kwargs else None
        self._appSecret = kwargs['appSecret'] if 'appSecret' in kwargs else None
        self._raw = kwargs['raw'] if 'raw' in kwargs else self._raw

        if 100000 >= int(kwargs.get('limit', -1)) > self._limit:
            self._limit = int(kwargs['limit'])

        super().__init__(self.product, **kwargs)

    def _authenticate(self) -> None:
        if not self._token:
            
            if self._tenantId and self._appId and self._appSecret:
                self._token = self._get_aad_token(self._tenantId, self._appId, self._appSecret)
            
            elif not os.path.isfile(self.creds_file):
                raise ValueError(f'Credential file {self.creds_file} does not exist')
            
            elif os.path.isfile(self.creds_file):

                config = configparser.ConfigParser()
                config.sections()
                config.read(self.creds_file)

                if self.profile not in config:
                    raise ValueError(f'Profile {self.profile} is not present in credential file')

                section = config[self.profile]

                if 'token' in section:
                    self._token = section['token']
                elif 'tenantId' not in section or 'appId' not in section or 'appSecret' not in section:
                    raise ValueError(f'Credential file must contain a token or the fields tenantId, appId, and appSecret values')
                else:
                    self._token = self._get_aad_token(section['tenantId'], section['appId'], section['appSecret'])

    def _get_aad_token(self, tenant_id: str, app_id: str, app_secret: str) -> str:
        """
        Retrieve an authentication token from Azure Active Directory using app ID and secret.
        """
        self.log.debug(f'Acquiring AAD access token for tenant {tenant_id} and app {app_id}')

        body = {
            "resource": 'https://api.securitycenter.windows.com',
            "client_id": app_id,
            "client_secret": app_secret,
            "grant_type": "client_credentials"
        }

        url = f"https://login.windows.net/{tenant_id}/oauth2/token"

        response = requests.get(url, data=body)
        response.raise_for_status()

        return response.json()['access_token']

    def _post_advanced_query(self, data: dict, headers: dict) -> list[Result]:
        #raw_results = list()
        results = set()

        try:
            url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
            response = requests.post(url, data=json.dumps(data).encode('utf-8'), headers=headers)

            if response.status_code == 200:
                for res in response.json()["Results"]:
                    
                    # Raw Feature (Inactive)
                    '''
                    if self._raw:
                        raw_results.append(res)
                    '''
                    hostname = res['DeviceName'] if 'DeviceName' in res else 'Unknown'
                    if 'AccountName' in res or 'InitiatingProcessAccountName' in res:
                        username = res['AccountName'] if 'AccountName' in res else res['InitiatingProcessAccountName']
                        username = 'Unknown'
                    
                    if 'ProcessCommandLine' in res or 'InitiatingProcessCommandLine' in res:
                        cmdline = res['ProcessCommandLine'] if 'ProcessCommandLine' in res else res['InitiatingProcessCommandLine']
                    else:
                        cmdline = 'Unknown'
                    
                    if 'FolderPath' in res or 'InitiatingProcessFolderPath' in res:
                        proc_name = res['FolderPath'] if 'FolderPath' in res else res['InitiatingProcessFolderPath']
                    else:
                        proc_name = 'Unknown'

                    timestamp = res['Timestamp'] if 'Timestamp' in res else 'Unknown'

                    result = Result(hostname, username, proc_name, cmdline,
                                    (timestamp,))
                    results.add(result)
            else:
                self._echo(f"Received status code: {response.status_code} (message: {response.json()})")
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Rerun surveyor")
        except Exception as e:
            self._echo(f"There was an exception {e}")
            self.log.exception(e)
        
        # Raw Feature (Inactive)
        '''
        if self._raw:
            return raw_results
        '''
        return list(results)

    def _get_default_header(self) -> dict[str, str]:
        return {
            "Authorization": 'Bearer ' + self._token,
            "Content-Type": 'application/json',
            "Accept": 'application/json'
        }

    def process_search(self, tag: Tag, base_query: dict, query: str) -> None:
        query = query.rstrip()
        
        query += f" {self.build_query(base_query)}" if base_query != {} else ''

        if self._limit > 0 and 'limit' not in query:
            query += f" | limit {str(self._limit)}"

        self.log.debug(f'Query: {query}')
        full_query = {'Query': query}

        results = self._post_advanced_query(data=full_query, headers=self._get_default_header())

        self._add_results(list(results), tag)

    def nested_process_search(self, tag: Tag, criteria: dict, base_query: dict) -> None:
        query_base = self.build_query(base_query)

        try:
            for search_field, terms in criteria.items():
                if search_field == 'query':
                    if isinstance(terms, list):
                        for query_entry in terms:
                            query_entry += f" {query_base}" if query_base != '' else ''
                            self.process_search(tag, {}, query_entry)
                    else:
                        query_entry = terms
                        query_entry += f" {query_base}" if query_base != '' else ''

                        self.process_search(tag, {}, query_entry)
                else:
                    all_terms = ', '.join(f"'{term}'" for term in terms)
                    if search_field in PARAMETER_MAPPING:
                        query = f"| where {PARAMETER_MAPPING[search_field]['field']} has_any ({all_terms})"
                    else:
                        self._echo(f'Query filter {search_field} is not supported by product {self.product}',
                                   logging.WARNING)
                        continue
                
                    query = f"{PARAMETER_MAPPING[search_field]['table']} {query} "

                    query += f"{(PARAMETER_MAPPING[search_field]['additional'])} " if 'additional' in PARAMETER_MAPPING[search_field] else ''

                    query += f" {query_base} " if query_base != '' else ''

                    query += f"| project Timestamp, {', '.join(PARAMETER_MAPPING[search_field]['projections'])}"

                    self.process_search(tag, {}, query)
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Returning what we have...")

    def build_query(self, filters: dict) -> str:
        query_base = []

        for key, value in filters.items():
            if key == 'days':
                query_base.append(f'| where Timestamp > ago({value}d)')
            elif key == 'minutes':
                query_base.append(f'| where Timestamp > ago({value}m)')
            elif key == 'hostname':
                query_base.append(f'| where DeviceName contains "{value}"')
            elif key == 'username':
                query_base.append(f'| where AccountName contains "{value}"')
            else:
                self._echo(f'Query filter {key} is not supported by product {self.product}', logging.WARNING)

        return ' '.join(query_base)

    def get_other_row_headers(self) -> list[str]:
        return ['Timestamp']