import configparser
import json
import logging
import os

import requests

from common import Product, Tag, Result

PARAMETER_MAPPING: dict[str, str] = {
    'process_name': 'FileName',
    'filemod': 'FileName',
    'ipaddr': 'RemoteIP',
    'cmdline': 'ProcessCommandLine',
    'digsig_publisher': 'Signer',
    'domain': 'RemoteUrl',
    'internal_name': 'ProcessVersionInfoInternalFileName',
    'md5':'MD5',
    'sha1':'SHA1',
    'sha256':'SHA256'
}

class DefenderForEndpoints(Product):
    """
    Surveyor implementation for product "Microsoft Defender For Endpoint"
    """
    product: str = 'dfe'
    creds_file: str  # path to credential configuration file
    _token: str  # AAD access token

    def __init__(self, profile: str, creds_file: str, **kwargs):
        if not os.path.isfile(creds_file):
            raise ValueError(f'Credential file {creds_file} does not exist')

        self.creds_file = creds_file

        super().__init__(self.product, profile, **kwargs)

    def _authenticate(self) -> None:
        config = configparser.ConfigParser()
        config.sections()
        config.read(self.creds_file)

        if self.profile not in config:
            raise ValueError(f'Profile {self.profile} is not present in credential file')

        section = config[self.profile]

        if 'tenantId' not in section or 'appId' not in section or 'appSecret' not in section:
            raise ValueError(f'Credential file must contain tenantId, appId, and appSecret values')

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
        results = set()

        try:
            url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
            response = requests.post(url, data=json.dumps(data).encode('utf-8'), headers=headers)

            if response.status_code == 200:
                for res in response.json()["Results"]:
                    result = Result(res["DeviceName"], res["AccountName"], res["ProcessCommandLine"], res["FolderPath"],
                                    (res["Timestamp"],))
                    results.add(result)
            else:
                self._echo(f"Received status code: {response.status_code} (message: {response.json()})")
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Rerun surveyor")
        except Exception as e:
            self._echo(f"There was an exception {e}")
            self.log.exception(e)

        return list(results)

    def _get_default_header(self) -> dict[str, str]:
        return {
            "Authorization": 'Bearer ' + self._token,
            "Content-Type": 'application/json',
            "Accept": 'application/json'
        }

    def process_search(self, tag: Tag, base_query: dict, query: str) -> None:
        query = query + self.build_query(base_query)

        query = "union DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceNetworkEvents, DeviceImageLoadEvents, DeviceFileCertificateInfo, DeviceEvents " \
                + query + " | project DeviceName, AccountName, ProcessCommandLine, FolderPath, Timestamp "
        query = query.rstrip()

        self.log.debug(f'Query: {query}')
        full_query = {'Query': query}

        results = self._post_advanced_query(data=full_query, headers=self._get_default_header())
        self._add_results(list(results), tag)

    def nested_process_search(self, tag: Tag, criteria: dict, base_query: dict) -> None:
        results = set()

        query_base = self.build_query(base_query)

        try:
            for search_field, terms in criteria.items():
                if search_field == 'query':
                    if isinstance(terms, list):
                        if len(terms) > 1:
                            query = ' '.join(terms)
                        else:
                            query = terms[0]
                    else:
                        query = terms
                else:
                    all_terms = ', '.join(f"'{term}'" for term in terms)
                    if search_field in PARAMETER_MAPPING:
                        query = f" | where {PARAMETER_MAPPING[search_field]} has_any ({all_terms})"
                    else:
                        self._echo(f'Query filter {search_field} is not supported by product {self.product}',
                                   logging.WARNING)
                        continue

                query = "union DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceNetworkEvents, DeviceImageLoadEvents, DeviceFileCertificateInfo, DeviceEvents" \
                        + query_base + query + " | project DeviceName, AccountName, ProcessCommandLine, FolderPath, Timestamp "
                query = query.rstrip()

                self.log.debug(f'Query: {query}')
                data = {'Query': query}

                for entry in self._post_advanced_query(data=data, headers=self._get_default_header()):
                    results.add(entry)
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Returning what we have...")

        self._add_results(list(results), tag)

    def build_query(self, filters: dict) -> str:
        query_base = ''

        for key, value in filters.items():
            if key == 'days':
                query_base += f'| where Timestamp > ago({value}d)'
            elif key == 'minutes':
                query_base += f'| where Timestamp > ago({value}m)'
            elif key == 'hostname':
                query_base += f'| where DeviceName contains "{value}"'
            elif key == 'username':
                query_base += f'| where AccountName contains "{value}"'
            else:
                self._echo(f'Query filter {key} is not supported by product {self.product}', logging.WARNING)

        return query_base

    def get_other_row_headers(self) -> list[str]:
        return ['Timestamp']