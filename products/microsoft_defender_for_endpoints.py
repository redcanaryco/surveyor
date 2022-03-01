import configparser
import os

import click
import requests

from common import Product


class DefenderForEndpoints(Product):
    """
    Surveyor implementation for product "Microsoft Defender For Endpoint"
    """
    product: str = 'defender'
    creds_file: str  # path to credential configuration file
    _token: str  # AAD access token

    def __init__(self, profile: str, creds_file: str):
        if not os.path.isfile(creds_file):
            raise ValueError(f'Credential file {creds_file} does not exist')

        self.creds_file = creds_file

        super().__init__(self.product, profile)

    def _authenticate(self):
        config = configparser.ConfigParser()
        config.sections()
        config.read(self.creds_file)

        if self.profile not in config:
            raise ValueError(f'Profile {self.profile} is not present in credential file')

        section = config[self.profile]
        self._token = self._get_aad_token(section['tenantId'], section['appId'], section['appSecret'])

    def _get_aad_token(self, tenant_id: str, app_id: str, app_secret: str):
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

    def _post_advanced_query(self, data: dict, headers: dict):
        results = set()

        try:
            url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
            response = requests.post(url, data=data, headers=headers)

            if response.status_code == 200:
                for res in response.json()["Results"]:
                    results.add((res["DeviceName"], res["AccountName"], res["ProcessCommandLine"], res["FolderPath"]))
            else:
                click.echo(f"We received the following status code {response.status_code}")
        except KeyboardInterrupt as e:
            click.echo("Caught CTRL-C. Rerun surveyor")
            self.log.exception(e)
        except Exception as e:
            click.echo(f"There was an exception {e}")
            self.log.exception(e)

        return results

    def _get_default_header(self):
        return {
            "Authorization": 'Bearer ' + self._token,
            "Content-Type": 'application/json',
            "Accept": 'application/json'
        }

    def process_search(self, base_query, query):
        query = "DeviceEvents" + base_query + query + "| project DeviceName, AccountName, ProcessCommandLine, " \
                                                      "FolderPath "
        query = {'Query': query}

        return self._post_advanced_query(data=query, headers=self._get_default_header())

    def nested_process_search(self, criteria, base_query):
        results = set()

        query_base = self.build_query(base_query)

        try:
            for search_field, terms in criteria.items():
                all_terms = ', '.join(f"'{term}'" for term in terms)
                if search_field == 'process_name':
                    query = f"| where FileName has_any ({all_terms})"
                elif search_field == "filemod":
                    query = f"| where FileName has_any ({all_terms})"
                elif search_field == "ipaddr":
                    query = f"| where RemoteIP has_any ({all_terms})"
                elif search_field == "cmdline":
                    query = f"| where ProcessCommandLine has_any ({all_terms})"
                elif search_field == "digsig_publisher":
                    query = f"| where Signer has_any ({all_terms})"
                elif search_field == "domain":
                    query = f"| where RemoteUrl has_any ({all_terms})"
                elif search_field == "internal_name":
                    query = f"| where ProcessVersionInfoInternalFileName has_any ({all_terms})"
                else:
                    continue

                query = "union DeviceEvents, DeviceFileCertificateInfo, DeviceProcessEvents" + query_base + query \
                        + "| project DeviceName, AccountName, ProcessCommandLine, FolderPath "
                data = {'Query': query}

                for entry in self._post_advanced_query(data=data, headers=self._get_default_header()):
                    results.add(entry)
        except KeyboardInterrupt:
            click.echo("Caught CTRL-C. Returning what we have...")

        return results

    def build_query(self, filters: dict) -> str:
        query_base = ''

        for key, value in filters.items():
            if key == 'days':
                query_base += f'| where Timestamp > ago({value}d)'

            if key == 'minutes':
                query_base += f'| where Timestamp > ago({value}m)'

            if key == 'hostname':
                query_base += f'| where DeviceName contains "{value}"'

            if key == 'username':
                query_base += f'| where AccountName contains "{value}"'

        return query_base
