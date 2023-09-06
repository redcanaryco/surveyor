import os
import sys
import pytest
sys.path.append(os.getcwd())
from unittest.mock import patch
from help import check_credentials_structure,check_product_args_structure, build_survey

class DictToClass:
    def __init__(self, dictionary):
        for key, value in dictionary.items():
            setattr(self, key, value)

@pytest.mark.parametrize("edr, product_args",
                         [
                            ("cbc", {
                                'device_group': "test",
                                'device_policy': "test"}),
                            ("cbc", {'device_group': "test"}),
                            ("cbc", {'device_policy': "test"}),
                            ("cbc", {}),
                            ("cortex", {}),
                            ("cbr", {'sensor_group': "test"}),
                            ("cbr", {}),
                            ("dfe", {}),
                            ("s1", {}),
                            ("s1", {"deep_visibility": True})
                         ]
)
def test_check_valid_product_args_structure(edr, product_args) -> dict:

    results = check_product_args_structure(edr, product_args)
    
    assert results == True

@pytest.mark.parametrize("edr, product_args",
                         [
                            ("cbc", {"deep_visibility": True}),
                            ("cortex", {"deep_visibility": True}),
                            ("cortex", {
                                'device_group': "test",
                                'device_policy': "test"}),
                            ("cbr", {"deep_visibility": True}),
                            ("dfe", {"deep_visibility": True}),
                            ("dfe", {
                                'device_group': "test",
                                'device_policy': "test"}),
                            ("s1", {
                                'device_group': "test",
                                'device_policy': "test"})
                         ]
)
def test_check_invalid_product_args_structure(edr, product_args) -> dict:

    with pytest.raises((ValueError, TypeError)):
        results = check_product_args_structure(edr, product_args)
    
@pytest.mark.parametrize("edr, creds",
                        [
                            ("cbc", {'profile': "default"}),
                            ("cbc", {'profile': "default", 'creds_file': 'credentials.psc'}),
                            ("cbc", {'url': "test.cbc.com",
                                     'token': "supersecret",
                                     'org_key': "something"}
                                     ),
                            ("cortex", {'profile': "personal_profile", 'creds_file': "cortex.ini"}),
                            ("cortex", {'url': "test.cortex.com",
                                     'api_key': "supersecret",
                                     'api_key_id': "1",
                                     "auth_type": "standard"}),
                            ("cbr", {'profile': "default"}),
                            ("cbc", {'profile': "default", 'creds_file': 'credentials.response'}),
                            ("cbr", {'url': "test.cbr.com",
                                     'token': "supersecret"}),
                            ("dfe", {'profile': "personal_profile", 'creds_file': "microsoft.ini"}),
                            ("dfe", {'token': "supersecret",
                                     'tenantId': "supersecret",
                                     'appId': "supersecret",
                                     'appSecret': "supersecret"}),
                            ("dfe", {'token': "supersecret"}),
                            ("dfe", {'tenantId': "supersecret"}),
                            ("dfe", {'appId': "supersecret"}),
                            ("dfe", {'appSecret': "supersecret"}),
                            ("s1", {'profile': "personal_profile", 'creds_file': "s1.ini"}),
                            ("s1", {'account_ids': ["22"],
                                    'bypass': True,
                                    'site_ids': ["123"],
                                    'account_names': ["you"]}),
                            ("s1", {'bypass': True}),
                            ("s1", {'site_ids': ["123"]}),
                            ("s1", {'account_names': ["you"]}),
                            ("s1", {'account_ids': ["22"]})
                        ]
)
def test_check_valid_credentials_structure(edr, creds) -> dict:

    results = check_credentials_structure(edr, creds)

    assert results == True

@pytest.mark.parametrize("edr, creds",
                        [
                            ("cbc", {}),
                            ("cbc", {'creds_file': 'credentials.psc'}),
                            ("cbc", {
                                'token': "supersecret",
                                'org_key': "something"}),
                            ("cortex", {}),
                            ("cortex", {'creds_file': "cortex.ini"}),
                            ("cortex", {
                                'api_key': "supersecret",
                                'api_key_id': "1",
                                'auth_type': "standard"}),
                            ("cbr", {}),
                            ("cbc", {'creds_file': 'credentials.response'}),
                            ("cbr", {'url': "test.cbr.com"}),
                            ("dfe", {'creds_file': "microsoft.ini"}),
                            ("dfe", {}),
                            ("dfe", {'tokhfghhgen': "supersecret"}),
                            ("dfe", {
                                'tenandfgjgjfgdtId': "supersecret"}),
                            ("dfe", {'appItjdjgjd': "supersecret"}),
                            ("dfe", {'appdfjggfjfgSecret': "supersecret"}),
                            ("s1", {'creds_file': "s1.ini"}),
                            ("s1", {
                                'account_ids': [],
                                'site_ids': [],
                                'account_names': []}),
                            ("s1", {}),
                            ("s1", {'singfjgte_ids': ["123"]}),
                            ("s1", {'accogfdjgfjgfdfjgunt_names': ["you"]}),
                            ("s1", {'jgdfjggdjgfggj': ["22"]})
                        ]
)
def test_check_invalid_credentials_structure(edr, creds) -> dict:

    with pytest.raises(ValueError):
        results = check_credentials_structure(edr, creds)

@pytest.mark.parametrize(
    "input_arguments, output_surveyor_arguments",
    [
        (
            {
                'prefix': None,
                'days': None,
                'minutes': None,
                'limit': None,
                'hostname': None,
                'username': None,
                'query': 'ProcessCmd RegExp “schtasks” AND processName != “Manages scheduled tasks”',
                'deffile': None,
                'defdir': None,
                'sigmarule': None,
                'sigmadir': None,
                'iocfile': None,
                'iocdir': None,
                'ioctype': None,
                'output': None,
                'output_format': 'csv',
                'no_file': False,
                'no_progress': False,
                'log_dir': 'logs',
                'edr': 's1',
                'site_ids': [],
                'account_ids': [],
                'account_names': [],
                'dv': False,
                'creds': 's1.ini',
                'profile': 'test',
                'bypass': False
            },
            {
                'query': 'ProcessCmd RegExp “schtasks” AND processName != “Manages scheduled tasks”',
                'no_file': False,
                'no_progress': False,
                'log_dir': 'logs',
                'output_format': 'csv',
                'edr': 's1',
                'product_args': {'deep_visibility': False},
                'creds': {
                    'profile': 'test',
                    'site_ids': [],
                    'account_ids': [],
                    'account_names': [],
                    'creds_file': 's1.ini',
                    'bypass': False
                }
            }
        ),
        (
            {
                'prefix': None,
                'days': None,
                'minutes': None,
                'limit': None,
                'hostname': None,
                'username': None,
                'query': 'python.exe',
                'deffile': None,
                'defdir': None,
                'sigmarule': None,
                'sigmadir': None,
                'iocfile': None,
                'iocdir': None,
                'ioctype': None,
                'output': None,
                'output_format': 'csv',
                'no_file': False,
                'no_progress': False,
                'log_dir': 'logs',
                'edr': 'cbc',
                'device_group': None,
                'device_policy': None,
                'creds': None,
                'profile': 'default'
            },
            {
                'query': 'python.exe',
                'no_file': False,
                'no_progress': False,
                'log_dir': 'logs',
                'output_format': 'csv',
                'edr': 'cbc',
                'product_args': {},
                'creds': {
                    'profile': 'default'
                }
            }
        ),
        (
            {
                'prefix': None,
                'days': None,
                'minutes': None,
                'limit': None,
                'hostname': None,
                'username': None,
                'query': 'python.exe',
                'deffile': None,
                'defdir': None,
                'sigmarule': None,
                'sigmadir': None,
                'iocfile': None,
                'iocdir': None,
                'ioctype': None,
                'output': None,
                'output_format': 'csv',
                'no_file': False,
                'no_progress': False,
                'log_dir': 'logs',
                'edr': 'cbr',
                'sensor_group': None,
                'creds': None,
                'profile': 'default'
            },
            {
                'query': 'python.exe',
                'no_file': False,
                'no_progress': False,
                'log_dir': 'logs',
                'output_format': 'csv',
                'edr': 'cbr',
                'product_args': {},
                'creds': {
                    'profile': 'default'
                }
            }
        ),
        (
            {
                'prefix': None,
                'days': None,
                'minutes': None,
                'limit': None,
                'hostname': None,
                'username': None,
                'query': 'DeviceEvents',
                'deffile': None,
                'defdir': None,
                'sigmarule': None,
                'sigmadir': None,
                'iocfile': None,
                'iocdir': None,
                'ioctype': None,
                'output': None,
                'output_format': 'csv',
                'no_file': False,
                'no_progress': False,
                'log_dir': 'logs',
                'edr': 'dfe',
                'creds': 'microsoft.ini',
                'profile': 'test'
            },
            {
                'query': 'DeviceEvents',
                'no_file': False,
                'no_progress': False,
                'log_dir': 'logs',
                'output_format': 'csv',
                'edr': 'dfe',
                'product_args': {},
                'creds': {
                    'profile': 'test',
                    'creds_file': 'microsoft.ini'
                }
            }
        ),
        (
            {
                'prefix': None,
                'days': None,
                'minutes': None,
                'limit': None,
                'hostname': None,
                'username': None,
                'query': 'dataset = xdr_data | fields os_actor_process_file_size as osapfs | filter to_string(osapfs) = "12345"',
                'deffile': None,
                'defdir': None,
                'sigmarule': None,
                'sigmadir': None,
                'iocfile': None,
                'iocdir': None,
                'ioctype': None,
                'output': None,
                'output_format': 'csv',
                'no_file': False,
                'no_progress': False,
                'log_dir': 'logs',
                'edr': 'cortex',
                'auth_type': 'standard',
                'tenant_ids': [],
                'creds': 'cortex.ini',
                'profile': 'test'
            },
            {
                'query': 'dataset = xdr_data | fields os_actor_process_file_size as osapfs | filter to_string(osapfs) = "12345"',
                'no_file': False,
                'no_progress': False,
                'log_dir': 'logs',
                'output_format': 'csv',
                'edr': 'cortex',
                'product_args': {},
                'creds': {
                    'profile': 'test',
                    'auth_type': 'standard',
                    'tenant_ids': [],
                    'creds_file': 'cortex.ini'
                }
            }
        ),
    ]
)
def test_check_valid_build_surveys(input_arguments, output_surveyor_arguments) -> dict:
    results = build_survey(DictToClass(input_arguments))
    assert results == output_surveyor_arguments
