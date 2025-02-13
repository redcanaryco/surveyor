import pytest
import sys
import os
import logging
import json
from unittest.mock import patch
sys.path.append(os.getcwd())
from products.microsoft_defender_for_endpoints import DefenderForEndpoints
from common import Tag

def test_init_lower_limit_option(tmpdir, mocker):
    mocker.patch.object(DefenderForEndpoints, '_authenticate')
    cred_file_path = tmpdir.mkdir('test_dir').join('test_creds.ini')
    cred_file_path.write("asdfasdfasdf")
    dfe_product = DefenderForEndpoints(profile='default',creds_file=cred_file_path, limit=-2)
    assert dfe_product._limit == -1


def test_init_upper_limit_option(tmpdir, mocker):
    mocker.patch.object(DefenderForEndpoints, '_authenticate')
    cred_file_path = tmpdir.mkdir('test_dir').join('test_creds.ini')
    cred_file_path.write("asdfasdfasdf")
    dfe_product = DefenderForEndpoints(profile='default',creds_file=cred_file_path, limit=100001)
    assert dfe_product._limit == -1


def test_init_limit_option(tmpdir, mocker):
    mocker.patch.object(DefenderForEndpoints, '_authenticate')
    cred_file_path = tmpdir.mkdir('test_dir').join('test_creds.ini')
    cred_file_path.write("asdfasdfasdf")
    dfe_product = DefenderForEndpoints(profile='default',creds_file=cred_file_path, limit=10)
    assert dfe_product._limit == 10


@pytest.fixture
def dfe_product():
    with patch.object(DefenderForEndpoints, "__init__", lambda x, y: None):
        return DefenderForEndpoints(None)

def test_build_query_with_supported_fields(dfe_product : DefenderForEndpoints):
    """
    Verify build_query() can handle all filter options
    """
    filters = {
        'days':7,
        'minutes':10,
        'hostname':'workstation1',
        'username':'admin'
    }

    assert dfe_product.build_query(filters) == '| where Timestamp > ago(7d) | where Timestamp > ago(10m) ' + \
                      '| where DeviceName contains "workstation1" | where AccountName contains "admin"'
    
def test_build_query_with_unsupported_field(dfe_product: DefenderForEndpoints, mocker):
    """
    Verify build_query() gracefully handles unsupported filter options
    """
    filters = {
        'foo': 'bar'
    }

    mocked_logger = mocker.patch.object(dfe_product, '_echo')

    assert dfe_product.build_query(filters) == ''

    mocked_logger.assert_has_calls([
        mocker.call('Query filter foo is not supported by product dfe', logging.WARNING)
    ])

def test_process_search_limit_option(dfe_product: DefenderForEndpoints, mocker):
    query = 'DeviceFileEvents | where FileName = "foo bar"'
    full_query = 'DeviceFileEvents | where FileName = "foo bar" | limit 5'
    dfe_product._limit = 5

    mocked_post_advanced_query = mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._post_advanced_query')
    mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._add_results')
    mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._get_default_header', return_value=None)

    dfe_product.log = logging.getLogger('pytest_surveyor')
    dfe_product._token = 'test_token_value'
    dfe_product.process_search(Tag('test123'), {}, query)
    mocked_post_advanced_query.assert_called_once_with(data={'Query': full_query}, headers=None)

def test_process_search(dfe_product : DefenderForEndpoints, mocker):
    """
    Verify process_search() does not alter a given query
    """
    query = 'DeviceFileEvents | where FileName="foo bar"'

    mocked_post_advanced_query = mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._post_advanced_query')
    mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._add_results')
    mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._get_default_header', return_value=None)

    dfe_product.log = logging.getLogger('pytest_surveyor')
    dfe_product._token = 'test_token_value'
    dfe_product.process_search(Tag('test123'), {}, query)
    mocked_post_advanced_query.assert_called_once_with(data={'Query': query}, headers=None)

def test_nested_process_search(dfe_product : DefenderForEndpoints, mocker):
    """
    Verify nested_process_search() translates the given definition file correctly
    """
    mocked_process_search = mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints.process_search')
    mocked_logger = mocker.patch.object(dfe_product, '_echo')

    with open(os.path.join(os.getcwd(), 'tests','data','test_def_file.json')) as f:
        programs = json.load(f)

    for program, criteria in programs.items():
        dfe_product.nested_process_search(Tag(program), criteria, {})

    mocked_process_search.assert_has_calls(
        [
            mocker.call(Tag('field_translation', data=None), {}, "DeviceProcessEvents | where FolderPath has_any ('notepad.exe') | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            mocker.call(Tag('field_translation', data=None), {}, "DeviceNetworkEvents | where RemoteIP has_any ('127.0.0.1') | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine"),
            mocker.call(Tag('field_translation', data=None), {}, "DeviceProcessEvents | where ProcessCommandLine has_any ('MiniDump') | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            mocker.call(Tag('field_translation', data=None), {}, "DeviceFileCertificateInfo | where Signer has_any ('Microsoft') | join kind=inner DeviceProcessEvents on $left.SHA1 == $right.SHA1 | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            mocker.call(Tag('field_translation', data=None), {}, "DeviceNetworkEvents | where RemoteUrl has_any ('raw.githubusercontent.com') | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine"),            
            mocker.call(Tag('field_translation', data=None), {}, "DeviceProcessEvents | where ProcessVersionInfoInternalFileName has_any ('powershell') | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            mocker.call(Tag('field_translation', data=None), {}, "DeviceFileEvents | where FolderPath has_any ('current_date.txt') | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine"),
            mocker.call(Tag('field_translation', data=None), {}, "DeviceImageLoadEvents | where FolderPath has_any ('pcwutl.dll') | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine"),
            mocker.call(Tag('field_translation', data=None), {}, "DeviceProcessEvents | where MD5 has_any ('asdfasdfasdfasdf') | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            mocker.call(Tag('field_translation', data=None), {}, "DeviceProcessEvents | where SHA1 has_any ('qwerqwerqwerqwer') | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            mocker.call(Tag('field_translation', data=None), {}, "DeviceProcessEvents | where SHA256 has_any ('zxcvzxcvzxcv') | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            mocker.call(Tag('field_translation', data=None), {}, "DeviceRegistryEvents | where RegistryKey has_any ('HKLM') | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RegistryValueName, RegistryValueData"),
            mocker.call(Tag('field_translation', data=None), {}, "DeviceNetworkEvents | where RemotePort has_any ('80') | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine"),
            mocker.call(Tag('field_translation', data=None), {}, "DeviceProcessEvents | where InitiatingFolderPath has_any ('cmd.exe') | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            mocker.call(Tag('multiple_values', data=None), {}, "DeviceProcessEvents | where FolderPath has_any ('svchost.exe', 'cmd.exe') | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            mocker.call(Tag('single_query', data=None), {}, "single_query_string_here"),
            mocker.call(Tag('multiple_query', data=None), {}, "first_query_string"),
            mocker.call(Tag('multiple_query', data=None), {}, "second_query_string")
        ]
    )

    mocked_logger.assert_has_calls([
        mocker.call('Query filter url is not supported by product dfe', logging.WARNING),
        mocker.call('Query filter process_file_description is not supported by product dfe', logging.WARNING),
        mocker.call('Query filter filewrite_md5 is not supported by product dfe', logging.WARNING),
        mocker.call('Query filter filewrite_sha256 is not supported by product dfe', logging.WARNING),
    ], any_order = True)

def test_nested_process_search_limit_option(dfe_product: DefenderForEndpoints, mocker):
    query = 'DeviceImageLoadEvents | where FileName = "foo bar"'
    full_query = 'DeviceImageLoadEvents | where FileName = "foo bar" | limit 5'
    dfe_product._limit = 5

    mocked_post_advanced_query = mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._post_advanced_query')
    mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._add_results')
    mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._get_default_header', return_value=None)

    dfe_product.log = logging.getLogger('pytest_surveyor')
    dfe_product._token = 'test_token_value'
    dfe_product.nested_process_search(Tag('test123'), {'query': query}, {})
    mocked_post_advanced_query.assert_called_once_with(data={'Query': full_query}, headers=None)

def test_nested_process_search_unsupported_field(dfe_product : DefenderForEndpoints, mocker):
    """
    Verify nested_process_search() gracefully handles an unsupported field in a definition file
    """
    mocked_process_search = mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints.process_search')
    mocked_logger = mocker.patch.object(dfe_product, '_echo')

    criteria = {'foo': 'bar'}

    dfe_product.log = logging.getLogger('pytest_surveyor')

    dfe_product.nested_process_search(Tag('unsupported_field'), criteria, {})
    mocked_process_search.assert_not_called()
    mocked_logger.assert_has_calls([
        mocker.call('Query filter foo is not supported by product dfe', logging.WARNING)
    ])

def test_process_search_build_query(dfe_product : DefenderForEndpoints, mocker):
    """
    Verify process_search() correctly merges a given query with filter options
    """
    query = 'DeviceFileEvents | where FileName="bar foo"'
    filters = {
        'days':1,
        'minutes':2,
        'hostname':'server1',
        'username':'guest'
    }

    mocked_post_advanced_query = mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._post_advanced_query')
    mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._add_results')
    mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._get_default_header', return_value=None)

    dfe_product.log = logging.getLogger('pytest_surveyor')
    dfe_product._token = 'test_token_value'
    dfe_product.process_search(Tag('test123'), filters, query)
    mocked_post_advanced_query.assert_called_once_with(data={'Query': 'DeviceFileEvents | where FileName="bar foo" | where Timestamp > ago(1d) | where Timestamp > ago(2m) | where DeviceName contains "server1" | where AccountName contains "guest"'}, headers=None)

def test_nested_process_search_build_query(dfe_product : DefenderForEndpoints, mocker):
    """
    Verify nested_process_search() correctly merges a given query with filter options
    """
    criteria = {'query': 'DeviceFileEvents | where FileName="bar foo"'}
    filters = {
        'days':1,
        'minutes':2,
        'hostname':'server1',
        'username':'guest'
    }

    mocked_process_search = mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints.process_search')

    dfe_product.nested_process_search(Tag('test123'), criteria, filters)
    mocked_process_search.assert_called_once_with(Tag('test123', data=None), {}, 'DeviceFileEvents | where FileName="bar foo" | where Timestamp > ago(1d) | where Timestamp > ago(2m) | where DeviceName contains "server1" | where AccountName contains "guest"')