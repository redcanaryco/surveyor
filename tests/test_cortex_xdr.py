import pytest
import sys
import os
import logging
import json
from unittest.mock import patch
sys.path.append(os.getcwd())
from products.cortex_xdr import CortexXDR, Query
from common import Tag


def test_init_lower_limit_option(tmpdir, mocker):
    mocker.patch.object(CortexXDR, '_authenticate')
    cred_file_path = tmpdir.mkdir('test_dir').join('test_creds.ini')
    cred_file_path.write("asdfasdfasdf")
    cortex_product = CortexXDR(profile='default',creds_file = cred_file_path, limit = -1)
    assert cortex_product._limit == 1000


def test_init_upper_limit_option(tmpdir, mocker):
    mocker.patch.object(CortexXDR, '_authenticate')
    cred_file_path = tmpdir.mkdir('test_dir').join('test_creds.ini')
    cred_file_path.write("asdfasdfasdf")
    cortex_product = CortexXDR(profile='default',creds_file = cred_file_path, limit = 1001)
    assert cortex_product._limit == 1000


def test_init_limit_option(tmpdir, mocker):
    mocker.patch.object(CortexXDR, '_authenticate')
    cred_file_path = tmpdir.mkdir('test_dir').join('test_creds.ini')
    cred_file_path.write("asdfasdfasdf")
    cortex_product = CortexXDR(profile='default',creds_file = cred_file_path, limit = 11)
    assert cortex_product._limit == 11

@pytest.fixture
def cortex_product():
    with patch.object(CortexXDR, "__init__", lambda x, y: None):
        return CortexXDR(None)

def test_build_query_with_supported_field(cortex_product : CortexXDR):
    filters = {
        'hostname': 'workstation1',
        'username': 'admin'
    }

    result, timestamp = cortex_product.build_query(filters)

    assert result == ' | filter agent_hostname contains "workstation1" | filter action_process_username contains "admin" or actor_primary_username contains "admin"'

def test_build_query_with_days(cortex_product : CortexXDR):
    filters = {
        'days': 7
    }

    result, timestamp = cortex_product.build_query(filters)

    assert timestamp == 7 * 24 * 60 * 60 * 1000

def test_build_query_with_min(cortex_product : CortexXDR):
    filters = {
        'minutes': 5
    }

    result, timestamp = cortex_product.build_query(filters)

    assert timestamp == 5 * 60 * 1000

def test_build_query_with_unsupported_field(cortex_product : CortexXDR, mocker):
    filters = {
      "useless key": "asdfasdasdf"
    }

    mocked_echo = mocker.patch.object(cortex_product, '_echo')

    result, timestamp = cortex_product.build_query(filters)

    assert result == ''

    mocked_echo.assert_has_calls([
        mocker.call('Query filter useless key is not supported by product cortex', logging.WARNING)
    ])

def test_process_search(cortex_product : CortexXDR):
    cortex_product._queries = {}
    cortex_product.log = logging.getLogger('pytest_surveyor')

    cortex_product.process_search(Tag('test_query'), {}, 'FieldA=ValueB')

    assert len(cortex_product._queries[Tag('test_query')]) == 1
    assert cortex_product._queries[Tag('test_query')][0].parameter is None
    assert cortex_product._queries[Tag('test_query')][0].operator is None
    assert cortex_product._queries[Tag('test_query')][0].search_value is None
    assert cortex_product._queries[Tag('test_query')][0].full_query == 'FieldA=ValueB'
    assert cortex_product._queries[Tag('test_query')][0].relative_time_ms == 14 * 24 * 60 * 60 * 1000

def test_nested_process_search(cortex_product : CortexXDR, mocker):
    cortex_product._queries = {}
    mocked_echo = mocker.patch.object(cortex_product, '_echo')


    with open(os.path.join(os.getcwd(), 'tests','data','test_def_file.json')) as f:
        programs = json.load(f)
    
    for program, criteria in programs.items():
        cortex_product.nested_process_search(Tag(program), criteria, {})

    assert len(cortex_product._queries) == 4

    assert len(cortex_product._queries[Tag('field_translation')]) == 13
    relative_ts = 14 * 24 * 60 * 60 * 1000
    assert Query(relative_ts, 'action_process_image_name', 'contains', '"notepad.exe"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_remote_ip', 'contains', '"127.0.0.1"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_process_command_line', 'contains', '"MiniDump"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_file_signature_vendor', 'contains', '"Microsoft"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_module_path', 'contains', '"pcwutl.dll"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_file_path', 'contains', '"current_date.txt"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_registry_key_name', 'contains', '"HKLM"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_process_image_md5', 'contains', '"asdfasdfasdfasdf"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_process_image_sha256', 'contains', '"zxcvzxcvzxcv"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_remote_port', 'contains', '"80"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_file_md5', 'contains', '"tyuityuityuityui"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_file_sha256', 'contains', '"poiupoiupoiu"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'actor_process_image_name', 'contains', '"cmd.exe"') in cortex_product._queries[Tag('field_translation')]

    assert len(cortex_product._queries[Tag('multiple_values')]) == 1
    assert Query(relative_ts, 'action_process_image_name', 'in', '("*svchost.exe*", "*cmd.exe*")') in cortex_product._queries[Tag('multiple_values')]

    assert len(cortex_product._queries[Tag('single_query')]) == 1
    assert Query(relative_ts, None, None, None, 'single_query_string_here') in cortex_product._queries[Tag('single_query')]

    assert len(cortex_product._queries[Tag('multiple_query')]) == 2
    assert Query(relative_ts, None, None, None, 'first_query_string') in cortex_product._queries[Tag('multiple_query')]
    assert Query(relative_ts, None, None, None, 'second_query_string') in cortex_product._queries[Tag('multiple_query')]

    mocked_echo.assert_has_calls([
        mocker.call('Query filter domain is not supported by product cortex', logging.WARNING),
        mocker.call('Query filter sha1 is not supported by product cortex', logging.WARNING),
        mocker.call('Query filter internal_name is not supported by product cortex', logging.WARNING),
        mocker.call('Query filter url is not supported by product cortex', logging.WARNING),
        mocker.call('Query filter process_file_description is not supported by product cortex', logging.WARNING)        
    ], any_order=True)

def test_nested_process_search_unsupported_field(cortex_product : CortexXDR, mocker):
    criteria = {'foo': 'bar'}
    cortex_product._queries = {}
    cortex_product.log = logging.getLogger('pytest_surveyor')

    mocker.patch.object(cortex_product, '_echo')

    cortex_product.nested_process_search(Tag('unsupported_field'), criteria, {})

    assert len(cortex_product._queries) == 1
    assert cortex_product._queries[Tag('unsupported_field')] == []
    cortex_product._echo.assert_has_calls([
        mocker.call('Query filter foo is not supported by product cortex', logging.WARNING)
    ])

def test_process_queries_full_query(cortex_product : CortexXDR, mocker):
    cortex_product._queries = {}
    cortex_product._results = {}

    cortex_product._url = 'https://cortex.xdr.domain'
    mocker.patch('products.cortex_xdr.CortexXDR._get_default_header', return_value = {})

    criteria = {'query': ['FieldA=cmd.exe']}
    cortex_product.nested_process_search(Tag('single_test'), criteria, {})

    cortex_product.log = logging.getLogger('pytest_surveyor')

    json_response = {'reply': []}
    response_mock = mocker.Mock()
    response_mock.json.return_value = json_response

    cortex_product._session = mocker.Mock()
    mocker.patch('products.cortex_xdr.CortexXDR._get_xql_results', return_value= [[], 0])
    mocked_func = mocker.patch.object(cortex_product._session, 'post', return_value=response_mock)

    cortex_product._process_queries()

    params = {
        'request_data':{
            'query': 'FieldA=cmd.exe | fields agent_hostname, action_process_image_path, action_process_username, action_process_image_command_line, actor_process_image_path, actor_primary_username, actor_process_command_line, event_id',
            'tenants': [],
            'timeframe':{'relativeTime': 14*24*60*60*1000 }
        }
    }

    mocked_func.assert_called_once_with('https://cortex.xdr.domain/public_api/v1/xql/start_xql_query/', headers={}, data=json.dumps(params))

def test_process_queries_query_parameter(cortex_product : CortexXDR, mocker):
    cortex_product._queries = {}
    cortex_product._results = {}

    cortex_product._url = 'https://cortex.xdr.domain'
    mocker.patch('products.cortex_xdr.CortexXDR._get_default_header', return_value = {})

    criteria = {'process_name': ['cmd.exe']}
    cortex_product.nested_process_search(Tag('single_test'), criteria, {})

    cortex_product.log = logging.getLogger('pytest_surveyor')

    json_response = {'reply': []}
    response_mock = mocker.Mock()
    response_mock.json.return_value = json_response

    cortex_product._session = mocker.Mock()
    mocker.patch('products.cortex_xdr.CortexXDR._get_xql_results', return_value= [[], 0])
    mocked_func = mocker.patch.object(cortex_product._session, 'post', return_value=response_mock)

    cortex_product._process_queries()

    params = {
        'request_data':{
            'query': 'dataset=xdr_data | filter action_process_image_name contains "cmd.exe" | fields agent_hostname, action_process_image_path, action_process_username, action_process_image_command_line, actor_process_image_path, actor_primary_username, actor_process_command_line, event_id',
            'tenants': [],
            'timeframe':{'relativeTime': 14*24*60*60*1000 }
        }
    }

    mocked_func.assert_called_once_with('https://cortex.xdr.domain/public_api/v1/xql/start_xql_query/', headers={}, data=json.dumps(params))