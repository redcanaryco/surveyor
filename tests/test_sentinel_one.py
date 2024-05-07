import pytest
import sys
import os
import logging
import json
from datetime import datetime, timedelta
from unittest.mock import patch, call, ANY
sys.path.append(os.getcwd())
from products.sentinel_one import SentinelOne, Query
from common import Tag

def test_init_dv_lower_limit_option(tmpdir, mocker):
    mocker.patch.object(SentinelOne, '_authenticate')
    cred_file_path = tmpdir.mkdir('test_dir').join('test_creds.ini')
    cred_file_path.write("asdfasdfasdf")
    s1_product = SentinelOne(profile='default',creds_file=cred_file_path, account_id=None, site_id=None, account_name=None, pq=False, limit = -1)
    assert s1_product._limit == 20000

def test_init_dv_upper_limit_option(tmpdir, mocker):
    mocker.patch.object(SentinelOne, '_authenticate')
    cred_file_path = tmpdir.mkdir('test_dir').join('test_creds.ini')
    cred_file_path.write("asdfasdfasdf")

    s1_product = SentinelOne(profile='default',creds_file=cred_file_path, account_id=None, site_id=None, account_name=None, pq=False, limit = 30000)
    assert s1_product._limit == 20000

def test_init_dv_limit_option(tmpdir, mocker):
    mocker.patch.object(SentinelOne, '_authenticate')
    cred_file_path = tmpdir.mkdir('test_dir').join('test_creds.ini')
    cred_file_path.write("asdfasdfasdf")
    s1_product = SentinelOne(profile='default',creds_file=cred_file_path, account_id=None, site_id=None, account_name=None, pq=False, limit = 5)
    assert s1_product._limit == 5

def test_init_pq_lower_limit_option(tmpdir, mocker):
    mocker.patch.object(SentinelOne, '_authenticate')
    cred_file_path = tmpdir.mkdir('test_dir').join('test_creds.ini')
    cred_file_path.write("asdfasdfasdf")

    s1_product = SentinelOne(profile='default',creds_file=cred_file_path, account_id=None, site_id=None, account_name=None, pq=True, limit = -1)
    assert s1_product._limit == 1000

def test_init_pq_upper_limit_option(tmpdir, mocker):
    mocker.patch.object(SentinelOne, '_authenticate')
    cred_file_path = tmpdir.mkdir('test_dir').join('test_creds.ini')
    cred_file_path.write("asdfasdfasdf")
    s1_product = SentinelOne(profile='default',creds_file=cred_file_path, account_id=None, site_id=None, account_name=None, pq=True, limit = 30000)
    assert s1_product._limit == 1000

def test_init_pq_limit_option(tmpdir, mocker):
    mocker.patch.object(SentinelOne, '_authenticate')
    cred_file_path = tmpdir.mkdir('test_dir').join('test_creds.ini')
    cred_file_path.write("asdfasdfasdf")
    s1_product = SentinelOne(profile='default',creds_file=cred_file_path, account_id=None, site_id=None, account_name=None, pq=True, limit = 6)
    assert s1_product._limit == 6

@pytest.fixture
def s1_product():
    with patch.object(SentinelOne, "__init__", lambda x, y: None):
        return SentinelOne(None)

def test_build_query_with_supported_field_dv(s1_product : SentinelOne):
    filters = {
        'hostname': 'workstation1',
        'username': 'admin'
    }
    s1_product._pq = False
    base, from_date, to_date = s1_product.build_query(filters)

    assert base == 'EndpointName containscis "workstation1" AND UserName containscis "admin"'

def test_build_query_time_filter_min(s1_product : SentinelOne):
    filters = {
        'minutes': 10
    }
    s1_product._pq = False
    base, from_date, to_date = s1_product.build_query(filters)

    assert to_date - timedelta(minutes=10) == from_date

def test_build_query_time_filter_day(s1_product : SentinelOne):
    filters = {
        'days': 7
    }
    s1_product._pq = False
    base, from_date, to_date = s1_product.build_query(filters)

    assert to_date - timedelta(days=7) == from_date

def test_build_query_with_supported_field_pq(s1_product : SentinelOne):
    filters = {
        'hostname': 'workstation2',
        'username': 'admin1'
    }
    s1_product._pq = True

    base, from_date, to_date = s1_product.build_query(filters)

    assert base == 'endpoint.name contains "workstation2" and src.process.user contains "admin1"'

def test_build_query_unsupported_keys(s1_product : SentinelOne):
    filters = {
        "useless key": "asdfasdfasdf"
    }
    s1_product._pq = False
    s1_product.log = logging.getLogger('pytest_surveyor')

    base, from_date, to_date = s1_product.build_query(filters)

    assert base == ''

def test_divide_chunks(s1_product : SentinelOne):
    entries = ['a','b','c','d','e']
    expected_results = [['a','b','c'],['d','e']]
    count = 3
    i = 0

    results = s1_product.divide_chunks(l=entries, n=count)
    for item in results:
        assert item == expected_results[i]
        i += 1

def test_process_search(s1_product : SentinelOne):
    s1_product.log = logging.getLogger('pytest_surveyor')
    s1_product._queries = {}

    s1_product.process_search(Tag('test_query'), {}, 'FileName containsCIS "svchost.exe"')

    assert len(s1_product._queries[Tag('test_query')]) == 1
    assert s1_product._queries[Tag('test_query')][0].parameter is None
    assert s1_product._queries[Tag('test_query')][0].operator is None
    assert s1_product._queries[Tag('test_query')][0].search_value is None
    assert s1_product._queries[Tag('test_query')][0].full_query == 'FileName containsCIS "svchost.exe"'
    assert s1_product._queries[Tag('test_query')][0].end_date - timedelta(days=14) == s1_product._queries[Tag('test_query')][0].start_date

def test_nested_process_search_dv(s1_product : SentinelOne):
    with open(os.path.join(os.getcwd(), 'tests', 'data', 's1_surveyor_testing.json')) as f:
        programs = json.load(f)

    s1_product._queries = {}
    s1_product._pq = False

    for program, criteria in programs.items():
        s1_product.nested_process_search(Tag(program), criteria, {})
    
    assert len(s1_product._queries) == 4

    assert len(s1_product._queries[Tag('field_translation')]) == 16
    sdate = s1_product._queries[Tag('field_translation')][0].start_date
    edate = s1_product._queries[Tag('field_translation')][0].end_date
    assert Query(sdate, edate, 'ProcessName', 'containscis', '"notepad.exe"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'IP', 'containscis', '"127.0.0.1"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'CmdLine', 'containscis', '"MiniDump"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'Publisher', 'containscis', '"Microsoft Publisher"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'DNS', 'containscis', '"raw.githubusercontent.com"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'TgtFileInternalName', 'containscis', '"powershell"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'Url', 'containscis', '"https://google.com"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'FilePath', 'containscis', '"current_date.txt"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'ModulePath', 'containscis', '"pcwutl.dll"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'SrcProcDisplayName', 'containscis', '"Evil Stuff Here"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'Md5', 'containscis', '"asdfasdfasdfasdf"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'Sha1', 'containscis', '"qwerqwerqwerqwer"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'Sha256', 'containscis', '"zxcvzxcvzxcv"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'DstPort', 'containscis', '"80"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'RegistryKeyPath', 'containscis', '"HKLM"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'RegistryValue', 'containscis', '"HKLM"', None) in s1_product._queries[Tag('field_translation')]

    assert len(s1_product._queries[Tag('multiple_values')]) == 1
    sdate = s1_product._queries[Tag('multiple_values')][0].start_date
    edate = s1_product._queries[Tag('multiple_values')][0].end_date    
    assert Query(sdate, edate, 'ProcessName', 'in contains anycase', '("svchost.exe", "cmd.exe")', None) in s1_product._queries[Tag('multiple_values')]
    
    assert len(s1_product._queries[Tag('single_query')]) == 1
    sdate = s1_product._queries[Tag('single_query')][0].start_date
    edate = s1_product._queries[Tag('single_query')][0].end_date    
    assert Query(sdate, edate, 'query', 'raw', 'FileName containscis "rundll.exe"', None) in s1_product._queries[Tag('single_query')]
    
    assert len(s1_product._queries[Tag('multiple_query')]) == 1
    sdate = s1_product._queries[Tag('multiple_query')][0].start_date
    edate = s1_product._queries[Tag('multiple_query')][0].end_date
    assert Query(sdate, edate, 'query', 'raw', '(ProcessCmdLine contains "-enc") OR (ModulePath contains "malware.dll")', None) in s1_product._queries[Tag('multiple_query')]

def test_nested_process_search_dv_over_100_terms(s1_product : SentinelOne):
    list_o_terms = list(range(1, 106))
    first_list = '("' + '", "'.join([str(x) for x in list(range(1,101))]) + '")'
    second_list = '("' + '", "'.join([str(x) for x in list(range(101,106))]) + '")'

    s1_product._queries = {}
    s1_product._pq = False

    s1_product.nested_process_search(Tag('list_of_105_terms'), {'process_name':list_o_terms}, {})

    assert len(s1_product._queries[Tag('list_of_105_terms')]) == 2
    sdate = s1_product._queries[Tag('list_of_105_terms')][0].start_date
    edate = s1_product._queries[Tag('list_of_105_terms')][0].end_date
    assert Query(sdate, edate, 'ProcessName', 'in contains anycase', first_list, None) in s1_product._queries[Tag('list_of_105_terms')]
    assert Query(sdate, edate, 'ProcessName', 'in contains anycase', second_list, None) in s1_product._queries[Tag('list_of_105_terms')]

def test_nested_process_search_pq(s1_product : SentinelOne):
    with open(os.path.join(os.getcwd(), 'tests', 'data', 's1_surveyor_testing.json')) as f:
        programs = json.load(f)

    s1_product._queries = {}
    s1_product._pq = True

    for program, criteria in programs.items():
        s1_product.nested_process_search(Tag(program), criteria, {})
    
    assert len(s1_product._queries) == 4

    assert len(s1_product._queries[Tag('field_translation')]) == 21
    sdate = s1_product._queries[Tag('field_translation')][0].start_date
    edate = s1_product._queries[Tag('field_translation')][0].end_date
    assert Query(sdate, edate, 'src.process.name', 'in', '("notepad.exe")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'dst.ip.address', 'in', '("127.0.0.1")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'src.process.cmdline', 'in', '("MiniDump")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'src.process.publisher', 'in', '("Microsoft Publisher")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'event.dns.request', 'in', '("raw.githubusercontent.com")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.file.internalName', 'in', '("powershell")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'url.address', 'in', '("https://google.com")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.file.path', 'in', '("current_date.txt")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'module.path', 'in', '("pcwutl.dll")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'src.process.displayName', 'in', '("Evil Stuff Here")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'src.process.image.md5', 'in', '("asdfasdfasdfasdf")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'src.process.image.sha256', 'in', '("zxcvzxcvzxcv")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'src.process.image.sha1', 'in', '("qwerqwerqwerqwer")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.file.md5', 'in', '("asdfasdfasdfasdf")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.file.sha256', 'in', '("zxcvzxcvzxcv")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.file.sha1', 'in', '("qwerqwerqwerqwer")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'module.md5', 'in', '("asdfasdfasdfasdf")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'module.sha1', 'in', '("qwerqwerqwerqwer")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'registry.keyPath', 'in', '("HKLM")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'registry.value', 'in', '("HKLM")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'dst.port.number', 'in', '("80")', None) in s1_product._queries[Tag('field_translation')]

    assert len(s1_product._queries[Tag('multiple_values')]) == 1
    sdate = s1_product._queries[Tag('multiple_values')][0].start_date
    edate = s1_product._queries[Tag('multiple_values')][0].end_date    
    assert Query(sdate, edate, 'src.process.name', 'in', '("svchost.exe", "cmd.exe")', None) in s1_product._queries[Tag('multiple_values')]
    
    assert len(s1_product._queries[Tag('single_query')]) == 1
    sdate = s1_product._queries[Tag('single_query')][0].start_date
    edate = s1_product._queries[Tag('single_query')][0].end_date    
    assert Query(sdate, edate, None, None, None, 'FileName containscis "rundll.exe"') in s1_product._queries[Tag('single_query')]
    
    assert len(s1_product._queries[Tag('multiple_query')]) == 1
    sdate = s1_product._queries[Tag('multiple_query')][0].start_date
    edate = s1_product._queries[Tag('multiple_query')][0].end_date
    assert Query(sdate, edate, None, None, None, '(ProcessCmdLine contains "-enc") or (ModulePath contains "malware.dll")') in s1_product._queries[Tag('multiple_query')]

def test_nested_process_search_pq_over_max_char_limit(s1_product : SentinelOne):
    list_o_terms = ['abcdefghijklmnopqrstuvwxyz'] * 251
    first_list = '("' + '", "'.join(['abcdefghijklmnopqrstuvwxyz']*125) + '")'
    second_list = '("' + '", "'.join(['abcdefghijklmnopqrstuvwxyz']*1) + '")'

    s1_product._queries = {}
    s1_product._pq = True

    s1_product.nested_process_search(Tag('many_chars'), {'process_name': list_o_terms}, {})

    assert len(s1_product._queries[Tag('many_chars')]) == 3
    sdate = s1_product._queries[Tag('many_chars')][0].start_date
    edate = s1_product._queries[Tag('many_chars')][0].end_date
    assert s1_product._queries[Tag('many_chars')] == [Query(sdate, edate, 'src.process.name', 'in', first_list, None), Query(sdate, edate, 'src.process.name', 'in', first_list, None), Query(sdate, edate, 'src.process.name', 'in', second_list, None)]

def test_nested_process_search_unsupported_field(s1_product : SentinelOne):
    criteria = {'foo': 'bar'}
    s1_product._queries = {}
    s1_product._pq = False
    s1_product.log = logging.getLogger('pytest_surveyor')

    s1_product.nested_process_search(Tag('unsupported_field'), criteria, {})

    assert len(s1_product._queries) == 0

def test_get_query_text_handles_same_field_different_tag_dv(s1_product : SentinelOne):
    sdate = datetime.now()
    edate = sdate - timedelta(days=7)
    s1_product._pq = False
    s1_product._queries = {
        Tag('valueA'): [Query(sdate, edate, 'ProcessName', 'containscis', '"svchost.exe"')],
        Tag('valueB'): [Query(sdate, edate, 'ProcessName', 'containscis', '"cmd.exe"')]
    }

    assert s1_product._get_query_text() == [(Tag('valueA', data=None), 'ProcessName containscis "svchost.exe"'), (Tag('valueB', data=None), 'ProcessName containscis "cmd.exe"')]

def test_get_query_text_handles_different_fields_different_tag_dv(s1_product : SentinelOne):
    sdate = datetime.now()
    edate = sdate - timedelta(days=7)
    s1_product._pq = False
    s1_product._queries = {
        Tag('valueA'): [Query(sdate, edate, 'ProcessName', 'containscis', '"posh.exe"')],
        Tag('valueB'): [Query(sdate, edate, 'ModulePath', 'containscis', '"evil.dll"')]
    }

    assert s1_product._get_query_text() == [
        (Tag('valueA', data=None), 'ProcessName containscis "posh.exe"'),
        (Tag('valueB', data=None), 'ModulePath containscis "evil.dll"')]

def test_get_query_text_handles_parameters_pq(s1_product: SentinelOne):
    sdate = datetime.now()
    edate = sdate - timedelta(days=7)
    s1_product._pq = True
    s1_product._queries = {
        Tag('valueA'): [Query(sdate, edate, 'endpoint.name', 'contains', '"dc01"')]
    }

    assert s1_product._get_query_text() == [
        (Tag('valueA', data=None), 'endpoint.name contains "dc01"')
    ]

def test_get_query_text_handles_full_query_pq(s1_product : SentinelOne):
    sdate = datetime.now()
    edate = sdate - timedelta(days=7)
    s1_product._pq = True
    s1_product._queries = {
        Tag('valueA'): [Query(sdate, edate, None, None, None, 'src.process.name contains "explorer.exe"')]
    }

    assert s1_product._get_query_text() == [
        (Tag('valueA', data=None), 'src.process.name contains "explorer.exe"')
    ]

def test_process_queries_dv(s1_product : SentinelOne, mocker):
    # test that queries are grouped by tag as expected
    sdate = datetime.now()
    edate = sdate - timedelta(days=7)
    s1_product._pq = False
    s1_product._query_base = None
    s1_product._dv_wait = 1
    s1_product.log = logging.getLogger('pytest_surveyor')
    mocked_run_query = mocker.patch.object(s1_product, '_run_query')

    s1_product._queries = {
        Tag('valueA', data=None): [Query(sdate, edate, 'ProcessName', 'containscis', 'powershell.exe'),
                                   Query(sdate, edate, 'ProcessName', 'containscis', 'cmd.exe'),
                                   Query(sdate, edate, 'ProcessName', 'containscis', 'rundll32.exe'),
                                   Query(sdate, edate, 'ProcessName', 'containscis', 'wsl.exe'),
                                   Query(sdate, edate, 'ProcessName', 'containscis', 'regsvr32.exe'),
                                   Query(sdate, edate, 'ProcessName', 'containscis', 'svchost.exe'),
                                   Query(sdate, edate, 'ProcessName', 'containscis', 'notepad.exe'),
                                   Query(sdate, edate, 'ProcessName', 'containscis', 'explorer.exe'),
                                   Query(sdate, edate, 'ProcessName', 'containscis', 'firefox.exe'),
                                   Query(sdate, edate, 'ProcessName', 'containscis', 'chrome.exe'),
                                   Query(sdate, edate, 'ProcessName', 'containscis', 'iexplore.exe')],
        Tag('valueB', data=None): [Query(sdate, edate, 'DNS', 'containscis', 'google.com'),
                                   Query(sdate, edate, 'DNS', 'containscis', 'microsoft.com'),
                                   Query(sdate, edate, 'DNS', 'containscis', 'amazon.com'),
                                   Query(sdate, edate, 'DNS', 'containscis', 'bing.com'),
                                   Query(sdate, edate, 'DNS', 'containscis', 'yahoo.com'),
                                   Query(sdate, edate, 'DNS', 'containscis', 'github.com'),
                                   Query(sdate, edate, 'DNS', 'containscis', 'virustotal.com'),
                                   Query(sdate, edate, 'DNS', 'containscis', 'facebook.com'),
                                   Query(sdate, edate, 'DNS', 'containscis', 'twitter.com'),
                                   Query(sdate, edate, 'DNS', 'containscis', 'spotify.com'),
                                   Query(sdate, edate, 'DNS', 'containscis', 'apple.com'),]
    }

    s1_product._process_queries()

    mocked_run_query.assert_has_calls([
        call('ProcessName containscis powershell.exe OR ProcessName containscis cmd.exe OR ProcessName ' + 
             'containscis rundll32.exe OR ProcessName containscis wsl.exe OR ProcessName containscis regsvr32.exe ' + 
             'OR ProcessName containscis svchost.exe OR ProcessName containscis notepad.exe OR ProcessName containscis ' + 
             'explorer.exe OR ProcessName containscis firefox.exe OR ProcessName containscis chrome.exe', 
             ANY, ANY, Tag('valueA', data=None), ANY, True),
        call('ProcessName containscis iexplore.exe', ANY, ANY, Tag('valueA', data=None), ANY, True),
        call('DNS containscis google.com OR DNS containscis microsoft.com OR DNS containscis amazon.com OR DNS containscis bing.com ' + 
             'OR DNS containscis yahoo.com OR DNS containscis github.com OR DNS containscis virustotal.com OR DNS containscis facebook.com ' + 
             'OR DNS containscis twitter.com OR DNS containscis spotify.com', 
             ANY, ANY, Tag('valueB', data=None), ANY, True),
        call('DNS containscis apple.com', ANY, ANY, Tag('valueB', data=None), ANY, True)
    ])

def test_process_queries_pq(s1_product : SentinelOne, mocker):
    # test that queries are grouped by tag as expected
    sdate = datetime.now()
    edate = sdate - timedelta(days=7)
    s1_product._pq = True
    s1_product._query_base = None
    s1_product._site_ids = []
    s1_product.log = logging.getLogger('pytest_surveyor')
    mocked_run_query = mocker.patch.object(s1_product, '_run_query')

    s1_product._queries = {
        Tag('valueA', data=None): [Query(sdate, edate, 'src.process.name', 'contains', 'powershell.exe'),
                                   Query(sdate, edate, 'src.process.name', 'contains', 'cmd.exe'),
                                   Query(sdate, edate, 'src.process.name', 'contains', 'rundll32.exe'),
                                   Query(sdate, edate, 'src.process.name', 'contains', 'wsl.exe'),
                                   Query(sdate, edate, 'src.process.name', 'contains', 'regsvr32.exe'),
                                   Query(sdate, edate, 'src.process.name', 'contains', 'svchost.exe'),
                                   Query(sdate, edate, 'src.process.name', 'contains', 'notepad.exe'),
                                   Query(sdate, edate, 'src.process.name', 'contains', 'explorer.exe'),
                                   Query(sdate, edate, 'src.process.name', 'contains', 'firefox.exe'),
                                   Query(sdate, edate, 'src.process.name', 'contains', 'chrome.exe'),
                                   Query(sdate, edate, 'src.process.name', 'contains', 'iexplore.exe')],
        Tag('valueB', data=None): [Query(sdate, edate, 'event.dns.request', 'contains', 'google.com'),
                                   Query(sdate, edate, 'event.dns.request', 'contains', 'microsoft.com'),
                                   Query(sdate, edate, 'event.dns.request', 'contains', 'amazon.com'),
                                   Query(sdate, edate, 'event.dns.request', 'contains', 'bing.com'),
                                   Query(sdate, edate, 'event.dns.request', 'contains', 'yahoo.com'),
                                   Query(sdate, edate, 'event.dns.request', 'contains', 'github.com'),
                                   Query(sdate, edate, 'event.dns.request', 'contains', 'virustotal.com'),
                                   Query(sdate, edate, 'event.dns.request', 'contains', 'facebook.com'),
                                   Query(sdate, edate, 'event.dns.request', 'contains', 'twitter.com'),
                                   Query(sdate, edate, 'event.dns.request', 'contains', 'spotify.com'),
                                   Query(sdate, edate, 'event.dns.request', 'contains', 'apple.com'),]
    }

    s1_product._process_queries()

    mocked_run_query.assert_has_calls([
        call('src.process.name contains powershell.exe OR src.process.name contains cmd.exe OR src.process.name contains ' + 
             'rundll32.exe OR src.process.name contains wsl.exe OR src.process.name contains regsvr32.exe ' + 
             'OR src.process.name contains svchost.exe OR src.process.name contains notepad.exe OR src.process.name contains ' + 
             'explorer.exe OR src.process.name contains firefox.exe OR src.process.name contains chrome.exe ' + 
             '| group count() by endpoint.name, src.process.user, ' +
             'src.process.image.path, src.process.cmdline, event.time, ' +
             'site.id, site.name, src.process.storyline.id, src.process.displayname, ' +
             'src.process.parent.image.path, tgt.process.displayname, tgt.process.image.path, ' +
             'tgt.file.path, tgt.file.sha1, tgt.file.sha256, url.address, src.ip.address, ' +
             'dst.ip.address, event.dns.request, event.type', 
             ANY, ANY, Tag('valueA', data=None), ANY, False),
        call('src.process.name contains iexplore.exe | group count() by endpoint.name, src.process.user, ' +
             'src.process.image.path, src.process.cmdline, event.time, ' +
             'site.id, site.name, src.process.storyline.id, src.process.displayname, ' +
             'src.process.parent.image.path, tgt.process.displayname, tgt.process.image.path, ' +
             'tgt.file.path, tgt.file.sha1, tgt.file.sha256, url.address, src.ip.address, ' +
             'dst.ip.address, event.dns.request, event.type',  ANY, ANY, Tag('valueA', data=None), ANY, False),
        call('event.dns.request contains google.com OR event.dns.request contains microsoft.com OR event.dns.request contains amazon.com OR event.dns.request contains bing.com ' + 
             'OR event.dns.request contains yahoo.com OR event.dns.request contains github.com OR event.dns.request contains virustotal.com OR event.dns.request contains facebook.com ' + 
             'OR event.dns.request contains twitter.com OR event.dns.request contains spotify.com ' + 
             '| group count() by endpoint.name, src.process.user, ' +
             'src.process.image.path, src.process.cmdline, event.time, ' +
             'site.id, site.name, src.process.storyline.id, src.process.displayname, ' +
             'src.process.parent.image.path, tgt.process.displayname, tgt.process.image.path, ' +
             'tgt.file.path, tgt.file.sha1, tgt.file.sha256, url.address, src.ip.address, ' +
             'dst.ip.address, event.dns.request, event.type', 
             ANY, ANY, Tag('valueB', data=None), ANY, False),
        call('event.dns.request contains apple.com | group count() by endpoint.name, src.process.user, ' +
             'src.process.image.path, src.process.cmdline, event.time, ' +
             'site.id, site.name, src.process.storyline.id, src.process.displayname, ' +
             'src.process.parent.image.path, tgt.process.displayname, tgt.process.image.path, ' +
             'tgt.file.path, tgt.file.sha1, tgt.file.sha256, url.address, src.ip.address, ' +
             'dst.ip.address, event.dns.request, event.type',  ANY, ANY, Tag('valueB', data=None), ANY, False)
    ])

def test_process_queries_pq_single_site_id(s1_product : SentinelOne, mocker):
    # test that queries are grouped by tag as expected
    sdate = datetime.now()
    edate = sdate - timedelta(days=7)
    s1_product._pq = True
    s1_product._query_base = None
    s1_product._site_ids = ['12345']
    s1_product.log = logging.getLogger('pytest_surveyor')
    mocked_run_query = mocker.patch.object(s1_product, '_run_query')

    s1_product._queries = {
        Tag('valueA', data=None): [Query(sdate, edate, 'src.process.name', 'contains', 'powershell.exe')],
    }

    s1_product._process_queries()

    mocked_run_query.assert_has_calls([
        call('(src.process.name contains powershell.exe) AND (site.id = 12345) ' + 
             '| group count() by endpoint.name, src.process.user, ' +
             'src.process.image.path, src.process.cmdline, event.time, ' +
             'site.id, site.name, src.process.storyline.id, src.process.displayname, ' +
             'src.process.parent.image.path, tgt.process.displayname, tgt.process.image.path, ' +
             'tgt.file.path, tgt.file.sha1, tgt.file.sha256, url.address, src.ip.address, ' +
             'dst.ip.address, event.dns.request, event.type', 
             ANY, ANY, Tag('valueA', data=None), ANY, False)
    ])

def test_process_queries_pq_multiple_site_ids(s1_product : SentinelOne, mocker):
    # test that queries are grouped by tag as expected
    sdate = datetime.now()
    edate = sdate - timedelta(days=7)
    s1_product._pq = True
    s1_product._query_base = None
    s1_product._site_ids = ['12345', '67890']
    s1_product.log = logging.getLogger('pytest_surveyor')
    mocked_run_query = mocker.patch.object(s1_product, '_run_query')

    s1_product._queries = {
        Tag('valueA', data=None): [Query(sdate, edate, 'src.process.name', 'contains', 'powershell.exe')],
    }

    s1_product._process_queries()

    mocked_run_query.assert_has_calls([
        call('(src.process.name contains powershell.exe) AND (site.id = 12345 OR site.id = 67890) ' + 
             '| group count() by endpoint.name, src.process.user, ' +
             'src.process.image.path, src.process.cmdline, event.time, ' +
             'site.id, site.name, src.process.storyline.id, src.process.displayname, ' +
             'src.process.parent.image.path, tgt.process.displayname, tgt.process.image.path, ' +
             'tgt.file.path, tgt.file.sha1, tgt.file.sha256, url.address, src.ip.address, ' +
             'dst.ip.address, event.dns.request, event.type', 
             ANY, ANY, Tag('valueA', data=None), ANY, False)
    ])
