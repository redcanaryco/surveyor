import pytest
import sys
import os
from click.testing import CliRunner
sys.path.append(os.getcwd())
from surveyor import cli
from common import Tag


@pytest.fixture
def runner():
    return CliRunner()


def test_survey_cbr(runner: CliRunner, mocker):
    """
    Verify when passing `cbr` parameter, the CbResponse product is called
    """
    mocked_func = mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    runner.invoke(cli, ["cbr"])
    mocked_func.assert_called()


def test_survey_cbc(runner, mocker):
    """
    Verify when passing 'cbc' parameter, the CbEnterpriseEdr product is called
    """
    mocked_func = mocker.patch('products.vmware_cb_enterprise_edr.CbEnterpriseEdr._authenticate')
    runner.invoke(cli, ["cbc"])
    mocked_func.assert_called_once()


def test_survey_s1(runner, mocker):
    """
    Verify when passing `s1` parameter, the SentinelOne product is called
    """
    mocked_func = mocker.patch('products.sentinel_one.SentinelOne._authenticate')
    with runner.isolated_filesystem() as temp_dir:
        cred_file_path = os.path.join(temp_dir, "test_creds.ini")
        with open(cred_file_path, 'w') as deffile:
            deffile.write("testing123")
        runner.invoke(cli, ["s1", "--creds", cred_file_path])
        mocked_func.assert_called_once()


def test_survey_dfe(runner, mocker):
    """
    Verify when passing `dfe` parameter, the DefenderForEndpoints product is called
    """
    mocked_func = mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._authenticate')
    with runner.isolated_filesystem() as temp_dir:
        cred_file_path = os.path.join(temp_dir, "test_creds.ini")
        with open(cred_file_path, 'w') as deffile:
            deffile.write("testing123")
        runner.invoke(cli, ["dfe", "--creds", cred_file_path])
        mocked_func.assert_called_once()


def test_survey_cortex(runner, mocker):
    """
    Verify when passing `cortex` parameter, the CortexXDR product is called
    """
    mocked_func = mocker.patch('products.cortex_xdr.CortexXDR._authenticate')
    with runner.isolated_filesystem() as temp_dir:
        cred_file_path = os.path.join(temp_dir, "test_creds.ini")
        with open(cred_file_path, 'w') as deffile:
            deffile.write("testing123")
        runner.invoke(cli, ["cortex", "--creds", cred_file_path])
        mocked_func.assert_called_once()


def test_custom_query(runner, mocker):
    """
    Verify when a query is passed, it is logged and an EDR product is called
    """
    mocked_func = mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_process_search = mocker.patch('products.vmware_cb_response.CbResponse.process_search')
    result = runner.invoke(cli, ["--query", "SELECT * FROM processes"])
    assert "Running Custom Query: SELECT * FROM processes" in result.output
    mocked_func.assert_called_once()
    mocked_process_search.assert_called_once_with(Tag('query'), {}, 'SELECT * FROM processes')


def test_def_file(runner, mocker):
    """
    Verify when a definition file is passed, it is logged and an EDR product is called
    """
    mocked_func = mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    with runner.isolated_filesystem() as temp_dir:
        def_file_path = os.path.join(temp_dir, "test_deffile.json")
        with open(def_file_path, 'w') as deffile:
            deffile.write("""{"ProgramA":{"process_name":["test.exe"]}}""")
        result = runner.invoke(cli, ["--deffile", def_file_path])
        assert "Processing definition files:" in result.output
        mocked_func.assert_called_once()
        mocked_nested_process_search.assert_called_once_with(Tag('ProgramA', 'test_deffile'), {"process_name":["test.exe"]}, {})


def test_def_dir(runner, mocker):
    """
    Verify when a definition directory is passed, it is logged and an EDR product is called
    """
    mocked_func = mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    with runner.isolated_filesystem() as temp_dir:
        def_file_path1 = os.path.join(temp_dir, "test_deffile1.json")
        def_file_path2 = os.path.join(temp_dir, "test_deffile2.json")
        with open(def_file_path1, 'w') as deffile:
            deffile.write("""{"ProgramA":{"process_name":["test1.exe"]}}""")
        with open(def_file_path2, 'w') as deffile:
            deffile.write("""{"ProgramB":{"process_name":["test2.exe"]}}""")

        expected_calls = [mocker.call(Tag('ProgramA', 'test_deffile1'),{"process_name":["test1.exe"]}, {}), 
                          mocker.call(Tag('ProgramB', 'test_deffile2'),{"process_name":["test2.exe"]}, {})]
        result = runner.invoke(cli, ["--defdir", temp_dir])
        assert "Processing definition files:" in result.output
        mocked_func.assert_called_once()
        mocked_nested_process_search.assert_has_calls(expected_calls)


def test_invalid_def_file(runner, mocker):
    """
    Verify if a non-existent definition file is passed, it is logged and nothing is passed to the EDR product
    """
    mocked_func = mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    result = runner.invoke(cli, ["--deffile", "nonexistent.json"])
    assert "The deffile doesn't exist" in result.output
    mocked_func.assert_called_once()
    mocked_nested_process_search.assert_not_called()


def test_ioc_file(runner, mocker):
    """
    Verify if an IOC file is passed, it is logged and an EDR product is called
    """
    mocked_func = mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    with runner.isolated_filesystem() as temp_dir:
        ioc_file_path = os.path.join(temp_dir, "ioc_list.txt")
        with open(ioc_file_path, 'w') as deffile:
            deffile.write("127.0.0.1")
        result = runner.invoke(cli, ["--iocfile", ioc_file_path, "--ioctype", "ipaddr"])
        assert "Processing IOC file" in result.output
        mocked_func.assert_called_once()
        mocked_nested_process_search.assert_called_once_with(Tag(f'IOC - {ioc_file_path}', 'ioc_list.txt'), {'ipaddr':['127.0.0.1']}, {})


def test_no_argument_provided(runner, mocker):
    mocked_func = mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    arguments = ["--deffile", "--profile", "--prefix", "--output", "--defdir", "--iocfile", "--ioctype", "--query", "--hostname", "--days", "--minutes", "--username"]

    for arg in arguments:
        result = runner.invoke(cli, [arg])
        assert f"Option '{arg}' requires an argument" in result.output


def test_unsupported_command(runner):
    result = runner.invoke(cli, ['asdfasdfasdfasdf'])
    assert f"Error: No such command 'asdfasdfasdfasdf'" in result.output


def test_unsupported_option(runner):
    result = runner.invoke(cli, ['--asdfasdfasdfasdf'])
    assert f"Error: No such option: --asdfasdfasdfasdf" in result.output
