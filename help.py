import os
import sys
import logging
import re
from datetime import *

# regular expression that detects ANSI color codes
from tqdm import tqdm

ansi_escape_regex = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', re.VERBOSE)

def any_item_in_list(values_list, check_list):
    values_set = set(values_list)
    for item in check_list:
        if item in values_set:
            return True
    return False

EDR_SUPPORTED_ARGUMENTS = {
    "cbc": {
        "cred_check_logic": lambda a: True if set(['url','token','org_key']).issubset(set(a)) else False,
        "credential_requirements": "url, token, and org_key",
        "product_arguments": ['device_group', 'device_policy']
    },
    "cbr": {
        "cred_check_logic": lambda a: True if set(['url','token']).issubset(set(a)) else False,
        "credential_requirements": "url and token",
        "product_arguments": ['sensor_group']
    },
    "cortex": {
        "cred_check_logic":  lambda a: True if set(['api_key','url', 'api_key_id','auth_type']).issubset(set(a)) else False,
        "credential_requirements": "api_key, url, api_key_id, and auth_type",
        "product_arguments": None
    },
    "dfe": {
        "cred_check_logic":  lambda a: True if any_item_in_list(['tenantId','appId','appSecret'], a) or 'token' in a else False,
        "credential_requirements": "tenantId, appId, and appSecret or token",
        "product_arguments": None
    },
    "s1": {
        "cred_check_logic": lambda a: True if any_item_in_list(['site_ids', 'account_ids', 'account_names', 'bypass'], a) else False,
        "credential_requirements": "site_ids, account_ids, account_names, or bypass",
        "product_arguments": ['deep_visibility']
    }
}

def _strip_ansi_codes(message: str) -> str:
    """
    Strip ANSI sequences from a log string
    """
    return ansi_escape_regex.sub('', message)

def log_echo(message: str, log: logging.Logger, level: int = logging.DEBUG, use_tqdm: bool = False):
    """
    Write a command to STDOUT and the debug log stream.
    """
    color_message = message

    if level == logging.WARNING:
        color_message = f'\u001b[33m{color_message}\u001b[0m'
    elif level >= logging.ERROR:
        color_message = f'\u001b[31m{color_message}\u001b[0m'

    if use_tqdm:
        tqdm.write(color_message)
    else:
        print(message)

    # strip ANSI sequences from log string
    log.log(level, _strip_ansi_codes(message))


def datetime_to_epoch_millis(date: datetime) -> int:
    """
    Convert a datetime object to an epoch timestamp in milliseconds.
    """
    return int((date - datetime.utcfromtimestamp(0)).total_seconds() * 1000)

def credential_builder(args) -> dict: 

    # CBC
    if args.edr == 'cbc':
        return {'profile': args.profile}
    
    # CBr
    if args.edr == 'cbr':
        return {'profile': args.profile}
        
    # Cortex
    if args.edr == 'cortex':
        return {'profile': args.profile, "auth_type": args.auth_type.lower(), "tenant_ids": args.tenant_ids, "creds_file": args.creds} 
            
    # DFE
    if args.edr == "dfe":
       return {'profile': args.profile, "creds_file": args.creds} 
    
    # S1
    if args.edr == "s1":
        return {'profile': args.profile, "site_ids": args.site_ids, "account_ids": args.account_ids, "account_names": args.account_names, "creds_file": args.creds, "bypass": args.bypass}


def product_arg_builder(args) -> dict:
    # Takes in argparse arguements and creates product arguments by applicable edr
    product_args = {}

    #CBC
    if args.edr == 'cbc':
        cbc_product_args = {"device_group": args.device_group,"device_policy": args.device_policy} 
        product_args = {k:v for k,v in cbc_product_args.items() if v != None}
    
    #CBr
    if args.edr == 'cbr':
        cbr_product_args =  {"sensor_group": args.sensor_group} 
        product_args = {k:v for k,v in cbr_product_args.items() if v != None}

    #S1
    if args.edr == 's1':
        s1_product_args = {"deep_visibility": args.dv} #str
        product_args = {k:v for k,v in s1_product_args.items() if v != None}
    
    return product_args

def build_survey(args) -> dict:
    import argparse
    parser = argparse.ArgumentParser(args)
    parser.add_argument("--prefix", help="Output filename prefix.", type=str)
    days_minutes = parser.add_mutually_exclusive_group()
    days_minutes.add_argument("--days", help="Number of days to search.", type=int)
    days_minutes.add_argument("--minutes", help="Number of minutes to search.", type=int)
    parser.add_argument("--limit",help="""
                Number of results to return. Cortex XDR: Default: 1000, Max: Default
                Microsoft Defender for Endpoint: Default/Max: 100000
                SentinelOne (PowerQuery): Default/Max: 1000
                SentinelOne (Deep Visibility): Default/Max: 20000
                VMware Carbon Black EDR: Default/Max: None
                VMware Carbon Black Cloud Enterprise EDR: Default/Max: None
                
                Note: Exceeding the maximum limits will automatically set the limit to its maximum value, where applicable.
                """
                , type=int)

    parser.add_argument("--hostname", help="Target specific host by name.", type=str)
    parser.add_argument("--username", help="Target specific username.", type=str)

    # different ways you can survey the EDR
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--query", "-q", help="A single query to execute.", type=str)
    mode.add_argument("--deffile", help="Definition file to process (must end in .json).", type=str)
    mode.add_argument("--defdir", help="Directory containing multiple definition files.", type=os.path.abspath, metavar='DIR')
    mode.add_argument("--sigmarule", help="Sigma rule file to process (must be in YAML format).", type=os.path.abspath, metavar='FILE')
    mode.add_argument("--sigmadir", help='Directory containing multiple sigma rule files.', type=os.path.abspath, metavar='DIR')
    mode.add_argument("--iocfile", help="IOC file to process. One IOC per line. REQUIRES --ioctype", type=os.path.abspath, metavar='FILE')
    mode.add_argument("--iocdir", help='Directory containing multiple IOC files of the same type [ipaddr, domain, md5] (file must be in TXT format).', type=os.path.abspath, metavar='DIR')

    # optional output
    parser.add_argument("--ioctype", help="One of: ipaddr, domain, md5", choices=['ipaddr', 'domain', 'md5'])
    parser.add_argument("--output", "-o", help="Specify the output file for the results. The default is create survey.csv in the current directory.")
    parser.add_argument("--output-format", help="Specify the output file for the results. The default is create survey.csv in the current directory.", choices=['csv', 'json'], default='csv')
    parser.add_argument("--no-file", help="Write results to STDOUT instead of the output CSV", default=False)
    parser.add_argument("--no-progress", help="Suppress progress bar", default=False)

    # logging options
    parser.add_argument("--log-dir", help="Specify the logging directory.", type=str, default='logs')

    # required
    subparsers = parser.add_subparsers(dest='edr',help="Specify EDR to be queried must be one of 'cbc', 'cbr', 'cortex', 'dfe', 's1'", required=True)

    # CbC options
    cbc_group = subparsers.add_parser('cbc', help='Optional VMware Cb Enterprise EDR Parameters')
    cbc_group.add_argument("--device-group", help="Name of device group to query", type=str, nargs='+', default=None)
    cbc_group.add_argument("--device-policy", help="Name of device policy to query", type=str, nargs='+', default=None)
    cbc_group.add_argument("--creds", help="Absolute path to credential file", type=os.path.realpath, default=None, required=False)
    cbc_group.add_argument("--profile", help="The credentials profile to use.", type=str, default='default')

    # CbR Options
    cbr_group = subparsers.add_parser('cbr', help='Optional VMware Cb Response Parameters')
    cbr_group.add_argument("--sensor-group", help="Name of sensor group to query", type=str, nargs='+', default=None)
    cbr_group.add_argument("--creds", help="Absolute path to credential file", type=os.path.realpath, default=None, required=False)
    cbr_group.add_argument("--profile", help="The credentials profile to use.", type=str, default='default')
    
    
    # Cortex options
    cortex_group = subparsers.add_parser('cortex', help='Optional Cortex XDR Parameters')
    cortex_group.add_argument("--auth-type", help="ID of SentinelOne site to query", type=str, default='standard')
    cortex_group.add_argument("--tenant-ids", help="ID of SentinelOne account to query", type=str, nargs='+', default=[])
    cortex_group.add_argument("--creds", help="Absolute path to credential file", type=os.path.realpath, default=None, required=True)
    cortex_group.add_argument("--profile", help="The credentials profile to use.", type=str, required=True)
    
    # DFE options
    dfe_group = subparsers.add_parser('dfe', help='Optional Microsoft Defender for Endpoints Parameters')
    dfe_group.add_argument("--creds", help="Absolute path to credential file", type=os.path.realpath, default=None, required=True)
    dfe_group.add_argument("--profile", help="The credentials profile to use.", type=str, required=True)

    # S1 options
    s1_group = subparsers.add_parser('s1', help='Optional S1 parameters')
    s1_group.add_argument("--site-ids", help="ID of SentinelOne site to query", type=str, nargs='+', default=[])
    s1_group.add_argument("--account-ids", help="ID of SentinelOne account to query", type=str, nargs='+', default=[])
    s1_group.add_argument("--account-names", help="Name of SentinelOne account to query", type=str, nargs='+', default=[])
    s1_group.add_argument("--dv", help="Use Deep Visibility for queries", action='store_true', default=False)
    s1_group.add_argument("--creds", help="Absolute path to credential file", type=os.path.realpath, default=None, required=True)
    s1_group.add_argument("--profile", help="The credentials profile to use.", type=str, required=True)
    s1_group.add_argument(
        "--bypass",
        help="Bypass authorization verification if account IDs, Site IDs, or Account Names are not to be taken into account.",
        action='store_true',
        default=False
    )

    args = parser.parse_args()
    product_args = product_arg_builder(args)
    creds = credential_builder(args)

    survey_payload = {'prefix': None, 'days': None, 'minutes': None, 'limit': None, 'hostname': None, 'username': None, 'query': None, 'output': None, 'no_file': True, 'no_progress': False, 'log_dir': None, "ioc_list": None, "ioc_type": None, "definitions" : None, "sigma_rules": None, "products_args": None, "output_format": "csv"}

    for k,v in args.__dict__.items():
        if k in list(survey_payload.keys()):
            survey_payload[k] = v if v != None else survey_payload.pop(k)

    survey_payload['edr'] = args.edr
    
    if args.iocfile and args.ioctype is None:
        sys.exit("--iocfile requires --ioctype")

    if args.iocfile and not os.path.isfile(args.iocfile):
        sys.exit('Supplied --iocfile is not a file')

    if (args.output or args.prefix) and args.no_file:
        sys.exit('--output and --prefix cannot be used with --no-file')

    if args.days and args.minutes:
        sys.exit('--days and --minutes are mutually exclusive')

    if args.sigmarule and not os.path.isfile(args.sigmarule):
        sys.exit('Supplied --sigmarule is not a file')

    if args.sigmadir and not os.path.isdir(args.sigmadir):
        sys.exit('Supplied --sigmadir is not a directory')

    definition_files = list()
    ioc_files = list()
    sigma_rules = list()

    # test if deffile exists
    # deffile can be resolved from 'definitions' folder without needing to specify path or extension
    if args.deffile:
        if not os.path.exists(args.deffile):
            repo_deffile: str = os.path.join(os.path.dirname(__file__), 'definitions', args.deffile)
            if not repo_deffile.endswith('.json'):
                repo_deffile = repo_deffile + '.json'

            if os.path.isfile(repo_deffile):
                args.deffile = repo_deffile
            else:
                sys.exit("The deffile doesn't exist. Please try again.")
        definition_files.append(args.deffile)

    # if --defdir add all files to list
    if args.defdir:
        if not os.path.exists(args.defdir):
            sys.exit("The defdir doesn't exist. Please try again.")
        else:
            for root_dir, dirs, files in os.walk(args.defdir):
                for filename in files:
                    if os.path.splitext(filename)[1] == '.json':
                        definition_files.append(os.path.join(root_dir, filename))

    if definition_files: survey_payload['definitions'] = definition_files

    # add sigmarule to list
    if args.sigmarule:
        sigma_rules.append(args.sigmarule)

    # if --sigmadir, add all files to sigma_rules list
    if args.sigmadir:
        for root_dir, dirs, files in os.walk(args.sigmadir):
            for filename in files:
                if os.path.splitext(filename)[1] == '.yml':
                    sigma_rules.append(os.path.join(root_dir, filename))

    if sigma_rules: survey_payload['sigma_rules'] = sigma_rules

    if args.iocfile:
        ioc_files.append(args.iocfile)

    # if --sigmadir, add all files to sigma_rules list
    if args.iocdir:
        for root_dir, dirs, files in os.walk(args.iocdir):
            for filename in files:
                if os.path.splitext(filename)[1] == '.txt':
                    ioc_files.append(os.path.join(root_dir, filename))

    if ioc_files: survey_payload.update({"ioc_list": ioc_files, "ioc_type": args.ioctype})

    survey_payload['product_args'] = product_args
    survey_payload['creds'] = creds

    survey_payload = {k:v for k,v in survey_payload.items() if v != None}
    return survey_payload

def logger(edr:str, logs_dir:str='logs') -> logging.Logger:
    # instantiate a logger
    log = logging.getLogger('surveyor')
    logging.debug(f'Product: {edr}')

    # configure logging
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers = list()  # remove all default handlers
    log_format = '[%(asctime)s] [%(levelname)-8s] [%(name)-36s] [%(filename)-20s:%(lineno)-4s] %(message)s'

    # create logging directory if it does not exist
    os.makedirs(logs_dir, exist_ok=True)

    # create logging file handler
    log_file_name = datetime.utcnow().strftime('%Y%m%d%H%M%S') + f'.{edr}.log'
    handler = logging.FileHandler(os.path.join(logs_dir, log_file_name))
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(log_format))
    root.addHandler(handler)
    
    return log

def check_product_args_structure(edr: str, product_args: dict) -> bool:
    """
    Check the structure of product arguments against supported arguments for the given EDR.
    
    Args:
        edr (str): The EDR identifier to check against.
        product_args (dict): A dictionary containing product arguments to check.
        
    Returns:
        bool: True if the product arguments are supported or empty, False otherwise.
    """
    
    unsupported_arguments = []
    supported_arguments = []
    
    if not product_args:
        return True
    
    for argument_key in product_args:
        if edr in EDR_SUPPORTED_ARGUMENTS:
            product_arguments = EDR_SUPPORTED_ARGUMENTS[edr]['product_arguments']
            if argument_key in product_arguments:
                supported_arguments.append(argument_key)
            else:
                unsupported_arguments.append(argument_key)
    
    if unsupported_arguments:
        unsupported_args_list = ', '.join(unsupported_arguments)
        supported_args_list = ', '.join(EDR_SUPPORTED_ARGUMENTS[edr]['product_arguments'])
        raise ValueError(f"You have provided the following unsupported product arguments for {edr}: {unsupported_args_list}. {edr} supports: {supported_args_list}. Execution Aborting.")
    
    return True

def check_credentials_structure(edr, creds: dict) -> bool:

    """
    Check the structure of provided credentials against supported credentials for the given EDR.
    
    This function verifies the presence of essential credential arguments required for execution.
    It ensures the necessary arguments are present, without validating the input values.
    
    Args:
        edr (str): The EDR identifier for which credentials are being checked.
        creds (dict): A dictionary containing credential arguments to be checked.
        
    Returns:
        bool: True if the provided credentials meet the necessary structure, False otherwise.
        
    Raises:
        ValueError: If the provided credentials for the EDR do not meet the required structure.
    """
    
    cred_check = [k for k, v in creds.items() if v]

    if (('creds_file' and 'profile') in cred_check) or ((edr in ["cbc", "cbr"]) and ('profile' in cred_check)):
        return True

    if edr in EDR_SUPPORTED_ARGUMENTS and EDR_SUPPORTED_ARGUMENTS[edr]['cred_check_logic'](cred_check):
        return True
    elif edr in EDR_SUPPORTED_ARGUMENTS:
        raise ValueError(f"Credentials for {edr} must include: {EDR_SUPPORTED_ARGUMENTS[edr]['credential_requirements']}")