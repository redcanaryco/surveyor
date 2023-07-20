import sys

# ensure Python version is compatible (Python v2 will always error out)
if sys.version_info.major == 3 and sys.version_info.minor < 9:
    print(f'Python 3.9+ is required to run Surveyor (current: {sys.version_info.major}.{sys.version_info.minor})')
    exit(1)

import os   
import csv
import json
import logging
from tqdm import tqdm
from help import log_echo, build_survey, logger, check_credentials_structure, check_product_args_structure, credential_builder, product_arg_builder
from common import Tag, Result, sigma_translation
from load import get_product_instance
from typing import Optional, Tuple, Any

# Application version

current_version = '2.5'

class Surveyor:
    
    _table_template: Tuple[int, int, int, int, int, int] = (30, 30, 30, 30, 30, 30)
    _table_template_str = f'{{:<{_table_template[0]}}} ' \
                             f'{{:<{_table_template[1]}}} ' \
                             f'{{:<{_table_template[2]}}} ' \
                             f'{{:<{_table_template[3]}}}'
    _edr: str = None
    _creds: dict = None
    _prefix: str = None
    _namespace: str = None
    _log: logging.Logger = None
    _use_tqdm: bool = True
    _log_dir = str = "logs"
    _results_collector: list = None
    _output_format: str = "csv"
    _writer: csv.writer = None
        
    def __init__(self, edr:str, creds:dict):
        validation = check_credentials_structure(edr,creds)
        
        if validation['result'] == True:
            self._edr = edr
            self._creds = creds
        else:
            sys.exit(validation)
            
    def survey(
        self,
        prefix: str = None,
        hostname: str = None,
        days: int = None,
        minutes: int = None,
        username: str = None,
        namespace: str = None,
        limit: int = None,
        ioc_file: list = None,
        ioc_list: list = None,
        ioc_source: str = "No Source Specified",
        ioc_type: str = None,
        query: str = None,
        output: str = None,
        output_format: str = "csv",
        definition: dict = {},
        definitions: list = [],
        def_source: str = "No Source Specified",
        sigma_rule: str = None,
        sigma_rules_str: str = None,
        sigma_rules: list = None,
        no_file: bool = True,
        no_progress: bool = False,
        log: logging.Logger = None,
        log_dir: str = "logs",
        product_args: dict = {},
        raw=False
    ) -> list:

        if definition and definitions:
            sys.exit("keywords arguments definitons and definition may not be used in the same survey. Select one.")
        if ioc_list and not ioc_type:
            sys.exit('keyword argument ioc_list requires type of ioc to be specified with one of the following [md5, ipaddr, or domain]')

        if ioc_type and not ioc_list:
            sys.exit('keyword argument ioc_type requires list of type associated indicators')

        if (output or prefix) and no_file:
            sys.exit('keyword arguments "output" and "prefix" cannot be used with "no_file"')

        if days and minutes:
            sys.exit('keyword arguments days and minutes are mutually exclusive')

        if (sigma_rules or sigma_rule or sigma_rules_str) and self._edr == 'cortex':
            sys.exit('sigmarules are not supported by edr "cortex"')

        if (sigma_rules or sigma_rule or sigma_rules_str) and self._edr == 's1' and product_args.get('deep_visibility', True) == False:
            sys.exit('sigmarules are not supported by SentinelOne PowerQuery')

        #Instantiate a Logger
        self._log_dir = log_dir
        if not log:
            log = logger(self._edr, self._log_dir)
            
        #Update class variables
        if prefix: self._prefix = prefix
        if namespace: self._namespace = namespace    
        self._log = log
        self._output_format = output_format
        
        # build arguments required for product class
        kwargs={}

        if limit: kwargs['limit'] = str(limit)
        if raw: kwargs['raw'] = raw

        kwargs['tqdm_echo'] = str(not no_progress)

        if product_args:
            validation = check_product_args_structure(edr=self._edr, product_args=product_args)
            required_fields = validation["required_fields"]
            if validation["result"] != True:
                sys.exit(f"Invalid products arguments provided for edr: {self._edr}, here were the keys provided {list(product_args.keys())}, here are the keys required for {self._edr}: {required_fields}")
            else:
                kwargs.update(product_args)

        if self._creds:
            validation = check_credentials_structure(edr = self._edr, creds = self._creds)
            required_fields = validation["required_fields"]
            if validation["result"] != True:
                sys.exit(f"Invalid credentials provided for edr: {self._edr}, here were the keys provided {list(self._creds.keys())}, here are the keys required for {self._edr}: {required_fields}. If you'd like, you can use the {self._edr+'_creds'} keyword arguement available to the survey function.")
            else:
                kwargs.update(self._creds)

        # instantiate a product class instance based on the product string
        try:
            product = get_product_instance(self._edr, **kwargs)
        except ValueError as e:
            self._log.exception(e)
            sys.exit(str(e))

        base_query = product.base_query()

        # add filters specified by user
        if username is not None:
            base_query.update({"username": username})

        if hostname is not None:
            base_query.update({"hostname": hostname})

        if days is not None:
            base_query.update({"days": days})

        if minutes is not None:
            base_query.update({"minutes": minutes})

        # default header, shared by all products 
        header = ["endpoint", "username", "process_path", "cmdline", "program", "source", "edr"]
        if prefix: header.append('prefix')
        if namespace: header.append('namespace')

        # add any additional rows that the current product includes to header
        header.extend(product.get_other_row_headers())

        if not no_file:
            # determine output file name
            if output and prefix:
                self._log.debug("Output arg takes precendence so prefix arg will be ignored")
            if output:
                file_name = output
            elif prefix:
                file_name = f'{prefix}-survey.{output_format}'
            else:
                file_name = f'survey.{output_format}'

            output_file = open(file_name, 'w', newline='', encoding='utf-8')
            
            if output_format == 'csv':
                # create CSV writer and write the header row
                self._writer = csv.writer(output_file)
                self._writer.writerow(header)
        else:
            output_file = None
            no_progress = True
            template_str = f'{{:<{self._table_template[0]}}} {{:<{self._table_template[1]}}} {{:<{self._table_template[2]}}} ' \
                            f'{{:<{self._table_template[3]}}}'
            if not raw: 
                print(template_str.format(*header))

        try:
            self._results_collector = [header] #A dd header to results collector.
            
            # Query
            if query:
                # if a query is specified run it directly
                log_echo(f"Running Custom Query: {query}", self._log)
                if raw:
                    raw_results = product.process_search(Tag('query'), base_query, query) # Returns data directly from API

                    if self._edr in ['cbr', 'cbc']: 
                        if len(raw_results) > 0:
                            log_echo(f"\033[92m-->query: {len(raw_results)} results \033[0m", self._log, use_tqdm=self._use_tqdm)
                        else:
                            log_echo(f"-->query: {len(raw_results)} results", self._log, use_tqdm=False)
                        return raw_results
                    
                    elif self._edr in ['cortex', 'dfe', 's1']:
                        self._results_collector = [] 
                        for tag, results in product.get_results().items():
                            self._results_collector.append(results)                    
                            if len(self._results_collector ) > 0:
                                log_echo(f"\033[92m-->query: {len(self._results_collector )} results \033[0m", self._log, use_tqdm=self._use_tqdm)
                            else:
                                log_echo(f"-->query: {len(self._results_collector )} results", self._log, use_tqdm=self._use_tqdm)
                                
                    if len(self._results_collector) > 1:
                         return self._results_collector
                    else:
                        return "No results"
                        
                else:
                    product.process_search(Tag('query'), base_query, query)
                
                for tag, results in product.get_results().items():
                    self._write_results(results, query, "query", tag)
            
            # IOC
            if ioc_list and (ioc_source and ioc_type):
                # run search based on IOC file

                    log_echo(f"Processing IOC list: {ioc_source}", self._log)
                    ioc_list = [x.strip() for x in ioc_list]

                    product.nested_process_search(Tag(f"IOC - {ioc_source}", data=ioc_source), {ioc_type: ioc_list}, base_query)

                    for tag, results in product.get_results().items():
                        self._write_results(results, ioc_source, 'ioc', tag)

            # Sigma
            if sigma_rule or sigma_rules or sigma_rules_str:
                 
                if sigma_rule:
                    sigma_rules.append(sigma_rule)

                #If list of one or more sigma rules is provided, rule(s) will be translated.
                if sigma_rules:
                    translated_rules = sigma_translation(product=self._edr, sigma_rules=sigma_rules, file=True)
                    length = len(sigma_rules)

            #If str of yaml containing one or more sigma rules is provided, rule(s) will be translated.
                elif sigma_rules_str:
                    translated_rules = sigma_translation(product=self._edr, sigma_rules=[sigma_rules_str], file=False)
                    length = len(translated_rules['queries'])

                if len(translated_rules['queries']) != length:
                    self._log.warning(f"Only {len(translated_rules['queries'])} out of {length} were able to be translated.")

                for rule in tqdm(translated_rules['queries'], desc="Processing sigma rules", disable=no_progress):
                    program = f"{rule['title']} - {rule['id']}"
                    source = 'Sigma Rule'

                    product.nested_process_search(Tag(program, data=source), {'query': [rule['query']]}, base_query)

                    if product.has_results():
                        # write results as they become available
                        for tag, nested_results in product.get_results(final_call=False).items():
                            self._write_results(nested_results, program, str(tag.data), tag)

                        # ensure results are only written once
                        product.clear_results()

                # write any remaining results
                for tag, nested_results in product.get_results().items():
                    self._write_results(nested_results, tag.tag, str(tag.data), tag)

            # Definition Files

            # run search against definition files and write to csv
            if definitions:
                if isinstance(definitions,list):
                    for _definition in tqdm(definitions, desc='Processing definition files', disable=no_progress):
                        basename = os.path.basename(_definition)
                        source = os.path.splitext(basename)[0]

                        with open(os.path.abspath(_definition), 'r') as file:
                            programs = json.load(file)
                            for program, criteria in programs.items():
                                product.nested_process_search(Tag(program, data=source), criteria, base_query)

                                if product.has_results():
                                    # write results as they become available
                                    for tag, nested_results in product.get_results(final_call=False).items():
                                        self._write_results(nested_results, program, str(tag.data), tag)

                                    # ensure results are only written once
                                    product.clear_results()

                    # write any remaining results
                    for tag, nested_results in product.get_results().items():
                        self._write_results(nested_results, tag.tag, str(tag.data), tag)
                else: 
                    sys.exit("The definitions argument must be a list of absolute paths to a JSON file")
            # Definition JSON

            if definition:
                for program, criteria in definition.items():
                    source = def_source

                    product.nested_process_search(Tag(program, data=source), criteria, base_query)

                    if product.has_results():
                        # write results as they become available
                        for tag, nested_results in product.get_results(final_call=False).items():
                            self._write_results(nested_results, program, str(tag.data), tag)

                        # ensure results are only written once
                        product.clear_results()

                # write any remaining results
                for tag, nested_results in product.get_results().items():
                    self._write_results(nested_results, tag.tag, str(tag.data), tag)

            #Output
            if output_file:
                
                if output_format == "json":
                    # Serializing json
                    json_object = json.dumps(self._results_collector, indent=4, default=str)

                    # Writing to sample.json
                    with open(file_name, "w") as outfile:
                        outfile.write(json_object)
                        
                log_echo(f"\033[95mResults saved: {output_file.name}\033[0m", self._log)

            if len(self._results_collector) > 1:
                 return self._results_collector
            else:
                return "No results"
        
        except KeyboardInterrupt:
            log_echo("Caught CTRL-C. Exiting...", self._log)

        except Exception as e:
            log_echo(f'Caught {type(e).__name__} (see log for details): {e}', self._log, logging.ERROR)
            self._log.exception(e)

        finally:
            if output_file:
                output_file.close()
                
    def _write_results(self, results: list[Result], program: str, source: str, tag: Tag) -> None:
        
        """
        Helper function for writing search results to CSV or STDOUT.
        """ 
        if isinstance(tag, tuple):
            tag = tag[0]
            
        if len(results) > 0:
            log_echo(f"\033[92m-->{tag.tag}: {len(results)} results \033[0m", self._log, use_tqdm=self._use_tqdm)
            
        else:
            log_echo(f"-->{tag.tag}: {len(results)} results", self._log, use_tqdm=self._use_tqdm)

        for result in results:
            row = [result.hostname, result.username, result.path, result.command_line, program, source, self._edr]

            #Checking for optional addtions to add to output
            if self._prefix: row.append(self._prefix)
            if self._namespace: row.append(self._namespace)
            if result.other_data: row.extend(result.other_data)
                
            self._results_collector.append(row)
            
            if self._writer and self._output_format == 'csv':
                self._writer .writerow(row)
                
            else:
                print(self._table_template_str.format(*row))

if __name__ == "__main__":
    
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", help="Output filename prefix.", type=str)
    parser.add_argument("--profile", help="The credentials profile to use.", type=str)
    days_minutes_group = parser.add_mutually_exclusive_group(required=False)
    days_minutes_group.add_argument("--days", help="Number of days to search.", type=int)
    days_minutes_group.add_argument("--minutes", help="Number of minutes to search.", type=int)
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
    parser.add_argument("--username", help="Target specific username.",  type=str)

    # different ways you can survey the EDR
    parser.add_argument("--deffile", help="Definition file to process (must end in .json).", type=os.path.abspath)
    parser.add_argument("--defdir", help="Directory containing multiple definition files.", type=os.path.abspath, default=None)
    parser.add_argument("--query", help="A single query to execute.", type=str)
    parser.add_argument("--iocfile", help="IOC file to process. One IOC per line. REQUIRES --ioctype", type=os.path.abspath, default=None)
    parser.add_argument("--ioctype", help="One of: ipaddr, domain, md5", choices=['ipaddr', 'domain', 'md5'])
    parser.add_argument("--iocsource", help=" The source of the IOCs specified in ioc_list.", type=str, default= None)
    parser.add_argument("--sigmarule", help="Sigma rule file to process (must be in YAML format).", type=os.path.abspath, default=None)
    parser.add_argument("--sigmadir", help='Directory containing multiple sigma rule files.', type=os.path.abspath, default=None)

    #required
    subparsers = parser.add_subparsers(help='sub-command help')
    edr_parser = subparsers.add_parser('edr', help="Specify EDR to be queried must be one of 'cbc', 'cbr', 'cortex', 'dfe', 's1'")
    edr_parser.add_argument('edr', choices=['cbc', 'cbr', 'cortex', 'dfe', 's1'])

    # optional output
    parser.add_argument("--creds", help="Absolute path to credential file", type=os.path.abspath, default=None)
    parser.add_argument("--output", "-o", help="Specify the output file for the results. The default is create survey.csv in the current directory.", type=os.path.abspath)
    parser.add_argument("--output-format", help="Specify the output file for the results. The default is create survey.csv in the current directory.", choices=['csv', 'json'], default='csv')
    parser.add_argument("--no-file", help="Write results to STDOUT instead of the output CSV", default=False)
    parser.add_argument("--no-progress", help="Suppress progress bar", default=False)


    # logging options
    parser.add_argument("--log-dir", help="Specify the logging directory.", type=os.path.abspath, default='logs')

    # Cortex options
    cortex_group = parser.add_argument_group('Optional Cortex XDR Parameters')
    cortex_group.add_argument("--auth-type", help="Cortex XDR authentication type (standard or advanced). Default is standard", type=str, default='standard')
    cortex_group.add_argument("--tenant-ids", help="Space delimited list of Cortex XDR tenant IDs", type=str, nargs='+', default=None)


    # S1 options
    s1_group = parser.add_argument_group('Optional S1 parameters')
    s1_group.add_argument("--site-ids", help="ID of SentinelOne site to query", type=str, nargs='+', default=None)
    s1_group.add_argument("--account-ids", help="ID of SentinelOne account to query", type=str, nargs='+', default=None)
    s1_group.add_argument("--account-names", help="Name of SentinelOne account to query", type=str, nargs='+', default=None)
    s1_group.add_argument("--dv", help="Use Deep Visibility for queries", action='store_true', default=False)

    # CbC options
    cbc_group = parser.add_argument_group('Optional VMware Cb Enterprise EDR Parameters')
    cbc_group.add_argument("--device-group", help="Name of device group to query", type=str, nargs='+', default=None)
    cbc_group.add_argument("--device-policy", help="Name of device policy to query", type=str, nargs='+', default=None)

    # CbR Options
    cbr_group = parser.add_argument_group('Optional VMware Cb Response Parameters')
    cbr_group.add_argument("--sensor-group", help="Name of sensor group to query", type=str, nargs='+', default=None)

    # DFE options
    dfe_group = parser.add_argument_group('Optional Microsoft Defender for Endpoints Parameters') # None currently

    args = parser.parse_args()
    
    args.product_args = product_arg_builder(args)
    args.creds = credential_builder(args)
    
    #Run Surveyor
    Surveyor(args.edr,args.creds).survey(**build_survey(args, args.edr))