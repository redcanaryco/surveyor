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
from typing import Optional, Tuple

# Application version

current_version = '2.5'

class Surveyor:
    table_template: Tuple[int, int, int, int, int, int] = (30, 30, 30, 30, 30, 30)
    table_template_str = f'{{:<{table_template[0]}}} ' \
                            f'{{:<{table_template[1]}}} ' \
                            f'{{:<{table_template[2]}}} ' \
                            f'{{:<{table_template[3]}}}'
    _log: logging.Logger = None
    _use_tqdm: bool = True
    _log_dir = str = "logs"
    _results_collector: list = None
    _output_format: str = "csv"
    _writer: csv.writer = None
    _raw = None
        
    def __init__(self):
        None
        
    def process_telemetry(
        self,
        edr: str,
        creds: dict,
        query: Optional[str] = None,
        definitions: Optional[list] = [],
        ioc_list: Optional[list] = [],
        ioc_type: Optional[str] = None,
        sigma_rules: Optional[list] = [],
        prefix: Optional[str] = None,
        hostname: Optional[str] = None,
        days: Optional[int] = None,
        minutes: Optional[int] = None,
        username: Optional[str] = None,
        namespace: Optional[str] = None,
        limit: Optional[int] = None,
        output: Optional[str] = None,
        output_format: Optional[str] = "csv",
        no_file: Optional[bool] = True,
        no_progress: Optional[bool] = False,
        log_dir: Optional[str] = "logs",
        product_args: Optional[dict] = {},
        raw: Optional[bool] = False
    ) -> list:
        
        if ioc_list and not ioc_type:
            sys.exit('keyword argument ioc_list requires type of ioc to be specified with one of the following [md5, ipaddr, or domain]')

        if ioc_type and not ioc_list:
            sys.exit('keyword argument ioc_type requires list of type associated indicators')

        if (output or prefix) and no_file:
            sys.exit('keyword arguments "output" and "prefix" cannot be used with "no_file"')

        if days and minutes:
            sys.exit('keyword arguments days and minutes are mutually exclusive')

        validation = check_credentials_structure(edr,creds)
        
        if validation == True:
            edr = edr
            creds = creds
        else:
            sys.exit(validation)

        #Instantiate a Logger
        self._log_dir = log_dir
        self._log = logger(edr, self._log_dir)
            
        #Update class variable
        self._output_format = output_format
        self._raw = raw
        # build arguments required for product class
        kwargs={}

        if limit: kwargs['limit'] = str(limit)
        if raw: kwargs['raw'] = raw

        kwargs['tqdm_echo'] = str(not no_progress)

        if product_args:
            check_product_args_structure(edr=edr, product_args=product_args) 
            kwargs.update(product_args)

        if creds:
            validation = check_credentials_structure(edr = edr, creds = creds)
            if validation == True:
                kwargs.update(creds)

        # instantiate a product class instance based on the product string
        try:
            product = get_product_instance(edr, **kwargs)
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
            self.table_template: Tuple[int, int, int, int, int, int] = (30, 30, 30, 30, 30, 30)
            self.table_template_str = f'{{:<{self.table_template[0]}}} ' \
                                    f'{{:<{self.table_template[1]}}} ' \
                                    f'{{:<{self.table_template[2]}}} ' \
                                    f'{{:<{self.table_template[3]}}}'
            if not raw: 
                print(self.table_template_str.format(*header))

        try:
            self._results_collector = [header] #A dd header to results collector.
            
            # Query
            if query:
                if raw:
                    self._results_collector = []
                    
                # if a query is specified run it directly
                log_echo(f"Running Custom Query: {query}", self._log)
                product.process_search(Tag('query'), base_query, query)
                
                for tag, results in product.get_results().items():
                    self._write_results(results, edr, query, "query", tag, namespace)
            
            # IOC
            if (ioc_list and ioc_type):
                are_files = [os.path.isfile(i) for i in ioc_list]
                if all(are_files): # if all items in the list are files
                    for ioc_file in ioc_list:
                        with open(ioc_file) as iocs:
                            basename = os.path.basename(ioc_file)
                            data = iocs.readlines()
                            log_echo(f"Processing IOC file: {iocs}", self._log)
                            iocs = [x.strip() for x in data]
                            
                            product.nested_process_search(Tag(f"IOC - {iocs}", data=basename), {ioc_type: iocs}, base_query)

                            for tag, results in product.get_results().items():
                                self._write_results(results, edr, basename, 'ioc', tag, namespace)

                elif not any(are_files): # if none of the items in the list are files, assume JSON definitions:
                    log_echo(f"Processing IOC list: {ioc_list}", self._log)
                    ioc_list = [x.strip() for x in ioc_list]

                    product.nested_process_search(Tag(f"IOC", data="ioc"), {ioc_type: ioc_list}, base_query)

                    for tag, results in product.get_results().items():
                        self._write_results(results, edr, "IOC", 'ioc', tag, namespace)

                else:
                    logging.error("There appears to be a mix of an IOC file and IOC's passed in directly to a python array. Cannot process a mixed list of values. Aborting.")

            # Sigma
            if sigma_rules:

                pq = True if product_args.get('deep_visibility', None) else False
                
                #If list of one or more sigma rules is provided, rule(s) will be translated.
                if sigma_rules:
                    translated_rules = sigma_translation(product=edr, sigma_rules=sigma_rules, pq=pq)
                    length = len(sigma_rules)

                if len(translated_rules['queries']) != length:
                    self._log.warning(f"Only {len(translated_rules['queries'])} out of {length} were able to be translated.")

                for rule in tqdm(translated_rules['queries'], desc="Processing sigma rules", disable=no_progress):
                    program = f"{rule['title']} - {rule['id']}"
                    source = 'Sigma Rule'

                    product.nested_process_search(Tag(program, data=source), {'query': [rule['query']]}, base_query)

                    if product.has_results():
                        # write results as they become available
                        for tag, nested_results in product.get_results(final_call=False).items():
                            self._write_results(nested_results, edr, program, str(tag.data), tag, namespace)

                        # ensure results are only written once
                        product.clear_results()

                # write any remaining results
                for tag, nested_results in product.get_results().items():
                    self._write_results(nested_results, edr, tag.tag, str(tag.data), tag, namespace)

            # Definition Files
            # run search against definition files and write to csv
            if definitions:
                are_files = [os.path.isfile(i) for i in definitions]

                if all(are_files): # if all items in the list are files

                    for definition in tqdm(definitions, desc='Processing definition files', disable=no_progress):
                        basename = os.path.basename(definition)
                        source = os.path.splitext(basename)[0]

                        with open(os.path.abspath(definition), 'r') as file:
                            programs = json.load(file)
                            for program, criteria in programs.items():
                                product.nested_process_search(Tag(program, data=source), criteria, base_query)

                                if product.has_results():
                                    # write results as they become available
                                    for tag, nested_results in product.get_results(final_call=False).items():
                                        self._write_results(nested_results,edr, program, str(tag.data), tag, namespace)

                                    # ensure results are only written once
                                    product.clear_results()

                    # write any remaining results
                    for tag, nested_results in product.get_results().items():
                        self._write_results(nested_results, edr, tag.tag, str(tag.data), tag, namespace)

                elif not any(are_files): # if none of the items in the list are files, assume JSON definitions
                    for definition in definitions:
                        for program, criteria in definition.items():
                            source = "Definition JSON"

                            product.nested_process_search(Tag(program, data=source), criteria, base_query)

                            if product.has_results():
                                # write results as they become available
                                for tag, nested_results in product.get_results(final_call=False).items():
                                    self._write_results(nested_results, edr, program, str(tag.data), tag, namespace)

                                # ensure results are only written once
                                product.clear_results()

                        # write any remaining results
                        for tag, nested_results in product.get_results().items():
                            self._write_results(nested_results, edr, tag.tag, str(tag.data), tag, namespace)
                else:
                    logging.error("There appears to be a mix of definition files and definition JSON objects. Cannot process a mixed list of values. Aborting.")

            #Output
            if output_file:
                
                if output_format == "json":
                    # Serializing json
                    json_object = json.dumps(self._results_collector, indent=4, default=str)

                    # Writing to sample.json
                    with open(file_name, "w") as outfile:
                        outfile.write(json_object)
                        
                log_echo(f"\033[95mResults saved: {output_file.name}\033[0m", self._log)

            if (raw and len(self._results_collector) > 0) or (len(self._results_collector) > 1):
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
                
    def _write_results(self, results: list[Result], edr, program: str, source: str, tag: Tag, namespace) -> None:
        
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
            if self._raw:
                self._results_collector.append(result)
            else:
                row = [result.hostname, result.username, result.path, result.command_line, program, source, edr]

                #Checking for optional addtions to add to output
                if namespace: row.append(namespace)
                if result.other_data: row.extend(result.other_data)
                    
                self._results_collector.append(row)
                
                if self._writer and self._output_format == 'csv':
                    self._writer.writerow(row)
                else:
                    print(self.table_template_str.format(*row))

if __name__ == "__main__":
    Surveyor().process_telemetry(**build_survey(sys.argv))