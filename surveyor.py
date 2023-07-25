import sys

# ensure Python version is compatible (Python v2 will always error out)
if sys.version_info.major == 3 and sys.version_info.minor < 9:
    print(f'Python 3.9+ is required to run Surveyor (current: {sys.version_info.major}.{sys.version_info.minor})')
    exit(1)

import csv
import dataclasses
import datetime
import json
import logging
import os
from typing import Optional, Tuple, Callable, Any

import click
from tqdm import tqdm

from common import Tag, Result, sigma_translation
from help import log_echo
from load import get_product_instance, get_products


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help", "-what-am-i-doing"])

# Application version
current_version = "2.5.0"


def _list_products(ctx, _, value) -> None:
    """
    Print all implemented products to STDOUT.
    """
    if not value or ctx.resilient_parsing:
        return

    for product in get_products():
        click.echo(product)
    ctx.exit()


table_template: Tuple[int, int, int, int, int, int] = (30, 30, 30, 30, 30, 30)
table_template_str = f'{{:<{table_template[0]}}} ' \
                     f'{{:<{table_template[1]}}} ' \
                     f'{{:<{table_template[2]}}} ' \
                     f'{{:<{table_template[3]}}}'


def _write_results(output: Optional[Any], results: list[Result], program: str, source: str,
                   tag: Tag, log: logging.Logger, use_tqdm: bool = False) -> None:
    """
    Helper function for writing search results to CSV or STDOUT.
    """
    if output:
        if isinstance(tag, tuple):
            tag = tag[0]

        if len(results) > 0:
            log_echo(f"\033[92m-->{tag.tag}: {len(results)} results \033[0m", log, use_tqdm=use_tqdm)
        else:
            log_echo(f"-->{tag.tag}: {len(results)} results", log, use_tqdm=use_tqdm)

    for result in results:
        row = [result.hostname, result.username, result.path, result.command_line, program, source]

        if output:
            if result.other_data:
                row.extend(result.other_data)

            output.writerow(row)
        else:
            # trim data to make sure it fits into table format
            for i in range(len(row)):
                if len(row[i]) > table_template[i]:
                    row[i] = row[i][:table_template[i] - 3] + '...'

            click.echo(table_template_str.format(*row))


@dataclasses.dataclass
class ExecutionOptions:
    prefix: Optional[str]
    hostname: Optional[str]
    profile: str
    days: Optional[int]
    minutes: Optional[int]
    username: Optional[str]
    limit: Optional[int]
    ioc_file: Optional[str]
    ioc_type: Optional[str]
    query: Optional[str]
    output: Optional[str]
    def_dir: Optional[str]
    def_file: Optional[str]
    sigma_rule: Optional[str]
    sigma_dir: Optional[str]
    no_file: bool
    no_progress: bool
    log_dir: str
    product_args: dict


# noinspection SpellCheckingInspection
@click.group("surveyor", context_settings=CONTEXT_SETTINGS, invoke_without_command=True, chain=False)
# filtering options
@click.option("--prefix", help="Output filename prefix.", type=click.STRING)
@click.option("--profile", help="The credentials profile to use.", type=click.STRING)
@click.option("--days", help="Number of days to search.", type=click.INT)
@click.option("--minutes", help="Number of minutes to search.", type=click.INT)
@click.option("--limit",help="""
              Number of results to return. Cortex XDR: Default: 1000, Max: Default
              Microsoft Defender for Endpoint: Default/Max: 100000
              SentinelOne (PowerQuery): Default/Max: 1000
              SentinelOne (Deep Visibility): Default/Max: 20000
              VMware Carbon Black EDR: Default/Max: None
              VMware Carbon Black Cloud Enterprise EDR: Default/Max: None
              
              Note: Exceeding the maximum limits will automatically set the limit to its maximum value, where applicable.
              """
              , type=click.INT)
@click.option("--hostname", help="Target specific host by name.", type=click.STRING)
@click.option("--username", help="Target specific username.")
# different ways you can survey the EDR
@click.option("--deffile", 'def_file', help="Definition file to process (must end in .json).", type=click.STRING)
@click.option("--defdir", 'def_dir', help="Directory containing multiple definition files.", type=click.STRING)
@click.option("--query", help="A single query to execute.")
@click.option("--iocfile", 'ioc_file', help="IOC file to process. One IOC per line. REQUIRES --ioctype")
@click.option("--ioctype", 'ioc_type', help="One of: ipaddr, domain, md5")
@click.option("--sigmarule", 'sigma_rule', help="Sigma rule file to process (must be in YAML format).", type=click.STRING)
@click.option("--sigmadir", 'sigma_dir', help='Directory containing multiple sigma rule files.', type=click.STRING)
# optional output
@click.option("--output", "--o", help="Specify the output file for the results. "
                                      "The default is create survey.csv in the current directory.")
@click.option("--no-file", help="Write results to STDOUT instead of the output CSV", is_flag=True, default=False)
@click.option("--no-progress", help="Suppress progress bar", is_flag=True, default=False)
# version option
@click.version_option(current_version)
# logging options
@click.option("--log-dir", 'log_dir', help="Specify the logging directory.", type=click.STRING, default='logs')
@click.pass_context
def cli(ctx, prefix: Optional[str], hostname: Optional[str], profile: str, days: Optional[int], minutes: Optional[int],
        username: Optional[str], limit: Optional[int],
        ioc_file: Optional[str], ioc_type: Optional[str], query: Optional[str], output: Optional[str],
        def_dir: Optional[str], def_file: Optional[str], no_file: bool, no_progress: bool,
        sigma_rule: Optional[str], sigma_dir: Optional[str],
        log_dir: str) -> None:

    ctx.ensure_object(dict)
    ctx.obj = ExecutionOptions(prefix, hostname, profile, days, minutes, username, limit, ioc_file, ioc_type, query, output,
                               def_dir, def_file, sigma_rule, sigma_dir, no_file, no_progress, log_dir, dict())

    if ctx.invoked_subcommand is None:
        survey(ctx, 'cbr')


# Cortex options
@cli.command('cortex', help="Query Cortex XDR")
@click.option("--creds", 'creds', help="Path to credential file", type=click.Path(exists=True), required=True)
@click.pass_context
def cortex(ctx, creds: Optional[str]) -> None:
    ctx.obj.product_args = {
        'creds_file': creds
    }

    survey(ctx, 'cortex')


# S1 options
@cli.command('s1', help="Query SentinelOne")
@click.option("--site-id", help="ID of SentinelOne site to query", multiple=True, default=None)
@click.option("--account-id", help="ID of SentinelOne account to query", multiple=True, default=None)
@click.option("--account-name", help="Name of SentinelOne account to query", multiple=True, default=None)
@click.option("--creds", 'creds', help="Path to credential file", type=click.Path(exists=True), required=True)
@click.option("--dv", 'dv', help="Use Deep Visibility for queries", is_flag=True, required=False)
@click.pass_context
def s1(ctx, site_id: Optional[Tuple], account_id: Optional[Tuple], account_name: Optional[Tuple], creds: Optional[str],
       dv: bool) -> None:
    ctx.obj.product_args = {
        'creds_file': creds,
        'site_id': list(site_id) if site_id else None,
        'account_id': list(account_id) if account_id else None,
        'account_name': list(account_name) if account_name else None,
        'pq': not dv
    }

    survey(ctx, 's1')


# CbC options
@cli.command('cbc', help="Query VMware Cb Enterprise EDR")
@click.option("--device-group", help="Name of device group to query", multiple=True, default=None)
@click.option("--device-policy", help="Name of device policy to query", multiple=True, default=None)
@click.pass_context
def cbc(ctx, device_group: Optional[Tuple], device_policy: Optional[Tuple]) -> None:
    ctx.obj.product_args = {
        'device_group': list(device_group) if device_group else None,
        'device_policy': list(device_policy) if device_policy else None
    }

    survey(ctx, 'cbc')


# CbR Options
@cli.command('cbr', help="Query VMware Cb Response")
@click.option("--sensor-group", help="Name of sensor group to query", multiple=True, default=None)
@click.pass_context
def cbr(ctx, sensor_group: Optional[Tuple]) -> None:
    ctx.obj.product_args = {
        'sensor_group': list(sensor_group) if sensor_group else None
    }
    survey(ctx, 'cbr')


# DFE options
@cli.command('dfe', help="Query Microsoft Defender for Endpoints")
@click.option("--creds", 'creds', help="Path to credential file", type=click.Path(exists=True), required=True)
@click.pass_context
def dfe(ctx, creds: Optional[str]) -> None:
    ctx.obj.product_args = {'creds_file': creds}
    survey(ctx, 'dfe')


def survey(ctx, product_str: str = 'cbr') -> None:
    ctx.ensure_object(ExecutionOptions)
    opt: ExecutionOptions = ctx.obj

    if opt.ioc_file and opt.ioc_type is None:
        ctx.fail("--iocfile requires --ioctype")

    if opt.ioc_file and not os.path.isfile(opt.ioc_file):
        ctx.fail('Supplied --iocfile is not a file')

    if (opt.output or opt.prefix) and opt.no_file:
        ctx.fail('--output and --prefix cannot be used with --no-file')

    if opt.days and opt.minutes:
        ctx.fail('--days and --minutes are mutually exclusive')

    if (opt.sigma_rule or opt.sigma_dir) and product_str == 'cortex':
        ctx.fail('Neither --sigmarule nor --sigmadir are supported by product "cortex"')

    if (opt.sigma_rule or opt.sigma_dir) and product_str == 's1' and opt.product_args['pq']:
        ctx.fail('Neither --sigmarule nor --sigmadir are supported by SentinelOne PowerQuery')

    if opt.sigma_rule and not os.path.isfile(opt.sigma_rule):
        ctx.fail('Supplied --sigmarule is not a file')

    if opt.sigma_dir and not os.path.isdir(opt.sigma_dir):
        ctx.fail('Supplied --sigmadir is not a directory')

    # instantiate a logger
    log = logging.getLogger('surveyor')
    logging.debug(f'Product: {product_str}')

    # configure logging
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers = list()  # remove all default handlers
    log_format = '[%(asctime)s] [%(levelname)-8s] [%(name)-36s] [%(filename)-20s:%(lineno)-4s] %(message)s'

    # create logging directory if it does not exist
    os.makedirs(opt.log_dir, exist_ok=True)

    # create logging file handler
    log_file_name = datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S') + f'.{product_str}.log'
    handler = logging.FileHandler(os.path.join(opt.log_dir, log_file_name))
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(log_format))
    root.addHandler(handler)

    # build arguments required for product class
    # must products only require the profile name
    kwargs = {
        'profile': opt.profile
    }

    if len(opt.product_args) > 0:
        kwargs.update(opt.product_args)

    if opt.limit:
        kwargs['limit'] = str(opt.limit)


    kwargs['tqdm_echo'] = str(not opt.no_progress)

    # instantiate a product class instance based on the product string
    try:
        product = get_product_instance(product_str, **kwargs)
    except ValueError as e:
        log.exception(e)
        ctx.fail(str(e))

    # placeholder for definition files if --defdir or --deffile is selected
    definition_files = list()

    # base_query stores the filters applied to the product query
    # initial query is retrieved from product instance
    base_query = product.base_query()

    # placeholder for sigma rules if --sigmarule or --sigmadir is selected
    sigma_rules = list()

    # add filters specified by user
    if opt.username is not None:
        base_query.update({"username": opt.username})

    if opt.hostname is not None:
        base_query.update({"hostname": opt.hostname})

    if opt.days is not None:
        base_query.update({"days": opt.days})

    if opt.minutes is not None:
        base_query.update({"minutes": opt.minutes})

    # default header, shared by all products
    header = ["endpoint", "username", "process_path", "cmdline", "program", "source"]

    # add any additional rows that the current product includes to header
    header.extend(product.get_other_row_headers())

    if not opt.no_file:
        # determine output file name
        if opt.output and opt.prefix:
            log.debug("Output arg takes precendence so prefix arg will be ignored")
        if opt.output:
            file_name = opt.output
        elif opt.prefix:
            file_name = f'{opt.prefix}-survey.csv'
        else:
            file_name = 'survey.csv'

        output_file = open(file_name, 'w', newline='', encoding='utf-8')

        # create CSV writer and write the header row
        writer = csv.writer(output_file)
        writer.writerow(header)
    else:
        output_file = None
        writer = None
        opt.no_progress = True
        template_str = f'{{:<{table_template[0]}}} {{:<{table_template[1]}}} {{:<{table_template[2]}}} ' \
                       f'{{:<{table_template[3]}}}'
        click.echo(template_str.format(*header))

    try:
        if opt.query:
            # if a query is specified run it directly
            log_echo(f"Running Custom Query: {opt.query}", log)
            product.process_search(Tag('query'), base_query, opt.query)

            for tag, results in product.get_results().items():
                _write_results(writer, results, opt.query, "query", tag, log)

        # test if deffile exists
        # deffile can be resolved from 'definitions' folder without needing to specify path or extension
        if opt.def_file:
            if not os.path.exists(opt.def_file):
                repo_deffile: str = os.path.join(os.path.dirname(__file__), 'definitions', opt.def_file)
                if not repo_deffile.endswith('.json'):
                    repo_deffile = repo_deffile + '.json'

                if os.path.isfile(repo_deffile):
                    log.debug(f'Using repo definition file {repo_deffile}')
                    opt.def_file = repo_deffile
                else:
                    ctx.fail("The deffile doesn't exist. Please try again.")
            definition_files.append(opt.def_file)

        # add sigma_rule to list
        if opt.sigma_rule:
            sigma_rules.append(opt.sigma_rule)

        # if --defdir add all files to list
        if opt.def_dir:
            if not os.path.exists(opt.def_dir):
                ctx.fail("The defdir doesn't exist. Please try again.")
            else:
                for root_dir, dirs, files in os.walk(opt.def_dir):
                    for filename in files:
                        if os.path.splitext(filename)[1] == '.json':
                            definition_files.append(os.path.join(root_dir, filename))

        # if --sigma_dir, add all files to sigma_rules list
        if opt.sigma_dir:
            for root_dir, dirs, files in os.walk(opt.sigma_dir):
                for filename in files:
                    if os.path.splitext(filename)[1] == '.yml':
                        sigma_rules.append(os.path.join(root_dir, filename))

        # run search based on IOC file
        if opt.ioc_file:
            with open(opt.ioc_file) as ioc_file:
                basename = os.path.basename(opt.ioc_file)
                data = ioc_file.readlines()
                log_echo(f"Processing IOC file: {opt.ioc_file}", log)

                ioc_list = [x.strip() for x in data]

                product.nested_process_search(Tag(f"IOC - {opt.ioc_file}", data=basename), {opt.ioc_type: ioc_list}, base_query)

                for tag, results in product.get_results().items():
                    _write_results(writer, results, opt.ioc_file, 'ioc', tag, log)

        # run search against definition files and write to csv
        if opt.def_file is not None or opt.def_dir is not None:
            for definitions in tqdm(definition_files, desc='Processing definition files', disable=opt.no_progress):
                basename = os.path.basename(definitions)
                source = os.path.splitext(basename)[0]

                with open(definitions, 'r') as file:
                    programs = json.load(file)
                    for program, criteria in programs.items():
                        product.nested_process_search(Tag(program, data=source), criteria, base_query)

                        if product.has_results():
                            # write results as they become available
                            for tag, nested_results in product.get_results(final_call=False).items():
                                _write_results(writer, nested_results, program, str(tag.data), tag, log,
                                               use_tqdm=True)

                            # ensure results are only written once
                            product.clear_results()

            # write any remaining results
            for tag, nested_results in product.get_results().items():
                _write_results(writer, nested_results, tag.tag, str(tag.data), tag, log)

        # if there's sigma rules to be processed
        if len(sigma_rules) > 0:
            translated_rules = sigma_translation(product_str, sigma_rules)
            if len(translated_rules['queries']) != len(sigma_rules):
                log.warning(f"Only {len(translated_rules['queries'])} out of {len(sigma_rules)} were able to be translated.")
            for rule in tqdm(translated_rules['queries'], desc="Processing sigma rules", disable=opt.no_progress):
                program = f"{rule['title']} - {rule['id']}"
                source = 'Sigma Rule'

                product.nested_process_search(Tag(program, data=source), {'query': [rule['query']]}, base_query)

                if product.has_results():
                    # write results as they become available
                    for tag, nested_results in product.get_results(final_call=False).items():
                        _write_results(writer, nested_results, program, str(tag.data), tag, log,
                                       use_tqdm=True)

                    # ensure results are only written once
                    product.clear_results()

            # write any remaining results
            for tag, nested_results in product.get_results().items():
                _write_results(writer, nested_results, tag.tag, str(tag.data), tag, log)

        if output_file:
            log_echo(f"\033[95mResults saved: {output_file.name}\033[0m", log)
    except KeyboardInterrupt:
        log_echo("Caught CTRL-C. Exiting...", log)
    except Exception as e:
        log_echo(f'Caught {type(e).__name__} (see log for details): {e}', log, logging.ERROR)
        log.exception(e)
    finally:
        if output_file:
            output_file.close()


def create_generic_product_command(name: str) -> Callable:
    @click.pass_context
    def command(ctx):
        survey(ctx, name)

    command.__name__ = name
    return command


# create click commands for all products that don't have a command function defined
for product_name in get_products():
    dir_res = dir()
    if product_name not in dir_res:
        cli.command(name=product_name, help=f'Query {product_name}')(create_generic_product_command(str(product_name)))

if __name__ == "__main__":
    cli()