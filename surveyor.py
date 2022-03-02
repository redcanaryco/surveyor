import csv
import datetime
import json
import logging
import os
from typing import Optional, Union, Tuple

import click
from click import ClickException
from tqdm import tqdm

from common import Product
from help import log_echo, write_results
from load import get_product_instance, get_products

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help", "-what-am-i-doing"])

# Application version
current_version = "1.0"


def _list_products(ctx, _, value):
    """
    Print all implemented products to STDOUT.
    """
    if not value or ctx.resilient_parsing:
        return

    for product in get_products():
        click.echo(product)
    ctx.exit()


table_template: Tuple[int, int, int, int, int, int] = (30, 30, 30, 30, 30, 30)


def _write_results(output: Optional[csv.writer], results: list[Tuple[str, str, str, str]], program: str, source: str,
                   tag: Union[str, Tuple], log: logging.Logger):
    """
    Helper function for writing search results to CSV or STDOUT.
    """
    if output:
        if isinstance(tag, Tuple):
            tag = tag[0]

        if len(results) > 0:
            log_echo(f"\033[92m-->{tag}: {len(results)} results \033[0m", log)
        else:
            log_echo(f"-->{tag}: {len(results)} results", log)

    write_results(output, results, program, source, template=table_template)
    

# noinspection SpellCheckingInspection
@click.group("surveyor", context_settings=CONTEXT_SETTINGS, invoke_without_command=True, chain=False)
# list of all the different products we support
@click.option("--threathunter", 'product', help="Query Cb ThreatHunter.", flag_value="cbth", default=False)
@click.option("--response", 'product', help="Query Cb Response.", flag_value="cbr", default=False)
@click.option("--defender", 'product', help="Query Microsoft Defender for Endpoints", flag_value="defender",
              default=False)
@click.option("--atp", 'product', help="Query Microsoft Defender for Endpoints", flag_value="defender",
              default=False)
@click.option("--s1", 'product', help="Query SentinelOne", flag_value="s1", default=False)
@click.option('--product', 'custom_product', help="Query the specified product",
              type=click.Choice(list(get_products())))
@click.option("--creds", 'creds', help="Path to credential file for SentinelOne/Defender for Endpoints",
              type=click.Path(exists=True))
# filtering options
@click.option("--prefix", help="Output filename prefix.", type=click.STRING)
@click.option("--profile", help="The credentials profile to use.", type=click.STRING)
@click.option("--days", help="Number of days to search.", type=click.INT)
@click.option("--minutes", help="Number of minutes to search.", type=click.INT)
@click.option("--hostname", help="Target specific host by name.", type=click.STRING)
@click.option("--username", help="Target specific username.")
# different ways you can survey the EDR
@click.option("--deffile", 'def_file', help="Definition file to process (must end in .json).", type=click.STRING)
@click.option("--defdir", 'def_dir', help="Directory containing multiple definition files.", type=click.STRING)
@click.option("--query", help="A single query to execute.")
@click.option("--iocfile", 'ioc_file', help="IOC file to process. One IOC per line. REQUIRES --ioctype")
@click.option("--ioctype", 'ioc_type', help="One of: ipaddr, domain, md5")
# optional output
@click.option("--output", "--o", help="Specify the output file for the results. "
                                      "The default is create survey.csv in the current directory.")
@click.option("--no-file", help="Write results to STDOUT instead of the output CSV", is_flag=True, default=False)
@click.option("--no-progress", help="Suppress progress bar", is_flag=True, default=False)
@click.version_option(current_version)
@click.option('--products', default=False, is_flag=True, callback=_list_products, expose_value=False, is_eager=True)
@click.option("--log-dir", 'log_dir', help="Specify the logging directory.", type=click.STRING, default='logs')
@click.pass_context
def cli(ctx, prefix: Optional[str], hostname: Optional[str], profile: str, days: Optional[int], minutes: Optional[int],
        product: Optional[Union[str, Product]], custom_product: Optional[str], username: Optional[str],
        ioc_file: Optional[str], ioc_type: Optional[str], query: Optional[str], output: Optional[str],
        def_dir: Optional[str], def_file: Optional[str], creds: Optional[str], no_file: bool, no_progress: bool,
        log_dir: str):

    if not product and not custom_product:
        # default product is CBR
        product = 'cbr'
    elif not product:
        product = custom_product
    else:
        ctx.fail(f'Please specify either --product or one of --response/--defender/etc')

    # checks to ensure required parameters are present
    if (product == 'defender' or product == 's1') and not creds:
        # defender product requires credential file
        raise ClickException(f"\033[91m--creds required when using {product} product\033[0m")

    if ioc_file and ioc_type is None:
        ctx.fail("--iocfile requires --ioctype")

    if ioc_file and not os.path.isfile(ioc_file):
        ctx.fail(f'Supplied --iocfile is not a file')

    if (output or prefix) and no_file:
        ctx.fail('--output and --prefix cannot be used with --no-file')

    # instantiate a logger
    log = logging.getLogger('surveyor')
    logging.debug(f'Product: {product}')

    # configure logging
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers = list()  # remove all default handlers
    log_format = '[%(asctime)s] [%(levelname)-8s] [%(name)-36s] [%(filename)-20s:%(lineno)-4s] %(message)s'

    # create logging directory if it does not exist
    os.makedirs(log_dir, exist_ok=True)

    # create logging file handler
    log_file_name = datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S') + f'.{product}.log'
    handler = logging.FileHandler(os.path.join(log_dir, log_file_name))
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(log_format))
    root.addHandler(handler)

    # build arguments required for product class
    # must products only require the profile name
    kwargs = {
        'profile': profile
    }

    # add any custom required properties to kwargs
    if creds:
        kwargs['creds_file'] = creds

    # instantiate a product class instance based on the product string
    try:
        product = get_product_instance(product, **kwargs)
    except ValueError as e:
        log.exception(e)
        ctx.fail(str(e))

    # placeholder for definition files if --defdir or --deffile is selected
    definition_files = list()

    # base_query stores the filters applied to the product query
    # initial query is retrieved from product instance
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

    header = ["endpoint", "username", "process_path", "cmdline", "program", "source"]
    if not no_file:
        # determine output file name
        if output:
            file_name = output
        elif prefix:
            file_name = f'{prefix}-survey.csv'
        else:
            file_name = 'survey.csv'

        output_file = open(file_name, 'w', newline='')

        # create CSV writer and write the header row
        writer = csv.writer(output_file)
        writer.writerow(header)
    else:
        output_file = None
        writer = None
        no_progress = True
        template_str = f'{{:<{table_template[0]}}} {{:<{table_template[1]}}} {{:<{table_template[2]}}} ' \
                       f'{{:<{table_template[3]}}}'
        click.echo(template_str.format(*header))
    
    try:
        if query:
            # if a query is specified run it directly
            log_echo(f"Running Custom Query: {query}", log)
            product.process_search('query', base_query, query)

            for tag, results in product.get_results().items():
                _write_results(writer, results, query, "query", tag, log)

        # test if deffile exists
        # deffile can be resolved from 'definitions' folder without needing to specify path or extension
        if def_file:
            if not os.path.exists(def_file):
                repo_deffile: str = os.path.join(os.path.dirname(__file__), 'definitions', def_file)
                if not repo_deffile.endswith('.json'):
                    repo_deffile = repo_deffile + '.json'

                if os.path.isfile(repo_deffile):
                    log.debug(f'Using repo definition file {repo_deffile}')
                    def_file = repo_deffile
                else:
                    ctx.fail("The deffile doesn't exist. Please try again.")
            definition_files.append(def_file)

        # if --defdir add all files to list
        if def_dir:
            if not os.path.exists(def_dir):
                ctx.fail("The defdir doesn't exist. Please try again.")
            else:
                for root, dirs, files in os.walk(def_dir):
                    for filename in files:
                        if os.path.splitext(filename)[1] == '.json':
                            definition_files.append(os.path.join(root, filename))

        # run search based on IOC file
        if ioc_file:
            with open(ioc_file) as ioc_file:
                data = ioc_file.readlines()
                log_echo(f"Processing IOC file: {ioc_file}", log)

                for ioc in data:
                    ioc = ioc.strip()
                    base_query.update({ioc_type: ioc})
                    product.process_search(ioc, base_query, query)
                    del base_query[ioc_type]

                for tag, results in product.get_results().items():
                    _write_results(writer, results, ioc, 'ioc', tag, log)

        # run search against definition files and write to csv
        if def_file is not None or def_dir is not None:
            for definitions in tqdm(definition_files, desc='Processing definition files', disable=no_progress):
                basename = os.path.basename(definitions)
                source = os.path.splitext(basename)[0]

                with open(definitions, 'r') as file:
                    programs = json.load(file)
                    for program, criteria in programs.items():
                        product.nested_process_search((program, source), criteria, base_query)

            for (program, source), nested_results in product.get_results().items():
                _write_results(writer, nested_results, program, source, program, log)

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


if __name__ == "__main__":
    cli()
