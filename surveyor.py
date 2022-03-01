import csv
import json
import logging
import os
import re
from typing import Tuple

import click
from click import ClickException

from common import Product
from load import get_product_instance, get_products

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help", "-what-am-i-doing"])

# Application version
current_version = "1.0"

# regular expression that detects ANSI color codes
ansi_escape_regex = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', re.VERBOSE)


def _list_products(ctx, _, value):
    """
    Print all implemented products to STDOUT.
    """
    if not value or ctx.resilient_parsing:
        return

    for product in get_products():
        click.echo(product)
    ctx.exit()


def _strip_ansi_codes(message: str) -> str:
    """
    Strip ANSI sequences from a log string
    """
    return ansi_escape_regex.sub('', message)


def _log_echo(message: str, log: logging.Logger):
    """
    Write a command to STDOUT and the debug log stream.
    """
    click.echo(message)

    # strip ANSI sequences from log string
    log.debug(_strip_ansi_codes(message))


def _write_csv(output: csv.writer, results: list[Tuple[str, str, str, str]], program: str, source: str):
    """
    Write results to output CSV.
    """
    for hostname, username, path, command_line in results:
        row = [hostname, username, path, command_line, program, source]
        output.writerow(row)


# noinspection SpellCheckingInspection
@click.group("surveyor", context_settings=CONTEXT_SETTINGS, invoke_without_command=True, chain=False)
# list of all the different products we support
@click.option("--threathunter", 'product', help="Use this to use Cb ThreatHunter.", flag_value="cbth", default=False)
@click.option("--response", 'product', help="Use this to use Cb Response.", flag_value="cbr", default=True)
@click.option("--defender", 'product', help="Use this to query Microsoft Defender for Endpoints", flag_value="defender",
              default=False)
@click.option("--atp", 'product', help="Use this to query Microsoft Defender for Endpoints", flag_value="defender",
              default=False)
@click.option("--creds", 'creds', help="Use this to define the path of the ini file with your ATP credentials",
              type=click.Path(exists=True))
# filtering options
@click.option("--prefix", help="Output filename prefix.", type=click.STRING)
@click.option("--profile", help="The credentials profile to use.", type=click.STRING)
@click.option("--days", help="Number of days to search.", type=click.INT)
@click.option("--minutes", help="Number of minutes to search.", type=click.INT)
@click.option("--hostname", help="Target specific host by name.", type=click.STRING)
@click.option("--username", help="Target specific username.")
# different ways you can survey the EDR
@click.option("--deffile", help="Definition file to process (must end in .json).", type=click.STRING)
@click.option("--defdir", help="Directory containing multiple definition files.", type=click.STRING)
@click.option("--query", help="A single query to execute.")
@click.option("--iocfile", help="IOC file to process. One IOC per line. REQUIRES --ioctype")
@click.option("--ioctype", help="One of: ipaddr, domain, md5")
# optional output
@click.option("--output", "--o", help="Specify the output file for the results. "
                                      "The default is create survey.csv in the current directory.")
@click.version_option(current_version)
@click.option('--products', default=False, is_flag=True, callback=_list_products, expose_value=False, is_eager=True)
@click.pass_context
def cli(ctx, prefix, hostname, profile, days, minutes, product, username, iocfile, ioctype, query, output, defdir,
        deffile, creds):
    # instantiate a logger
    log = logging.getLogger('surveyor')
    logging.debug(f'Product: {product}')

    # perform checks to ensure required parameters are present
    if product == "defender" and creds is None:
        # defender product requires credential file
        raise ClickException("\033[91m--creds required when using 'defender' platform\033[0m")

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
        product: Product = get_product_instance(product, **kwargs)
    except ValueError as e:
        log.exception(e)
        click.echo(str(e))
        ctx.exit()

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

    # determine output file name
    if output:
        file_name = output
    elif prefix:
        file_name = f'{prefix}-survey.csv'
    else:
        file_name = 'survey.csv'

    with open(file_name, 'w', newline='') as output_file:
        # care CSV writer and write the header row
        writer = csv.writer(output_file)
        writer.writerow(["endpoint", "username", "process_path", "cmdline", "program", "source"])

        # if --query run the query and write results to the csv
        if query:
            _log_echo(f"Running Query: {query}", log)
            results = product.process_search(query, base_query)

            _write_csv(writer, results, query, "query")

        # if --deffile add file to list
        elif deffile:
            if not os.path.exists(deffile):
                ctx.fail("The deffile doesn't exist. Please try again.")
            definition_files.append(deffile)

        # if --defdir add all files to list
        elif defdir:
            if not os.path.exists(defdir):
                ctx.fail("The defdir doesn't exist. Please try again.")
            else:
                for root, dirs, files in os.walk(defdir):
                    for filename in files:
                        if os.path.splitext(filename)[1] == '.json':
                            # if filename.endswith('.json'):
                            definition_files.append(os.path.join(root, filename))

        # if --iocfile run search for iocs
        elif iocfile:
            if ioctype is None:
                ctx.fail("[!] --iocfile requires --ioctype")
            else:
                with open(iocfile) as iocfile:
                    data = iocfile.readlines()
                    _log_echo(f"Processing IOC file: {iocfile}", log)

                    for ioc in data:
                        ioc = ioc.strip()
                        query = f"{ioctype}:{ioc}"
                        results = product.process_search(query, base_query)
                        _log_echo(f"-->{ioc}", log)
                        _write_csv(writer, results, ioc, 'ioc')

        # run search against definition files and write to csv
        if deffile is not None or defdir is not None:
            results_set = set()
            for definitions in definition_files:
                _log_echo(f"\033[96m Processing definition file for {definitions} \033[0m", log)

                basename = os.path.basename(definitions)
                source = os.path.splitext(basename)[0]

                with open(definitions, 'r') as file:
                    programs = json.load(file)
                    for program, criteria in programs.items():
                        nested_results = product.nested_process_search(criteria, base_query)

                        if len(nested_results) > 0:
                            _log_echo(f"\033[92m-->{program}: {len(nested_results)} results \033[0m", log)
                        else:
                            _log_echo(f"-->{program}: {len(nested_results)} results", log)

                        _write_csv(writer, nested_results, program, source)
                        results_set |= nested_results

        _log_echo(f"\033[95mResults saved: {output_file.name}\033[0m", log)


if __name__ == "__main__":
    cli()
