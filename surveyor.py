import csv
import json
import os
from pprint import pprint

import click 
from click import ClickException

from common import EDRCommon

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help", "-what-am-i-doing"])
# Application version
current_version = "1.0"


@click.group("surveyor", context_settings=CONTEXT_SETTINGS, invoke_without_command=True,
             chain=False)
# @click.command("surveyor",context_settings=CONTEXT_SETTINGS)
# list of all the different products we support
@click.option("--threathunter", 'product', help="Use this to use Cb ThreatHunter.", flag_value="cbth", default=False)
@click.option("--response", 'product', help="Use this to use Cb Response.", flag_value="cbr", default=True)
@click.option("--defender", 'product', help="Use this to query Microsoft Defender for Endpoints", flag_value="defender", default=False)
@click.option("--atp", 'product', help="Use this to query Microsoft Defender for Endpoints", flag_value="defender", default=False)

@click.option("--creds", 'creds', help="Use this to define the path of the ini file with your ATP credentials", type=click.Path(exists=True))

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
@click.option("--output", "--o",
              help="Specify the output file for the results. The default is create survey.csv in the current directory.")
@click.version_option(current_version)
@click.pass_context
def cli(ctx, prefix, hostname, profile, days, minutes, product, username, iocfile, ioctype, query, output, defdir,
        deffile, creds):

    if product == "defender" and creds is None: 
        raise ClickException("\033[91m --atpcreds with the path of the INI file is required")
    # creates utility object with the profile and product to pass
    # sub functions to the correct product
    utils = EDRCommon(product, profile)

    # placeholder for definition files if --defdir or --deffile
    # is selected
    definition_files = []

    # this will build out or store the filter query based on the parameters
    # somehow needs to be modular and easy to add to and account for
    # different ways to do this via the different products`
    base_query = {}
    if username is not None:
        base_query.update({"username": username})
    if hostname is not None:
        base_query.update({"hostname": hostname})
    if days is not None:
        base_query.update({"days": days})
    if minutes is not None:
        base_query.update({"minutes": minutes})

    # create a single connection to the appropriate product
    # for use in our calls
    if product == "defender":
        conn = utils.get_connection_creds(creds)
    else: 
        conn = utils.get_connection()

    # set the output file
    if output:
        output_file = open(output, 'w', newline='')
    elif prefix:
        output_file = open(f'{prefix}-survey.csv', 'w', newline='')
    else:
        output_file = open('survey.csv', 'w', newline='')

    # write the header row
    writer = csv.writer(output_file)
    writer.writerow(["endpoint", "username", "process_path", "cmdline", "program", "source"])

    #if --query run the query and write results to the csv
    if query:
        click.echo(f"Running Query: {query}")
        results = utils.process_search(conn, query, base_query)
        utils.write_csv(writer, results, query, "query")

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
                click.echo(f"Processing IOC file: {iocfile}")
                for ioc in data:
                    ioc = ioc.strip()
                    query = f"{ioctype}:{ioc}"
                    results = utils.process_search(conn, query, base_query)
                    click.echo(f"-->{ioc}")
                    utils.write_csv(writer, results, ioc, 'ioc')

    # run search against definition files and write to csv
    if deffile is not None or defdir is not None:
        results_set = set()
        for definitions in definition_files:
            click.echo(f"\033[96m Processing definition file for {definitions} \033[0m")
            basename = os.path.basename(definitions)
            source = os.path.splitext(basename)[0]

            with open(definitions, 'r') as file:
                programs = json.load(file)
                for program, criteria in programs.items():
                    nested_results = utils.nested_process_search(criteria, conn, base_query)
                    if len(nested_results) > 0:
                        click.echo(f"\033[92m -->{program}: {len(nested_results)} results \033[0m")    
                    else:                     
                        click.echo(f"-->{program}: {len(nested_results)} results")
                    utils.write_csv(writer, nested_results, program, source)
                    results_set |= nested_results
    output_file.close()
    click.echo(f"\033[95m Results saved: {output_file.name} \033[0m")


if __name__ == "__main__":
    cli()
