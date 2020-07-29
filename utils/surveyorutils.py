from pprint import pprint

import click
from cbapi import CbEnterpriseResponseAPI, CbThreatHunterAPI

from products import response as cbr, threathunter as cbth


class SurveyorUtils:
    def __init__(self, product, profile):
        self.product = product
        self.profile = profile

    def validate_input(self, query, hostname, username):
        if hostname and 'hostname' in query:
            click.echo('Cannot use --hostname with "hostname:" (in query)')
            return False
        elif username and 'username' in query:
            click.echo('Cannot use --username with "username:" (in query)')
            return False
        else:
            return True

    # Build the query based on the product that was chosen
    def base_query(self, *args):
        if self.product == "cbr":
            return cbr.build_query(*args)

        elif self.product == "cbth":
            return args


    # Search based on the product that was chosen
    def process_search(self, cb_conn, base_query, query):
        if self.product == "cbr":
            return cbr.process_search(cb_conn, query, base_query)

        elif self.product == "cbth":
            return cbth.process_search(cb_conn, query, base_query)

    # If defdir or deffiles were given run the appropriate search based on the product
    def nested_process_search(self, criteria, cb_conn, base_query):
        if self.product == "cbr":
            return cbr.nested_process_search(cb_conn, criteria, base_query)

        elif self.product == "cbth":
            return cbth.nested_process_search(cb_conn, criteria, base_query)

    # write the rows of the CSV
    def write_csv(self, output, results, *args):
        for r in results:
            row = [r[0], r[1], r[2], r[3], args[0], args[1]]
            output.writerow(row)

    def get_cbapi_connection(self):
        if self.product == 'cbr':
            if self.profile:
                cb_conn = CbEnterpriseResponseAPI(profile=self.profile)
            else:
                cb_conn = CbEnterpriseResponseAPI()

        elif self.product == 'cbth':
            if self.profile:
                cb_conn = CbThreatHunterAPI(profile=self.profile)
            else:
                cb_conn = CbThreatHunterAPI()
        return cb_conn