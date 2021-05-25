from pprint import pprint

import click
from cbapi import CbEnterpriseResponseAPI, CbThreatHunterAPI
import urllib.request
import urllib.parse
import json
import configparser 

from products import vmware_cb_response as cbr, vmware_cb_enterprise_edr as cbth, microsoft_defender_for_endpoints as defender


class EDRCommon:
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

        elif self.product == "defender":
            return defender.build_query(*args)


    # Search based on the product that was chosen
    def process_search(self, conn, base_query, query):
        if self.product == "cbr":
            return cbr.process_search(conn, query, base_query)

        elif self.product == "cbth":
            return cbth.process_search(conn, query, base_query)
        
        elif self.product == "defender":
            return defender.process_search(conn, query, base_query)

    # If defdir or deffiles were given run the appropriate search based on the product
    def nested_process_search(self, criteria, cb_conn, base_query):
        if self.product == "cbr":
            return cbr.nested_process_search(cb_conn, criteria, base_query)

        elif self.product == "cbth":
            return cbth.nested_process_search(cb_conn, criteria, base_query)
        
        elif self.product == "defender": 
            return defender.nested_process_search(cb_conn, criteria, base_query)

    # write the rows of the CSV
    def write_csv(self, output, results, *args):
        for r in results:
            row = [r[0], r[1], r[2], r[3], args[0], args[1]]
            output.writerow(row)

    def get_connection(self):
        if self.product == 'cbr':
            if self.profile:
                cb_conn = CbEnterpriseResponseAPI(profile=self.profile)
            else:
                cb_conn = CbEnterpriseResponseAPI()

            return cb_conn

        elif self.product == 'cbth':
            if self.profile:
                cb_conn = CbThreatHunterAPI(profile=self.profile)
            else:
                cb_conn = CbThreatHunterAPI()
            
            return cb_conn

    def get_connection_creds(self, creds):
        
        if self.product == 'defender':
            if self.profile: 
                atp_profile = self.profile
            else: 
                atp_profile = "default"
        
            config = self.config_reader(creds)
            conn = self.get_atp_aadToken(config[atp_profile]['tenantId'], config[atp_profile]['appId'], config[atp_profile]['appSecret'])

            return conn
    
    def get_aad_token(self, tenantID, appID, appSecret):
        tenantId = tenantID 
        appId = appID
        appSecret = appSecret

        url = f"https://login.windows.net/{tenantID}/oauth2/token"

        resourcesAppIdUri = 'https://api.securitycenter.windows.com'
        body = {
            "resource": resourcesAppIdUri, 
            "client_id": appId, 
            "client_secret":appSecret, 
            "grant_type":"client_credentials"
        }

        data = urllib.parse.urlencode(body).encode("utf-8")
        req = urllib.request.Request(url, data)
        response = urllib.request.urlopen(req)
        jsonResponse = json.loads(response.read())
        aadToken = jsonResponse["access_token"]

        return aadToken 

    def config_reader(self, creds_file): 
        config = configparser.ConfigParser()
        config.sections()
        config.read(creds_file)

        return config 
