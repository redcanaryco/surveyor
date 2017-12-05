#!/usr/bin/env python

"""Given Carbon Black (Cb) Response process search criteria, return a unique set
of matches based on:

- hostname
- username
- process path
- process command-line

Results are written to a CSV file. 

Requires a valid cbapi credential file containing a Cb Response
server URL and corresponding API token.

Requires one or more JSON-formatted definition files (examples provided) or a
Cb Response query as input.
"""

import argparse
import csv
import json
import os
import sys

from cbapi.response import CbEnterpriseResponseAPI
from cbapi.response.models import Process

if sys.version_info.major >= 3:
    _python3 = True
else:
    _python3 = False


def err(msg):
    """Format msg as an ERROR and print to stderr.
    """
    msg = 'ERROR: %s\n' % msg
    sys.stderr.write(msg)
    return


def log(msg):
    """Format msg and print to stdout.
    """
    msg = '%s\n' % msg
    sys.stdout.write(msg)
    return


def process_search(cb_conn, query, query_base=None):
    """Perform a single Cb Response query and return a unique set of
    results.
    """
    results = set()

    query += query_base

    try:
        for proc in cb_conn.select(Process).where(query):
            results.add((proc.hostname.lower(),
                        proc.username.lower(), 
                        proc.path,
                        proc.cmdline))
    except KeyboardInterrupt:
        log("Caught CTRL-C. Returning what we have . . .\n")

    return results


def nested_process_search(cb_conn, criteria, query_base=None):
    """Perform Cb Response queries for one or more programs and return a 
    unique set of results per program.
    """
    results = set()

    try:
        for search_field,terms in criteria.items():
            query = '(' + ' OR '.join('%s:%s' % (search_field, term) for term in terms) + ')'
            query += query_base

            for proc in cb_conn.select(Process).where(query):
                results.add((proc.hostname.lower(),
                            proc.username.lower(), 
                            proc.path,
                            proc.cmdline))
    except KeyboardInterrupt:
        log("Caught CTRL-C. Returning what we have . . .")

    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=str, action="store", 
                        help="Output filename prefix.")
    parser.add_argument("--profile", type=str, action="store",
                        help="The credentials.response profile to use.")

    # Time boundaries for the survey
    parser.add_argument("--days", type=int, action="store",
                        help="Number of days to search.")
    parser.add_argument("--minutes", type=int, action="store",
                        help="Number of days to search.")

    # Survey criteria
    i = parser.add_mutually_exclusive_group(required=True)
    i.add_argument('--deffile', type=str, action="store", 
                        help="Definition file to process (must end in .json).")
    i.add_argument('--defdir', type=str, action="store", 
                        help="Directory containing multiple definition files.")
    i.add_argument('--query', type=str, action="store", 
                        help="A single Cb query to execute.")
    i.add_argument('--iocfile', type=str, action="store", 
                        help="IOC file to process. One IOC per line. REQUIRES --ioctype")
    parser.add_argument('--hostname', type=str, action="store",
                        help="Target specific host by name.")

    # IOC survey criteria
    parser.add_argument('--ioctype', type=str, action="store", 
                        help="One of: ipaddr, domain, md5")

    args = parser.parse_args()

    if (args.iocfile is not None and args.ioctype is None):
        parser.error('--iocfile requires --ioctype')

    if args.prefix:
        output_filename = '%s-survey.csv' % args.prefix
    else:
        output_filename = 'survey.csv' 

    query_base = ''
    if args.days:
        query_base += ' start:-%dm' % (args.days*1440)
    elif args.minutes:
        query_base += ' start:-%dm' % args.minutes

    if args.hostname:
        if args.query and 'hostname' in args.query:
            parser.error('Cannot use --hostname with "hostname:" (in query)')
        query_base += ' hostname:%s' % args.hostname

    definition_files = []
    if args.deffile:
        if not os.path.exists(args.deffile):
            err('deffile does not exist')
            sys.exit(1)
        definition_files.append(args.deffile)
    elif args.defdir:
        if not os.path.exists(args.defdir):
            err('defdir does not exist')
            sys.exit(1)
        for root, dirs, files in os.walk(args.defdir):
            for filename in files:
                if filename.endswith('.json'):
                    definition_files.append(os.path.join(root, filename))
        
    if _python3:
        output_file = open(output_filename, 'w', newline='')
    else:
        output_file = open(output_filename, 'wb')
    writer = csv.writer(output_file)
    writer.writerow(["endpoint","username","process_path","cmdline","program","source"])
    
    if args.profile:
        cb = CbEnterpriseResponseAPI(profile=args.profile)
    else:
        cb = CbEnterpriseResponseAPI()

    if args.query:
        result_set = process_search(cb, args.query, query_base)

        for r in result_set:
            row = [r[0], r[1], r[2], r[3], args.query, 'query']
            if _python3 == False:
                row = [col.encode('utf8') if isinstance(col, unicode) else col for col in row]
            writer.writerow(row)
    elif args.iocfile:
        with open(args.iocfile) as iocfile:
            data = iocfile.readlines()
            for ioc in data:
                ioc = ioc.strip()
                query = '%s:%s' % (args.ioctype, ioc)
                result_set = process_search(cb, query, query_base)

                for r in result_set:
                    row = [r[0], r[1], r[2], r[3], ioc, 'ioc']
                    if _python3 == False:
                        row = [col.encode('utf8') if isinstance(col, unicode) else col for col in row]
                    writer.writerow(row)
    else:
        for definition_file in definition_files:
            log("Processing definition file: %s" % definition_file)
            basename = os.path.basename(definition_file)
            source = os.path.splitext(basename)[0]

            with open(definition_file, 'r') as fh:
                programs = json.load(fh)

            for program,criteria in programs.items():
                log("--> %s" % program)

                result_set = nested_process_search(cb, criteria, query_base)

                for r in result_set:
                    row = [r[0], r[1], r[2], r[3], program, source]
                    if _python3 == False:
                        row = [col.encode('utf8') if isinstance(col, unicode) else col for col in row]
                    writer.writerow(row)

    output_file.close()


if __name__ == '__main__':

    sys.exit(main())
