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
from datetime import datetime, timedelta

from cbapi.response import CbEnterpriseResponseAPI
from cbapi.response.models import Process as r_Process

from cbapi.psc.threathunter import CbThreatHunterAPI
from cbapi.psc.threathunter.models import Process as th_Process

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


def process_search(cb_conn, query, query_base=None, translate=False):
  """Perform a single Cb Response query and return a unique set of
  results.
  """
  results = set()

  try:
    if isinstance(cb_conn, CbThreatHunterAPI):
      if translate:
        query = cb_conn.convert_query(query)
      query += query_base
      for proc in cb_conn.select(th_Process).where(query):
        results.add((str(proc.get('device_name')).lower(),
                     str(proc.get('process_username')).lower(),
                     str(proc.get('process_name')),
                     str(proc.get('process_cmdline'))))
    else:
      query += query_base
      for proc in cb_conn.select(r_Process).where(query):
        results.add((proc.hostname.lower(),
                     proc.username.lower(), 
                     proc.path,
                     proc.cmdline))
  except KeyboardInterrupt:
    log("Caught CTRL-C. Returning what we have . . .\n")

  return results


def nested_process_search(cb_conn, criteria, query_base=None, translate=False):
  """Perform Cb Response queries for one or more programs and return a
  unique set of results per program.
  """
  results = set()

  try:
    for search_field,terms in criteria.items():
      query = '(' + ' OR '.join('%s:%s' % (search_field, term) for term in terms) + ')'

      if isinstance(cb_conn, CbThreatHunterAPI):
        if translate:
          query = cb_conn.convert_query(query)
        query += query_base
        for proc in cb_conn.select(th_Process).where(query):
          results.add((str(proc.device_name).lower(),
                       str(proc.process_username).lower(),
                       str(proc.process_name),
                       str(proc.process_cmdline)))
      else:
        query += query_base
        for proc in cb_conn.select(r_Process).where(query):
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
  parser.add_argument("--profile", type=str, action="store", default="default",
                      help="The credentials.response profile to use.")
  parser.add_argument("--cbc", action="store_true",
                      help="Use Cloud Enterprise EDR (formerly ThreatHunter)"
                        "to perform the requested action")
  parser.add_argument("--translate", action="store_true",
                      help="Translate queries from Response to CBC format")

  # Time boundaries for the survey
  parser.add_argument("--days", type=int, action="store",
                      help="Number of days to search.")
  parser.add_argument("--minutes", type=int, action="store",
                      help="Number of days to search.")

  # Output level
  o = parser.add_mutually_exclusive_group(required=False)
  o.add_argument("--verbose", "-v", action="store_true",
                      help="Enable verbose output")
  o.add_argument("--quiet", "-q", action="store_true",
                      help="Enable quieter output")

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
  parser.add_argument('--username', type=str, action="store",
                      help="Target specific username.")

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
  if args.cbc:
    cb = CbThreatHunterAPI(profile=args.profile)
    if args.days:
      start_time = (datetime.now()-timedelta(days=args.days)
      ).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
      query_base += f" process_start_time:[{start_time} TO *]"
    elif args.minutes:
      start_time = (datetime.now()-timedelta(minutes=args.minutes)
      ).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
      query_base += f" process_start_time:[{start_time} TO *]"
    if args.hostname:
      if args.query and 'device_name' in args.query:
        parser.error('Cannot use --hostname with "device_name:" (in query)')
      query_base += ' device_name:%s' % args.hostname
    if args.username:
      if args.query and 'process_username' in args.query:
        parser.error('Cannot use --username with "process_username:" (in query)')
      query_base += ' process_username:%s' % args.username

  else:
    cb = CbEnterpriseResponseAPI(profile=args.profile)
    if args.days:
      query_base += ' start:-%dm' % (args.days*1440)
    elif args.minutes:
      query_base += ' start:-%dm' % args.minutes
    if args.hostname:
        if args.query and 'hostname' in args.query:
          parser.error('Cannot use --hostname with "hostname:" (in query)')
        query_base += ' hostname:%s' % args.hostname
    if args.username:
      if args.query and 'username' in args.query:
        parser.error('Cannot use --username with "username:" (in query)')
      query_base += ' username:%s' % args.username

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

  if args.query:
    result_set = process_search(cb, args.query, query_base, args.translate)

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
        result_set = process_search(cb, query, query_base, args.translate)

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

        result_set = nested_process_search(cb, criteria, query_base, args.translate)

        for r in result_set:
          row = [r[0], r[1], r[2], r[3], program, source]
          if _python3 == False:
            row = [col.encode('utf8') if isinstance(col, unicode) else col for col in row]
          writer.writerow(row)

  output_file.close()


if __name__ == '__main__':

  sys.exit(main())
