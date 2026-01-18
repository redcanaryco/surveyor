#!/usr/bin/env python3
"""
Convert RMM-Catalogue csv to surveyor definitions
https://raw.githubusercontent.com/0x706972686f/RMM-Catalogue/main/rmm.csv
"""

import os
import csv
import pandas as pd

file = os.environ.get("HOME") + "/Downloads/rmm.csv"

df = pd.read_csv(file, quoting=csv.QUOTE_ALL)
out = "{\n"
for index, row in df.iterrows():
    # print(row['Software'], row['Domain'])
    # print(row)
    out += f"""  "{row['Software']}": """ + "{\n"
    if row["Executables"] and isinstance(row["Executables"], str):
        out += """    "process_name": [\n"""
        for process in row["Executables"].split(","):
            out += f"""      "{process.replace('"', '')}",\n"""
        out = out[:-2] + "\n"
        out += """    ],\n"""
    if row["Domain"] and isinstance(row["Domain"], str):
        out += """    "domain": [\n"""
        for domain in row["Domain"].split(","):
            out += f"""      "{domain.split('/')[0]}",\n"""
        out = out[:-2] + "\n"
        out += """    ]\n"""
    else:
        out = out[:-2] + "\n"
    out += """  },\n"""

out = out[:-2] + "\n"
out += "}\n"
print(out)
