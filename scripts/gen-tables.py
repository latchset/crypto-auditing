#!/usr/bin/python

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2023 The crypto-auditing developers.

import argparse
import csv
import re
import sys

def format_dict(d, hex=True):
    output = []
    for (k, v) in d.items():
        output.append(f'    0x{format(k, "x")}: "{v}"')
    return "{\n" + ",\n".join(output) + "\n}"

def gen(args):
    ciphersuites = {}
    reader = csv.DictReader(args.ciphersuites)
    for row in reader:
        d = row["Description"]
        if not d.startswith("TLS_"):
            continue
        m = re.match(r"0x([0-9a-fA-F]{2}),0x([0-9a-fA-F]{2})", row["Value"])
        if m:
            ciphersuites[int(m.group(1), 16) << 8 | int(m.group(2), 16)] = d

    signature_schemes = {}
    reader = csv.DictReader(args.signature_schemes)
    for row in reader:
        d = row["Description"]
        if d.startswith("Reserved") or d == "Unassigned":
            continue
        m = re.match(r"0x([0-9a-fA-F]{4})", row["Value"])
        if m:
            signature_schemes[int(m.group(1), 16)] = d

    supported_groups = {}
    reader = csv.DictReader(args.supported_groups)
    for row in reader:
        d = row["Description"]
        if d.startswith("Reserved") or d == "Unassigned":
            continue
        m = re.match(r"^([0-9]+)$", row["Value"])
        if m:
            supported_groups[int(m.group(1))] = d
    return f"""\
CIPHERSUITES = {format_dict(ciphersuites)}

SIGNATURE_SCHEMES = {format_dict(signature_schemes)}

SUPPORTED_GROUPS = {format_dict(supported_groups, hex=False)}
"""
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create tables for flame graphs.")
    parser.add_argument("--ciphersuites",
                        type=argparse.FileType('r'))
    parser.add_argument("--signature-schemes",
                        type=argparse.FileType('r'))
    parser.add_argument("--supported-groups",
                        type=argparse.FileType('r'))
    parser.add_argument("-o", "--output",
                        help="output file name",
                        type=argparse.FileType('w'),
                        default=sys.stdout)
    
    args = parser.parse_args()
    print(gen(args), file=args.output)

