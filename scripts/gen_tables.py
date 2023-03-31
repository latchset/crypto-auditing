#!/usr/bin/python

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2023 The crypto-auditing developers.

# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=C0103

import argparse
import csv
import pprint
import re
import sys

PROTOCOLS = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

KX = {
    0: "ECDHE",
    1: "DHE",
    2: "PSK",
    3: "ECDHE-PSK",
    4: "DHE-PSK",
}


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
    pp = pprint.PrettyPrinter(indent=4)
    return f"""\
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2023 The crypto-auditing developers.

# DO NOT EDIT! GENERATED AUTOMATICALLY!

# pylint: disable=missing-module-docstring

PROTOCOLS = {pp.pformat(PROTOCOLS)}

KX = {pp.pformat(KX)}

CIPHERSUITES = {pp.pformat(ciphersuites)}

SIGNATURE_SCHEMES = {pp.pformat(signature_schemes)}

SUPPORTED_GROUPS = {pp.pformat(supported_groups)}\
"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create tables for flame graphs."
    )
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

    cli_args = parser.parse_args()
    print(gen(cli_args), file=cli_args.output)
