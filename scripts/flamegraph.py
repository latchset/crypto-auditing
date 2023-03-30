# flamegraph.py - create flame graphs from crypto-auditing events
# SPDX-License-Identifier: GPL-2.0
#
# Usage:
#
#     cargo run --bin crypto-auditing-log-parser audit.cborseq > audit.json
#     python flamegraph.py audit.json
#
# Based on perf script flamegraph written by Andreas Gerstmayr <agerstmayr@redhat.com>.
#
# pylint: disable=missing-module-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring

from __future__ import print_function
import sys
import os
import io
import os
import argparse
import json
import subprocess
import csv
import re

base = os.path.dirname(os.path.realpath(__file__))
sys.path.append(base)

from tables import CIPHERSUITES, SIGNATURE_SCHEMES, SUPPORTED_GROUPS

# pylint: disable=too-few-public-methods
class Node:
    def __init__(self, name, libtype):
        self.name = name
        # "root" | "kernel" | ""
        # "" indicates user space
        self.libtype = libtype
        self.value = 0
        self.children = []

    def to_json(self):
        return {
            "n": self.name,
            "l": self.libtype,
            "v": self.value,
            "c": self.children
        }

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

class FlameGraphCLI:
    def __init__(self, args):
        self.args = args
        self.stack = Node("all", "root")

        if self.args.format == "html" and \
                not os.path.isfile(self.args.template):
            print("Flame Graph template {} does not exist. Please install "
                  "the js-d3-flame-graph (RPM) or libjs-d3-flame-graph (deb) "
                  "package, specify an existing flame graph template "
                  "(--template PATH) or another output format "
                  "(--format FORMAT).".format(self.args.template),
                  file=sys.stderr)
            sys.exit(1)

    @staticmethod
    def find_or_create_node(node, name, libtype):
        for child in node.children:
            if child.name == name:
                return child

        child = Node(name, libtype)
        node.children.append(child)
        return child

    def format_details(self, name, events):
        details = []

        if name.startswith("tls::handshake_"):
            if "tls::protocol_version" in events:
                details.append(PROTOCOLS.get(events["tls::protocol_version"], "unknown version"))
            if "tls::ciphersuite" in events:
                details.append(CIPHERSUITES.get(events["tls::ciphersuite"], "unknown ciphersuite"))
        elif name.startswith("tls::certificate_"):
            if "tls::signature_algorithm" in events:
                details.append(SIGNATURE_SCHEMES.get(events["tls::signature_algorithm"], "unknown signature algorithm"))
        elif name.startswith("tls::certificate_"):
            if "tls::signature_algorithm" in events:
                details.append(SIGNATURE_SCHEMES.get(events["tls::signature_algorithm"], "unknown signature algorithm"))
        elif name == "tls::key_exchange":
            if "tls::key_exchange_algorithm" in events:
                details.append(KX.get(events["tls::key_exchange_algorithm"], "unknown algorithm"))
            if "tls::group" in events:
                details.append(SUPPORTED_GROUPS.get(events["tls::group"], "unknown group"))

        return ', '.join(details)

    def parse_span(self, parent, span):
        events = span.get("events", {})
        spans = span.get("spans", [])
        name = events.pop("name", "unknown")
        name = f"{name} [{self.format_details(name, events)}]"

        node = self.find_or_create_node(parent, name, "")
        node.value += 1
        return node

    def parse_spans(self, parent, spans):
        for span in spans:
            self.parse_span(parent, span)

    def run(self):
        spans = json.load(self.args.input)

        for span in spans:
            events = span.get("events", {})
            spans = span.get("spans", [])
            context = span.pop("context", "unknown")

            node = self.find_or_create_node(self.stack, context, "")
            node.value += 1

            node = self.parse_span(node, span)
            self.parse_spans(node, spans)

        stacks_json = json.dumps(self.stack, default=lambda x: x.to_json())

        if self.args.format == "html":
            options = {
                "colorscheme": self.args.colorscheme
            }
            options_json = json.dumps(options)

            try:
                with io.open(self.args.template, encoding="utf-8") as template:
                    output_str = (
                        template.read()
                        .replace("/** @options_json **/", options_json)
                        .replace("/** @flamegraph_json **/", stacks_json)
                    )
            except IOError as err:
                print("Error reading template file: {}".format(err), file=sys.stderr)
                sys.exit(1)
            output_fn = self.args.output or "flamegraph.html"
        else:
            output_str = stacks_json
            output_fn = self.args.output or "stacks.json"

        if output_fn == "-":
            with io.open(sys.stdout.fileno(), "w", encoding="utf-8", closefd=False) as out:
                out.write(output_str)
        else:
            print("dumping data to {}".format(output_fn))
            try:
                with io.open(output_fn, "w", encoding="utf-8") as out:
                    out.write(output_str)
            except IOError as err:
                print("Error writing output file: {}".format(err), file=sys.stderr)
                sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create flame graphs.")
    parser.add_argument("-f", "--format",
                        default="html", choices=["json", "html"],
                        help="output file format")
    parser.add_argument("-o", "--output",
                        help="output file name")
    parser.add_argument("--template",
                        default="/usr/share/d3-flame-graph/d3-flamegraph-base.html",
                        help="path to flame graph HTML template")
    parser.add_argument("--colorscheme",
                        default="blue-green",
                        help="flame graph color scheme",
                        choices=["blue-green", "orange"])
    parser.add_argument("input",
                        type=argparse.FileType('r'))

    cli_args = parser.parse_args()
    cli = FlameGraphCLI(cli_args)
    cli.run()
