# flamegraph.py - create flame graphs from crypto-auditing events
# SPDX-License-Identifier: GPL-2.0
#
# Usage:
#
#     crau-query --log-file audit.cborseq > audit.json
#     python flamegraph.py audit.json
#
# Based on perf script flamegraph written by
# Andreas Gerstmayr <agerstmayr@redhat.com>.
#
# pylint: disable=missing-module-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring

from __future__ import print_function
import sys
import os
import io
import argparse
import json
import sqlite3
from tables import CIPHERSUITES, KX, PROTOCOLS, SIGNATURE_SCHEMES, \
    SUPPORTED_GROUPS


# pylint: disable=too-few-public-methods
class Node:
    def __init__(self, name, libtype, depth):
        self.name = name
        # "root" | "kernel" | ""
        # "" indicates user space
        self.libtype = libtype
        self.depth = depth
        self.value = 0
        self.children = []
        self.cumulative = 1

    def accept(self, visitor):
        visitor.visit(self)
        for child in self.children:
            child.accept(visitor)

    def to_json(self):
        return {
            "n": self.name,
            "l": self.libtype,
            "v": self.value,
            "c": self.children
        }


class Visitor:
    def visit(self, node):
        pass


class SqliteVisitor(Visitor):
    def __init__(self, path):
        self.con = sqlite3.connect(path)
        self.cur = self.con.cursor()
        self.cur.execute("""
CREATE TABLE stacks (
        level INTEGER,
        value INTEGER,
        label STRING,
        self  INTEGER
)
""")

    def visit(self, node):
        self.cur.execute(f"""
INSERT INTO stacks VALUES (
        {node.depth},
        {node.cumulative},
        "{node.name}",
        {node.value}
)
""")

    def commit(self):
        self.con.commit()


class FlameGraphCLI:
    def __init__(self, args):
        self.args = args
        self.stack = Node("all", "root", 0)

        if self.args.format == "html" and \
                not os.path.isfile(self.args.template):
            print(f"""\
Flame Graph template {self.args.template} does not exist.
Please install the js-d3-flame-graph (RPM) or libjs-d3-flame-graph (deb)
package, specify an existing flame graph template
(--template PATH) or another output format
(--format FORMAT).""",
                  file=sys.stderr)
            sys.exit(1)

        if self.args.format == "sqlite":
            self.sqlite_visitor = \
                SqliteVisitor(self.args.output or "flamegraph.sqlite")

    @staticmethod
    def find_or_create_node(node, name, libtype):
        for child in node.children:
            if child.name == name:
                return child

        child = Node(name, libtype, node.depth + 1)
        node.children.append(child)
        return child

    def format_details(self, name, events):
        details = []

        if name.startswith("tls::handshake_"):
            if "tls::protocol_version" in events:
                details.append(PROTOCOLS.get(events["tls::protocol_version"],
                                             "unknown version"))
            if "tls::ciphersuite" in events:
                details.append(CIPHERSUITES.get(events["tls::ciphersuite"],
                                                "unknown ciphersuite"))
            for event in events:
                if event.startswith("tls::ext::"):
                    details.append(event[len("tls::ext::"):])
        elif name in ["tls::sign", "tls::verify"]:
            if "tls::signature_algorithm" in events:
                details.append(
                    SIGNATURE_SCHEMES.get(events["tls::signature_algorithm"],
                                          "unknown signature algorithm"))
        elif name == "tls::key_exchange":
            if "tls::key_exchange_algorithm" in events:
                details.append(KX.get(events["tls::key_exchange_algorithm"],
                                      "unknown algorithm"))
            if "tls::group" in events:
                details.append(SUPPORTED_GROUPS.get(events["tls::group"],
                                                    "unknown group"))
        elif name in ["pk::sign", "pk::verify",
                      "pk::generate", "pk::derive",
                      "pk::encapsulate", "pk::decapsulate",
                      "pk::encrypt", "pk::decrypt"]:
            if "pk::algorithm" in events:
                details.append(events["pk::algorithm"])

        return ', '.join(details)

    def parse_span(self, parent, span):
        events = span.get("events", {})
        name = events.pop("name", "unknown")
        details = self.format_details(name, events)
        name = f"{name} [{details}]" if details else f"{name}"

        node = self.find_or_create_node(parent, name, "")
        node.value += 1
        parent.cumulative += 1
        return node

    def parse_spans(self, parent, spans):
        for span in spans:
            children = span.get("spans", [])
            node = self.parse_span(parent, span)
            if len(children) > 0:
                self.parse_spans(node, children)

    def run(self):
        spans = json.load(self.args.input)

        for span in spans:
            spans = span.get("spans", [])
            context = span.pop("context", "unknown")

            node = self.find_or_create_node(self.stack, context, "")
            node.value += 1
            self.stack.cumulative += 1

            node = self.parse_span(node, span)
            self.parse_spans(node, spans)

        if self.args.format == "sqlite":
            self.stack.accept(self.sqlite_visitor)
            self.sqlite_visitor.commit()
            return

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
                print(f"Error reading template file: {err}", file=sys.stderr)
                sys.exit(1)
            output_fn = self.args.output or "flamegraph.html"
        else:
            output_str = stacks_json
            output_fn = self.args.output or "stacks.json"

        if output_fn == "-":
            with io.open(sys.stdout.fileno(), "w", encoding="utf-8",
                         closefd=False) as out:
                out.write(output_str)
        else:
            print(f"dumping data to {output_fn}")
            try:
                with io.open(output_fn, "w", encoding="utf-8") as out:
                    out.write(output_str)
            except IOError as err:
                print(f"Error writing output file: {err}", file=sys.stderr)
                sys.exit(1)


TEMPLATE = \
    "/usr/share/d3-flame-graph/d3-flamegraph-base.html"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create flame graphs.")
    parser.add_argument("-f", "--format",
                        default="html", choices=["json", "html", "sqlite"],
                        help="output file format")
    parser.add_argument("-o", "--output",
                        help="output file name")
    parser.add_argument("--template",
                        default=TEMPLATE,
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
