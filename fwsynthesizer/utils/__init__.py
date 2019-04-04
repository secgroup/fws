#!/usr/bin/env python2

import os
import re
import collections
from fwsynthesizer.parsers.utils import Negate, file_to_dict, protocols, services, ip_addr, ip_subnet, ip_range
import parsec

def get_local_addresses(interface_map):
    "Get local addresses from the interfaces file map"
    return [ local_addr for ifc, (subnet, local_addr) in interface_map.items() ]

def constrain_interface(interfaces, variable, ifname):
    """
    Make a formula in the generic language to constrain a variable to be
    inside the range of the selected interface subnet
    """

    ext_constraint = lambda var, constraints: "not ({})".format(
        " || ".join("{} == {}".format(var, addr) for addr in constraints))

    negated = False
    if isinstance(ifname, Negate):
        ifname = ifname.value
        negated = True

    if interfaces[ifname][0] == '0.0.0.0/0':
        constraints = [ network for ifc, (network, _) in interfaces.items() if ifc != ifname ] \
                    + [ interfaces[ifname][1] ]
        out = ext_constraint(variable, constraints)
    else:
        out = "{} == {}".format(variable, interfaces[ifname][0])

    return "not ({})".format(out) if negated else out

def load_interfaces(path):
    """
    Load Intefaces File
    """
    return file_to_dict(path)

def load_config(path):
    """
    Load config file with interfaces and aliases
    """
    sections = collections.defaultdict(dict)

    if not path or not os.path.exists(os.path.abspath(path)):
        return sections

    with open(path) as f:
        lines = [ line.strip()  for line in f
                  if line.strip() != '' and not line.startswith('#') ]

    # Check sections (new style config)
    if '[ALIASES]' in lines or '[INTERFACES]' in lines:
        addr_parser = ip_range ^ ip_subnet ^ ip_addr

        curr_sec = 'interfaces'
        for line in lines:
            if line == '[ALIASES]':
                curr_sec = 'aliases'
            elif line == '[INTERFACES]':
                curr_sec = 'interfaces'
            else:
                p = re.split("\s+", line)
                try:
                    sections[curr_sec][p[0]] = p[1:] if curr_sec == 'interfaces' \
                        else addr_parser.parse_strict(p[1].strip())
                except parsec.ParseError:
                    print "<!> Warning: invalid address `{}` ({}). Ignoring..."\
                        .format(p[1], p[0])
    # Old style config
    else:
        sections['interfaces'] = file_to_dict(path)
    return sections



def remove_escaped_newlines(contents):
    return contents.replace("\\\n", " ")

def remove_comments(contents):
    return re.sub("#.*?\n", "\n", contents)

def preprocess(contents):
    "Preprocess a configuration file removing comments and escaped newlines"
    return remove_comments(remove_escaped_newlines(contents))

def enum(*sequential, **named):
    "Make a c-style enum"
    enums = dict(zip(sequential, range(len(sequential))), **named)
    return type('Enum', (), enums)
