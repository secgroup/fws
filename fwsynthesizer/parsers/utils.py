#!/usr/bin/env python2

import re
import argparse

from ipaddr import IPv4Address, IPv4Network
from fwsynthesizer.utils.ipaddr_ext import IPv4Range
from fwsynthesizer.utils.macaddr import MACAddress

from parsec import *

import fwsynthesizer

###############################################################################
# Parsec Utils

def preturn(value):
    "Return a value from an iterator"
    e = StopIteration()
    e.value = value
    raise e

def option(parser, default):
    "Option parser: returns `default` if `parsers` fails"
    @Parser
    def option_parser(text, index):
        res = parser(text, index)
        if res.status: return res
        else: return Value.success(index, default)
    return option_parser

def optional(p):
    "Optional parser: returns `None` if `parser` fails"
    return option(p, None)

def not_in(p, words):
    "Not in: parses `p` then fails if the result is in `words`"
    @Parser
    def not_in_parser(text, index):
        res = p(text, index)
        if not res.status:
            return res
        if res.value in words:
            return Value.failure(index, "value not allowed!")
        return res
    return not_in_parser

################################################################################
# Argument parsing

class Argument(object):
    "Parser for a single Argument"
    def __init__(self, short, long=None, nargs=1, required=False, negated=False,
                 default=None, mapper=None, multiple=False):
        self.short = short
        self.required = required
        self.default = default
        self.multiple = multiple

        @generate
        def parser():
            if long:
                yield regex(short) ^ regex(long)
            else:
                yield regex(short)
            args = []
            for i in range(0, nargs):
                arg = yield spaces >> (between(string('"'), string('"'), until('"')) | until(" \n"))
                args.append(arg)
                yield spaces
            if nargs == 0: args.append(True)
            preturn ( args if len(args) > 1 else args[0] )

        self.parser = parser
        if mapper:  self.parser = self.parser.parsecmap(mapper)
        if negated: self.parser = negate(self.parser)


def argument_parser(**parsers):
    """
    Parser for a list of arguments

    Args:
        parsers (*Argument): single argument parsers
    """

    @Parser
    def argparse(text, index):
        args = sorted(parsers.items(), key=lambda x: x[0])
        results = {}

        while args != []:
            for arg in args:
                dest, argument = arg
                res = argument.parser(text, index)
                if res.status:
                    if argument.multiple:
                        if results.has_key(dest):
                            results[dest].append(res.value)
                        else:
                            results[dest] = [res.value]
                    else:
                        results[dest] = res.value
                        args.remove(arg)

                    index = res.index
                    break
            else:
                if all(not arg[1].required for arg in args): break
                else:
                    return Value.failure(index, "argument in [{}]"
                                         .format(', '.join(arg[1].short
                                                           for arg in args if arg[1].required)))

        # Default values
        for arg in parsers:
            if not results.has_key(arg):
                results[arg] = parsers[arg].default
        return Value.success(index, results)

    return argparse

###############################################################################
# Generic parsers

space       = one_of("\ \t")
spaces      = many(space)
spaces1     = many1(space)
space_endls = regex("\s+")
endl        = string("\n")
number      = regex("[0-9]+").parsecmap(int)
token       = lambda p: spaces >> p << spaces
symbol      = lambda s: token(string(s))
list_of     = lambda p: symbol("(") >> sepBy1(p, symbol(",")) << symbol(")")
until       = lambda s: (many1(none_of(s))).parsecmap(''.join)
until_endl  = until("\n")
between     = lambda o,c,p: o >> p << c

################################################################################
# Firewall Specific parsers

Negate = namedtuple('Negate', ['value'])
Port = namedtuple('Port', ['value'])
PortRange = namedtuple('PortRange', ['bottom', 'top'])

octet_regex  = '[0-9]{1,3}'
addr_regex   = '(:?{0}\.){{3}}{0}'.format(octet_regex)
subnet_regex = '(:?{0}\.){{3}}{0}\/[0-9]{{1,2}}'.format(octet_regex)
range_regex  = '{0}\s*-\s*{0}'.format(addr_regex)
port_regex   = '[0-9]{1,5}'
mac_regex    = '(:?[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'

ip_addr       = regex(addr_regex).parsecmap(IPv4Address)
ip_subnet     = regex(subnet_regex).parsecmap(IPv4Network)
ip_range      = regex(range_regex).parsecmap(IPv4Range)
port          = regex(port_regex).parsecmap(Port)
port_range    = (regex(port_regex) + (string('-') >> regex(port_regex))).parsecmap(lambda p: PortRange(*p))
mac_addr      = regex(mac_regex).parsecmap(MACAddress)

negate        = (lambda p: (optional(regex("!\s*")) + p)
                 .parsecmap(lambda (n, s): Negate(s) if n else s))
comment       = symbol("#") >> until_endl
endl_comments = space_endls >> many(comment << space_endls)

clist_of    = lambda p: symbol('{') >> sepBy1(p, symbol(',') ^ spaces1) << symbol('}')
switch      = lambda s: option(symbol(s).result(True), False)
alternative = lambda *ss: reduce(try_choice, map(symbol, ss))

###############################################################################
# Common Functions

def file_to_dict(path):
    with open(path) as f:
        return { p[0]: p[1:] for p in
                 (re.split("\s+",line.strip()) for line in f
                  if line.strip() != '' and not line.startswith('#') ) }

def protocols():
    "Dict from protocol name to protocol number"
    return { name: proto[0] for name, proto in file_to_dict('/etc/protocols').items() }


def services():
    "Dict from service name to port number"
    return { name: port[0].split("/")[0]
             for name, port in  file_to_dict('/etc/services').items() }
