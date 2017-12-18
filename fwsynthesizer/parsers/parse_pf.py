#!/usr/bin/env python2

import itertools
from collections import namedtuple
from parsec import *
from utils import *

################################################################################
# TYPES

Rule = namedtuple('Rule', ['action', 'direction', 'log', 'quick', 'interface',
                           'addr_family', 'protocol', 'src', 'dst',
                           'flags', 'state', 'nat_to'])
Macro = namedtuple('Macro', ['name'])
Table = namedtuple('Table', ['name'])

MacroDef = namedtuple('MacroDef', ['name', 'value'])
TableDef = namedtuple('TableDef', ['name', 'list'])

################################################################################
# UTILS / GLOBALS

PROTOCOLS = protocols()
PORTS     = services()
KEYWORDS  = ['block', 'pass', 'in', 'out', 'log', 'quick', 'all', 'any',
             'on', 'proto', 'from', 'to', 'port', 'flags', 'state']


def protocol_number(proto):
    try:
        return int(proto)
    except:
        return int(PROTOCOLS[proto])

def port_from_name(name):
    try:
        return Port(int(name))
    except:
        return Port(int(PORTS[name]))

################################################################################
# PARSERS

macro       = regex('\$[a-zA-Z0-9\-\_\/]+').parsecmap(lambda s: Macro(s[1:]))
table       = regex('<[a-zA-Z0-9\-\_]+>').parsecmap(lambda s: Table(s[1:len(s)-1]))

identifier  = not_in(regex('[a-zA-Z0-9\-\_\/]+'), KEYWORDS) ^ macro
identifiers = macro | identifier | clist_of(identifier)

port_spec   = negate(port) ^ identifier.parsecmap(port_from_name) ^ macro
addr_spec   = negate(ip_subnet) ^ negate(ip_addr) ^ identifier ^ macro ^ table
addr_specs  = macro | table | addr_spec | clist_of(addr_spec)
ports       = macro | port_spec | clist_of(port_spec)

address     = option(addr_specs ^ symbol("any"), 'any') + optional(symbol('port') >> ports)
addresses   = symbol("all").result((('any', None), ('any', None))) | \
               (optional(symbol('from') >> address) + optional((symbol('to') >> address)))

state_spec  = (alternative('no', 'keep', 'modulate', 'synproxy') << symbol('state')
               + optional(list_of(many1(none_of(',)'))
                                  .parsecmap(lambda s: ''.join(s).strip()))))

argument    = lambda s: symbol(s) >> identifiers << spaces

# PF RULE
# action [direction] [log] [quick] [on interface] [af] [proto protocol]
#        [from src_addr [port src_port]] [to dst_addr [port dst_port]]
#        [flags tcp_flags] [state]
@generate
def pf_rule():
    action      = yield alternative('pass', 'block return', 'block', 'nat', 'rdr')
    direction   = yield optional(alternative('in', 'out'))
    log         = yield optional(switch('log'))
    quick       = yield optional(switch('quick'))
    interface   = yield optional(argument('on'))
    addr_family = yield optional(identifiers)
    protocol    = yield optional(argument('proto').parsecmap(protocol_number))
    src, dst    = yield addresses
    flags       = yield optional(argument('flags'))
    state       = yield optional(state_spec)
    nat_to      = yield optional(symbol('->') >> address)

    preturn ( Rule(action, direction, log, quick, interface, addr_family,
                   protocol, src, dst, flags, state, nat_to) )

# We do not support recursive macros (IMPORTANT)
@generate
def macro_def():
    name  = yield identifier
    _     = yield symbol("=")
    value = yield between(symbol('"'), symbol('"'),
                          addr_spec ^ port_spec ^ identifier
                          ^ clist_of(addr_spec) ^ clist_of(port_spec) ^ clist_of(identifier))
    preturn ( MacroDef(name,value) )

@generate
def table_def():
    _    = yield symbol("table")
    name = yield symbol("<") >> identifier << symbol(">")
    _    = yield optional(alternative("const", "counters", "persist"))
    lst  = yield clist_of(addr_spec)
    preturn ( TableDef(name, lst) )

@generate
def conf_file():
    _    = yield (comment << space_endls) ^ endl_comments
    defs = yield many1( (macro_def ^ table_def ^ pf_rule) << endl_comments )
    preturn ( defs )

################################################################################
# CONVERTER

def build_macro_table_dicts(rules):
    macro_dict = {}
    table_dict = {}
    for rule in rules:
        if isinstance(rule, MacroDef):
            macro_dict[rule.name] = rule.value
        if isinstance(rule, TableDef):
            table_dict[rule.name] = rule.list
    return macro_dict, table_dict

def expand(macro, mdict):
    try:
        return mdict[macro.name]
    except KeyError:
        raise RuntimeError("Invalid Macro or Table `{}'".format(macro.name))


def convert_rule(rule, interfaces, macro_dict, table_dict):
    constraints = []

    def if_name_ip(ipaddr):
        if isinstance(ipaddr, str):
            return interfaces[ipaddr][0]
        else: return ipaddr

    def make_vals(value):
        if isinstance(value, list):
            return [ x for v in value for x in make_vals(v) ]
        if isinstance(value, Macro):
            return make_vals(expand(value, macro_dict))
        if isinstance(value, Table):
            return make_vals(expand(value, table_dict))
        if value:
            return [value]
        return []

    def append_constraint(variable, operator, value, mapper=None):
        c = []
        for v in make_vals(value):
            if isinstance(v, Negate):
                c.append("not ({} {} {})".format(variable, operator, mapper(v.value) if mapper else v.value))
            else:
                c.append("{} {} {}".format(variable, operator, mapper(v) if mapper else v))
        if c:
            constraints.append(c)

    if rule.src:
        srcip, srcport = rule.src
        append_constraint("srcIp", "==", srcip if srcip != 'any' else None, mapper=if_name_ip)
        append_constraint("srcPort", "==", srcport, mapper=lambda p: p.value)

    if rule.dst:
        dstip, dstport = rule.dst
        append_constraint("dstIp", "==", dstip if dstip != 'any' else None, mapper=if_name_ip)
        append_constraint("dstPort", "==", dstport, mapper=lambda p: p.value)

    if rule.protocol:
        append_constraint("protocol", "==", rule.protocol)
    elif (rule.src and rule.src[1]) or (rule.dst and rule.dst[1]):
        append_constraint("protocol", "==", 6)

    if rule.interface:
        if rule.direction == 'in':
            constraints.append(synthesis.constrain_interface(interfaces, "srcIp", rule.interface))
        if rule.direction == 'out':
            constraints.append(synthesis.constrain_interface(interfaces, "dstIp", rule.interface))
        else:
            constraints.append("({} || {})".format(
                synthesis.constrain_interface(interfaces, "srcIp", rule.interface),
                synthesis.constrain_interface(interfaces, "dstIp", rule.interface)))

    target = "DROP"
    if rule.action == 'pass':  target = "ACCEPT"
    if 'block' in rule.action: target = "DROP"
    if rule.action == 'nat':
        if not rule.nat_to: raise RuntimeError("No NAT Destination")
        ns, nd = rule.nat_to
        target = "NAT(Id, {}:{})".format("Id" if not ns else ns, "Id" if not nd else nd)
    if rule.action == 'rdr':
        if not rule.nat_to: raise RuntimeError("No RDR Destination")
        ns, nd = rule.nat_to
        target = "NAT({}:{}, Id)".format("Id" if not ns else ns, "Id" if not nd else nd)

    rules_constraints = itertools.product(*constraints)
    return [ "({}, {})".format(" && ".join(cs) if len(cs) > 0 else "true", target)
             for cs in rules_constraints ]


def convert_rules(rules, interfaces):
    chains = {}
    mdict, tdict = build_macro_table_dicts(rules)

    rules = filter(lambda r: isinstance(r, Rule), rules)

    quicks    = lambda rs: filter(lambda r: r.quick, rs)
    normals   = lambda rs: filter(lambda r: not r.quick, rs)
    get_rules = lambda rs: (  [ rule for plain in quicks(rs)
                                for rule in convert_rule(plain, interfaces, mdict, tdict) ]
                            + [ rule for plain in normals(rs)
                                for rule in convert_rule(plain, interfaces, mdict, tdict) ][::-1] )

    ## dnat
    dnats = [ rule for rule in rules if rule.action == 'rdr' ]
    if dnats:
        chains["R_dnat"] = ['(state == 1, CHECK-STATE(->))']
        chains["R_dnat"] += get_rules(dnats)

    ## snat
    snats = [ rule for rule in rules if rule.action == 'nat' ]
    if snats:
        chains["R_snat"] = ['(state == 1, CHECK-STATE(<-))']
        chains["R_snat"] += get_rules(snats)

    ## input
    inputs = [ rule for rule in rules
               if rule not in snats and rule not in dnats and rule.direction != 'out' ]
    if inputs:
        chains["R_finp"] = ['(state == 1, ACCEPT)']
        chains["R_finp"] += get_rules(inputs)

    ## output
    outputs = [ rule for rule in rules
                if rule not in snats and rule not in dnats and rule.direction != 'in' ]
    if outputs:
        chains["R_fout"] = ['(state == 1, ACCEPT)']
        chains["R_fout"] += get_rules(outputs)

    output = ""
    for name, rules in chains.items():
        if len(rules) > 0:
            output += 'CHAIN {} ACCEPT:\n'.format(name)
            output += '\n'.join(rules)
            output += '\n\n'

    return output

################################################################################
# QUERY FUNCTIONS

def get_lines(contents):
    return [ line.strip() for line in contents.split("\n")
             if not line.startswith("#") and  line.strip() != ""]

def delete_rule(rules, rule_number):
    rules = rules[::]
    del rules[rule_number]
    return rules
