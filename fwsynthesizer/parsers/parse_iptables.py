#!/usr/bin/env python2

import copy
from collections import namedtuple, defaultdict
from parsec import *
from utils import *

import fwsynthesizer

from ipaddr import IPv4Address, IPv4Network
from fwsynthesizer.ipaddr_ext import IPv4Range

################################################################################
# CONFIG

# If no protocol is specified (or the keyword `ALL` is used), the rule matches only TCP, UDP and ICMP
# protocols. Since the integers associated to these protocols are not contiguous (TCP -> 6, UDP -> 17,
# ICMP -> 1), we would have three separate cubes for these rules.
# Reference to the doc:
#   http://www.iptables.info/en/iptables-matches.html#GENERICMATCHES
# The doc and the manual specify different things in this regard, so i support both strict and not strict
# protocols checking
STRICT_PROTOCOLS = False

################################################################################
# TYPES

Table = namedtuple('Table', ['name', 'policies', 'rules'])

################################################################################
# PARSER

iptables_args = argument_parser(
    # Ignored Arguments
    z_n0   = Argument('-(F|X|Z)|--(flush|zero|delete-chain|syn|update|rsource|set|log-uid)', nargs=0, multiple=True),
    z_n1    = Argument('-(m|f|N)|--(match|comment|fragment|new-chain|limit-burst\
|limit|mac-source|icmp-type|log-prefix|log-level|reject-with|name|seconds|hitcount|uid-owner|mask)', multiple=True),
    a_n2  = Argument('--tcp-flags', nargs=2),

    # Interfaces
    in_if  = Argument('-(i|-in-interface)', negated=True),
    out_if = Argument('-(o|-out-interface)', negated=True),

    # Fully supported Arguments
    def_policy  = Argument('-(P|-policy)', nargs=2),
    table       = Argument('-(t|-table)', default='filter'),
    chain       = Argument('-(A|-append)'),
    ichain      = Argument('-(I|-insert)', nargs=2),
    src_ip      = Argument('-(s|-source)', negated=True, mapper=lambda s: s.split(",")),
    dst_ip      = Argument('-(d|-destination)', negated=True, mapper=lambda s: s.split(",")),
    protocol    = Argument('-(p|-protocol)', negated=True),
    src_port    = Argument('--(sports|sport)', negated=True, mapper=lambda s: s.split(",")),
    dst_port    = Argument('--(dports|dport)', negated=True, mapper=lambda s: s.split(",")),
    state       = Argument('--(state|ctstate)'),
    target      = Argument('-(j|-jump)'),
    goto_target = Argument('-(g|-goto)'),
    nat         = Argument('--to-(source|destination|ports?)', '--to')
)

@generate
def table_definition():
    table_name = yield (symbol("*") >> until_endl << endl_comments).parsecmap(lambda s: s.strip())
    policies   = yield many1(symbol(":") >> until(' ') + (spaces >> until(' ') << until_endl << endl_comments))
    rules      = yield many(iptables_args << endl_comments)
    _          = yield symbol("COMMIT") << endl_comments
    preturn ( Table(name = table_name, policies = policies, rules = rules) )

# type: Parser[List[Table]]
iptables_save_file = optional((comment << space_endls) ^ endl_comments) >> many1(table_definition)


################################################################################
# CONVERTER

PROTOCOLS = protocols()
PORTS     = services()

CHAIN_NAMES = {
    ('PREROUTING', 'mangle'): 'PreM',
    ('PREROUTING', 'nat'): 'PreN',
    ('FORWARD', 'mangle'): 'FwdM',
    ('FORWARD', 'filter'): 'FwdF',
    ('INPUT', 'mangle'): 'InpM',
    ('INPUT', 'nat'): 'InpN',
    ('INPUT', 'filter'): 'InpF',
    ('OUTPUT', 'mangle'): 'OutM',
    ('OUTPUT', 'nat'): 'OutN',
    ('OUTPUT', 'filter'): 'OutF',
    ('POSTROUTING', 'mangle'): 'PostM',
    ('POSTROUTING', 'nat'): 'PostN'
}

def chain_name(chain, table):
    try:
        return CHAIN_NAMES[(chain, table)]
    except KeyError:
        return chain

# Constraints on the protocol can be specified either by name or by integer identifier. The mapping
# between the two is given by the dictionary `protocols`, which is constructed from the information
# in the file `/etc/protocols`.
def protocol_number(proto):
    try:
        return int(proto)
    except ValueError:
        return int(PROTOCOLS[proto])

def ports(ps):
    # Parameters of the `--sport` and `--dport` flags can either be single ports or ranges of the type
    # `lower:upper`. Allowed ranges are:
    # - 22:80 -> all ports between 22 and 80;
    # - 22:   -> all ports between 22 and 65535;
    # - :80   -> all ports between 0 and 80;
    # - 80:22 -> all ports between 22 and 80.
    # Reference to the doc:
    #   http://www.iptables.info/en/iptables-matches.html#IMPLICITMATCHES
    # The function returns intervals of the type `lower-upper` where both extremes are specified.
    if ':' not in ps:
        return ps
    low, upp = ps.split(':')
    if len(low) == 0:
        low = '0'
    elif len(upp) == 0:
        upp = '65535'
    elif int(low) > int(upp):
        low, upp = upp, low
    return '{}-{}'.format(low, upp)

def nat_target(target):
    target = target.strip()
    if target[0] == ":":
        target = "Id"+target
    return target

def flatten(xs):
    ns = []
    for x in xs:
        if isinstance(x, list): ns.extend(x)
        else: ns.append(x)
    return ns

def args_to_rule(args, interfaces):
    if args['target'] == 'LOG':
        return None

    conditions = []

    def append_condition(variable, operator, value, mapper=None):
        if value:
            negate = isinstance(value, Negate)
            if negate: value = value.value
            if not isinstance(value, list): value = [value]
            cs = []
            value = flatten([ mapper(v) if mapper else v for v in value])
            for v in value:
                cs.append("{} {} {}".format(variable, operator, v))
            condition = " || ".join(cs)

            conditions.append(("not ({})" if negate else "({})" if len(cs) > 1 else "{}").format(condition))

    # Interfaces are converted using a statically known mapping
    if args['in_if']:
        conditions.append(fwsynthesizer.constrain_interface(interfaces, "srcIp", args['in_if']))
    if args['out_if']:
        conditions.append(fwsynthesizer.constrain_interface(interfaces, "dstIp", args['out_if']))

    append_condition("srcIp", "==", args['src_ip'], mapper=lambda s: [ r.strip() for r in s.split(',') ])
    append_condition("dstIp", "==", args['dst_ip'], mapper=lambda s: [ r.strip() for r in s.split(',') ])

    if args['protocol'] and args['protocol'] != 'ALL':
        append_condition("protocol", "==", args['protocol'], mapper=protocol_number)
    elif STRICT_PROTOCOLS:
        conditions.append('({})'.format(' || '.join('protocol == {}'.format(p) for p in [1, 6, 17])))

    append_condition("srcPort", "==", args['src_port'], mapper=ports)
    append_condition("dstPort", "==", args['dst_port'], mapper=ports)

    if args['state']:
        states = args['state'].split(",")
        established = "ESTABLISHED" in states and not "NEW" in states
        new = "NEW" in states and not "ESTABLISHED" in states
        if established or new:
            conditions.append('state == {}'.format(1 if established else 0))

    # At the moment we consider only the rules with the following targets:
    # ACCEPT, DROP, REJECT, SNAT, DNAT, MASQUERADE.
    # REJECT is treated as a DROP.

    rules = []

    if args['target']:

        if args['target'] == 'MASQUERADE':
            out_if = args['out_if']
            if out_if:
                # If the out interface is specified apply a SNAT on its local address
                rules.append((conditions, 'NAT(Id, {})'.format(nat_target(interfaces[out_if][1]))))
            else:
                # If no interface is specified, make a new rule with SNAT for every interface
                # constraining the rule to be `-o` on that interface
                for ifc in interfaces:
                    if '127.0.0.0' in interfaces[ifc][0]: continue # skip `lo`
                    rules.append((conditions + [fwsynthesizer.constrain_interface(interfaces, "dstIp", ifc)],
                                  'NAT(Id, {})'.format(nat_target(interfaces[ifc][1]))))

        elif args['target'] == 'REDIRECT':
            rules.append((conditions, 'NAT(Id:{},Id)'.format(args['nat'])))
        else:
            t = 'NAT(Id, {})'.format(nat_target(args['nat'])) if args['target'] == 'SNAT' else \
                'NAT({}, Id)'.format(nat_target(args['nat'])) if args['target'] == 'DNAT' else \
                'DROP' if args['target'] in ['DROP', 'REJECT'] else \
                'RETURN' if args['target'] == 'RETURN' else \
                'CALL({})'.format(args['target']) if args['target'] != 'ACCEPT' else args['target']

            rules.append((conditions, t))
    elif args['goto_target']:
        t = 'GOTO({})'.format(args['goto_target'])
        rules.append((conditions, t))
    else:
        raise RuntimeError("No Target Specified!")

    return [ '({}, {})'.format('true' if len(conditions) == 0 \
                               else ' && '.join(conditions), t)
            for conditions, t in rules ]

def tables_to_rules(tables, interfaces):
    chains = defaultdict(lambda: {'dp': 'ACCEPT', 'rules': []})

    used_targets = set()

    for table in tables:
        for chain, dp in table.policies:
            chains[(chain, table.name)]['dp'] = dp
        for rule in table.rules:
            # Skip rules without target since they have no effect on the packet's fate
            if (not rule['target']) and (not rule['goto_target']): continue

            used_targets.add(rule['target'])
            used_targets.add(rule['target'])

            if rule['ichain']:
                c = chains[(rule['ichain'][0], table.name)]
                idx = 0 if len(rule['ichain']) == 1 else int(rule['ichain'][1])
                c['rules'].insert(idx, args_to_rule(rule, interfaces))
            else:
                c = chains[(rule['chain'], table.name)]
                c['rules'].append(args_to_rule(rule, interfaces))

        # Add NULL rule to empty but referred ruleset
        for chain, _ in table.policies:
            c = chains[(chain, table.name)]
            if len(c['rules']) < 1:
                c['rules'].append(None)

    # Add CHECK-STATE rules at the beginning of the chains in the nat table. The direction is `->`
    # for chains performing DNAT, `<-` for those performing SNAT.
    for chain in ['PREROUTING', 'OUTPUT']:
        if len(chains[(chain, 'nat')]['rules']) > 0:
            chains[(chain, 'nat')]['rules'].insert(0, ['(state == 1, CHECK-STATE(->))'])
    for chain in ['POSTROUTING', 'INPUT']:
        if len(chains[(chain, 'nat')]['rules']) > 0:
            chains[(chain, 'nat')]['rules'].insert(0, ['(state == 1, CHECK-STATE(<-))'])

    output = ""
    for (chain,table), c in chains.items():
        if len(c['rules']) > 0:
            rules = filter(lambda r: r is not None, c['rules'])

            output += 'CHAIN {}{}:\n'.format(chain_name(chain, table), " "+c['dp'] if c['dp'] != "-" else "")
            output += '\n'.join('\n'.join(rule) for rule in rules)

            # If rules are empyt put a single default rule:
            #  RETURN if we are inside a user defined chain
            #  dp where dp in [ACCEPT, DROP] if we are inside a default chain
            if not rules:
                if chain not in [ d for d,_ in CHAIN_NAMES ]:
                    output += '(true, RETURN)'
                else:
                    output += '(true, {})'.format(c['dp'])

            # If the strict protocols mode is active the default policy
            # ACCEPT accepts only tcp, udp and icmp packets
            if STRICT_PROTOCOLS:
                output += '\n(not (protocol == 6 || protocol == 17 || protocol == 1), DROP)' \
                          if c['dp'] == 'ACCEPT' else ''
            output += '\n\n'

    return output

################################################################################
# QUERY FUNCTIONS

def get_lines(contents):
    ips_lines = [ rule.strip() for rule in contents.split('\n')
                  if rule.startswith("-") or rule.startswith("*") ]
    lines = []
    if not ips_lines[0].startswith("*"): raise RuntimeError("Invalid iptables-save file")
    table = ips_lines[0][1:].strip()
    for line in ips_lines:
        if line.startswith("-"):
            lines.append("-t {} {}".format(table, line))
        else:
            table = line[1:].strip()
    return lines

def delete_rule(tables, rule_number):
    new_tables = copy.deepcopy(tables)

    table_index = 0
    lengths = [ len(table.rules) for table in tables ]
    for l in lengths:
        if rule_number < l:
            break
        rule_number -= l
        table_index += 1
    else:
        raise RuntimeError("Rule `{}' not found!".format(rule_number))

    del new_tables[table_index].rules[rule_number]
    return new_tables
