#!/usr/bin/env python2

import re
import copy
from collections import namedtuple, defaultdict
from parsec import *
from utils import *
import fwsynthesizer

################################################################################
# TYPES

Rule = namedtuple('Rule', ['number', 'action', 'protocol',
                           'src', 'dst', 'options', 'action_target'])

NatDef = namedtuple('NatDef', ['number', 'options'])

################################################################################
# UTILS / GLOBALS

PROTOCOLS   = protocols()
PORTS       = services()
ACCEPT_CMDS = ['allow', 'accept', 'pass', 'permit']
DROP_CMDS   = ['deny', 'drop', 'reset']
KEYWORDS    = ACCEPT_CMDS + DROP_CMDS + ['from', 'to', 'in', 'out', 'log', 'any',
                                         'via', 'setup', 'keep-state', 'mac']


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

identifier  = not_in(regex('[a-zA-Z0-9\-\_\/]+'), KEYWORDS)
ipfw_negate = (lambda p: (optional(regex("not\s+")) + p)
               .parsecmap(lambda (n, s): Negate(s) if n else s))

ipfw_cmd = symbol("ipfw") >> optional(alternative("-q", "-f"))

addr_spec = ip_subnet ^ ip_addr

# IMPORTANT: Tables are not supported
addresses = ipfw_negate(symbol("any") ^ symbol("me") ^ sepBy1(token(ip_subnet ^ ip_addr), symbol(",")))

port_spec = token(port) ^ identifier.parsecmap(port_from_name)
ports     = ipfw_negate(sepBy1(port_spec + optional(symbol("-") >> port_spec), symbol(",")))

skip_opt = spaces >> until(' \n') >> spaces.result(None)

# NOTE: mac/mask, mac&mask are not supported.
# We could add the support simply converting them to intervals before the translation
# but since they are rarely used it's a future work ;P
macaddr = symbol('any') ^ regex(
    '[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}')

@generate
def ipfw_options():
    established = symbol("established").result(("established", True))
    direction   = alternative("in", "out").parsecmap(lambda r: ("direction", r))
    interface   = ((alternative("via", "recv", "xmit") + (identifier << spaces))
                   .parsecmap(lambda t: ("interface", t)))

    mac         = (token(regex('(?i)mac')) >> (macaddr << spaces) + macaddr).parsecmap(
                   lambda (dst_mac, src_mac): ("mac", (src_mac, dst_mac)))

    opts = yield many(interface ^ established ^ direction ^ mac ^ skip_opt)

    # Other options are ignored
    preturn ( defaultdict(lambda: None, filter(lambda r: r is not None, opts)) )

# IMPORTANT: or-block deprecated syntax is not supported
@generate
def ipfw_rule():
    _         = yield ipfw_cmd >> symbol("add")
    rule_numb = yield token(number)
    action    = yield alternative(*(ACCEPT_CMDS + DROP_CMDS
                    + ['check-state', 'count', 'skipto', 'call', 'return', 'nat']))

    action_target = None
    if action in ['call', 'skipto', 'nat']:
        action_target = yield token(number)

    protocol = None
    src      = None
    dst      = None
    if action != 'check-state':
        _        = yield optional(switch("log") << optional(symbol("logamount") << until(" ") << spaces))
        protocol = yield optional(ipfw_negate(number | identifier))
        src      = yield symbol("from") >> addresses + optional(ports)
        dst      = yield symbol("to") >> addresses + optional(ports)

    options = yield ipfw_options

    preturn ( Rule(rule_numb, action, protocol, src, dst, options, action_target) )

# IMPORTANT: LSNAT not supported
@generate
def ipfw_nat():
    pair = lambda s: lambda x: (s, x)

    @generate
    def redirect_port():
        _      = yield symbol("redirect_port")
        proto  = yield token(number | identifier)
        addr_p = yield token((addr_spec << string(":")) + port_spec)
        port   = yield port_spec
        preturn ( ('redirect_port', (proto, addr_p, port)) )

    redirect_addr = (symbol('redirect_addr') >> token(addr_spec) + token(addr_spec)).parsecmap(pair("redirect_addr"))
    ip            = symbol("ip") >> ip_addr.parsecmap(pair("ip"))
    interface     = symbol("if") >> identifier.parsecmap(pair("interface"))

    # NAT declaration
    _       = yield ipfw_cmd >> symbol("nat")
    num     = yield token(number)
    _       = yield symbol("config")
    opts    = yield many(redirect_port ^ redirect_addr ^ interface ^ ip ^ skip_opt)

    options = defaultdict(list)
    for k in opts:
        if k: options[k[0]].append(k[1])
    options = defaultdict(lambda: None, options)

    preturn ( NatDef(num, options) )

ipfw_conf = (optional((comment << space_endls) ^ endl_comments)
             >> many1((ipfw_nat ^ ipfw_rule) << endl_comments))

################################################################################
# CONVERTER

def make_nat_table(rules):
    table = {}
    for rule in rules:
        if isinstance(rule, NatDef):
            table[rule.number] = rule.options
    return table

def convert_rule(rule, interfaces, nat_table, prefix):
    conditions = []

    def format_ports(pair):
        xs = map(lambda x: "{}".format(x.value), filter(lambda x: x is not None, pair))
        return "-".join(xs)


    def append_condition(variable, operator, value, mapper=None):
        cs = []
        negate = isinstance(value, Negate)
        if negate: value = value.value
        if not isinstance(value, list): value = [value]
        for v in filter(lambda x: x, value):
            if isinstance(v, Negate):
                cs.append("not ({} {} {})".format(variable, operator, mapper(v.value) if mapper else v.value))
            else:
                cs.append("{} {} {}".format(variable, operator, mapper(v) if mapper else v))

        if cs:
            if negate:
                conditions.append("not ({})".format(" || ".join(cs)))
            else:
                conditions.append("({})".format(" || ".join(cs))
                                  if len(cs) > 1 else cs[0])

    if rule.src:
        srcip, srcport = rule.src

        if srcip == "me": srcip = [ local for _, (_, local) in interfaces.items()]

        if srcip != "any":
            append_condition("srcIp", "==", srcip)
        append_condition("srcPort", "==", srcport, mapper=format_ports)


    if rule.dst:
        dstip, dstport = rule.dst

        if dstip == "me": dstip = [ local for _, (_, local) in interfaces.items()]

        if dstip != "any":
            append_condition("dstIp", "==", dstip)
        append_condition("dstPort", "==", dstport, mapper=format_ports)



    if rule.protocol not in ['all', 'ip']:
        append_condition("protocol", "==", rule.protocol, mapper=protocol_number)

    # Supported options: established, in, out, recv, xmit, via, mac
    if rule.options['established']:
        append_condition("state", "==", 1)

    if rule.options['mac']:
        src, dst = rule.options['mac']
        if src != 'any':
            append_condition("srcMac", "==", src)
        if dst !='any':
            append_condition("dstMac", "==", dst)


    ext_constraint = lambda var, constraints: "not ({})".format(
        " || ".join("{} == {}".format(var, addr) for addr in constraints))

    # Interface
    # the addresses are constrained using the subnet of the specified interface
    #  source address in case of recv
    #  destination in case of xmit
    #  both in case of via but with logical disjunction

    # If interface subnet is 0.0.0.0/0 constrain ip not to be in all others and interface local
    if rule.options['interface']:
        if_direction, interface = rule.options['interface']

        if if_direction == 'recv':
            conditions.append(fwsynthesizer.constrain_interface(interfaces, "srcIp", interface))
        if if_direction == 'xmit':
            conditions.append(fwsynthesizer.constrain_interface(interfaces, "dstIp", interface))
        if if_direction == 'via':
            raise RuntimeError("Invalid option 'via': rule was not preprocessed!")

    rules = []
    target = None

    if rule.action in ACCEPT_CMDS:   target = "ACCEPT"
    if rule.action in DROP_CMDS:     target = "DROP"
    if rule.action == "return":      target = "RETURN"
    if rule.action == "call":        target = "CALL(R_{}_{})".format(prefix, rule.action_target)
    if rule.action == "skipto":      target = "GOTO(R_{}_{})".format(prefix, rule.action_target)

    if target is not None:
        rules.append((conditions, target))

    if rule.action == "check-state":
        rules.append((conditions + ['state == 1'], "CHECK-STATE(<->)"))

    if rule.action == "nat":
        direction = rule.options['direction']
        isinput = direction is None or direction == 'in'
        isoutput = direction is None or direction == 'out'

        nat = nat_table[rule.action_target]
        for opt in nat:
            if opt == 'redirect_port' and isinput and prefix == 'in':
                for option in nat[opt]:
                    proto, (addr, port), port1 = option
                    target = "NAT({}:{}, Id)".format(addr, port.value)
                    rules.append((conditions + ['protocol == {}'.format(protocol_number(proto)),
                                                'dstPort == {}'.format(port1.value)], target))

            elif opt == 'redirect_addr' and isinput and prefix == 'in':
                for option in nat[opt]:
                    addr, addr1 = option
                    target = "NAT({}, Id)".format(addr)
                    rules.append((conditions + ['dstIp == {}'.format(addr1)], target))

            elif opt == 'interface' and isoutput and prefix == 'out':
                for option in nat[opt]:
                    ifaddr = interfaces[option][1]
                    target = "NAT(Id, {})".format(ifaddr)
                    rules.append((conditions, target))

            elif opt == 'ip' and isoutput and prefix == 'out':
                for option in nat[opt]:
                    target = "NAT(Id, {})".format(option)
                    rules.append((conditions, target))

    return ["({}, {})".format('true' if len(conditions) == 0 else ' && '.join(conditions),
                             target)
            for conditions, target in rules]


def preprocess_rules(rules, interfaces):
    new_rules = []

    for rule in rules:
        if rule.options['interface'] and rule.options['interface'][0] == 'via':
            if_name = rule.options['interface'][1]

            if rule.options['direction'] and rule.options['direction'] == 'in':
                rule.options['interface'] = ('recv', if_name)
                new_rules.append(rule)
            elif rule.options['direction'] and rule.options['direction'] == 'out':
                rule.options['interface'] = ('xmit', if_name)
                new_rules.append(rule)
            else:
                in_rule = rule._replace(number=rule.number + 0.1, options=copy.copy(rule.options))
                out_rule = rule._replace(number=rule.number + 0.2, options=copy.copy(rule.options))
                in_rule.options['direction'] = 'in'
                in_rule.options['interface'] = ('recv', if_name)
                out_rule.options['direction'] = 'out'
                out_rule.options['interface'] = ('xmit', if_name)

                new_rules.extend([in_rule, out_rule])
        else:
            new_rules.append(rule)

    return new_rules

## ip_input ip_output
def convert_rules(rules, interfaces):
    ip_input = []
    ip_output = []

    nat_table = make_nat_table(rules)
    rules = sorted(filter(lambda x: isinstance(x, Rule) and x.action not in ["count"], rules), key=lambda x: x.number)
    rules = preprocess_rules(rules, interfaces)

    for rule in rules:
        direction = rule.options['direction']
        numbered = rule.number, rule
        ip_input.append((rule.number, rule  if direction is None or direction == 'in' else None))
        ip_output.append((rule.number, rule if direction is None or direction == 'out' else None))

    output = ""
    output += "CHAIN ip_input DROP:\n(true, GOTO(R_in_{}))\n\n".format(ip_input[0][0])
    output += "CHAIN ip_output DROP:\n(true, GOTO(R_out_{}))\n\n".format(ip_output[0][0])
    for prefix, chain in [("in", ip_input), ("out", ip_output)]:
        for i in range(len(chain)):
            number, rule = chain[i]

            rules = convert_rule(rule, interfaces, nat_table, prefix) if rule else []

            output += "CHAIN R_{}_{}:\n".format(prefix, number)
            output += "\n".join(rules) + "\n" if rules else ""

            if i == len(chain)-1:
                output += "(true, ACCEPT)"
            else:
                output += "(true, GOTO(R_{}_{}))".format(prefix, chain[i+1][0])
            output += "\n\n"

    return output

################################################################################
# QUERY FUNCTIONS

def get_lines(contents):
    return [ line.strip() for line in contents.split("\n")
             if not line.startswith("#") and line.strip() != ""
             and re.match("ipfw (-q |-f )*add.*", line)]

def delete_rule(rules, rule_number):

    new_rules = []
    target = None

    # Remove rule
    for rule in rules:
        if isinstance(rule, Rule):
            rule_number -=1
            if rule_number == -1:
                target = rule.number
                continue
            else:
                new_rules.append(rule)
        else:
            new_rules.append(rule)

    # Reconnect GOTOS
    for i in range(len(new_rules)):
        rule = new_rules[i]
        if (isinstance(rule, Rule)
            and rule.action not in ['nat', 'rdr']
            and rule.action_target == target):
            new_rules[i] = rule._replace(action_target = new_rules[i+1].number)

    return new_rules
