#!/usr/bin/env python2

import re
from collections import defaultdict

from textx.metamodel import metamodel_from_str
from textx.exceptions import TextXSyntaxError
from ipaddr import IPv4Address, IPv4Network, NetmaskValueError

from utils import protocols, services

################################################################################
# GLOBALS/UTILS

protocols = protocols()
services  = services()

# Additional service names having different names and/or not
# included in `/etc/services`.
cservices = [('lpd', 515), ('netbios-ss', 139), ('cmd', 514), ('www', 80), ('ident', 113)]
for name, port in cservices:
    if not name in services:
        services[name] = port

def read_blocks(contents):
    blocks = contents.split('!')
    return filter(lambda b: len(b.strip()) > 0, blocks)

def translate_action(a):
    return 'ACCEPT' if a == 'permit' else 'DROP'

def port_expr(p):
    if p.__class__.__name__ == 'PortExpr':
        port = services.get(p.port, p.port)
        if p.op == 'lt':
            return '0-{}'.format(port-1)
        elif p.op == 'gt':
            return '{}-65535'.format(port+1)
        else:
            return port
    else:
        from_port = services.get(p.from_port, p.from_port)
        to_port = services.get(p.to_port, p.to_port)
        return '{}-{}'.format(from_port, to_port)

################################################################################
# CLASSES

class Subnet(object):
    def __init__(self, parent, ip, mask):
        self.parent = parent
        self.ip = ip
        self.mask = mask

    def __str__(self):
        addr = '{}/{}'.format(self.ip, self.mask)
        try:
            return IPv4Network(addr, strict=False).with_prefixlen
        except NetmaskValueError:
            # TODO
            # Some configurations contain particular hostmask that are
            # rejected by the ipaddr module, e.g. `0.0.255.0`.
            # I'm not sure if they are correct, for now I reverse them
            # by hand.

            # rev_mask = '.'.join(str(255 - int(b)) for b in self.mask.split('.'))
            # return '{}/{}'.format(self.ip, rev_mask)

            # (I don't think it is a valid netmask: for now i use only the address)
            # (to get a better result we could try to insert all addresses one by one)
            # (EX: 128.12.0.1/255.255.0.255 -> 128.12.x.1 where x in {0..255})
            return '{}'.format(self.ip)


class StandardAclRule(object):
    def __init__(self, parent, id, action, src_ip):
        self.parent = parent
        self.id = id
        self.action = action
        self.src_ip = src_ip

    def conds(self):
        cond = 'true' if self.src_ip == 'any' else 'srcIp == {}'.format(self.src_ip)
        return cond

    def translate(self):
        return '({}, {})'.format(self.conds(), translate_action(self.action))


class ExtendedAclRule(object):
    def __init__(self, parent, id, action, proto, src_ip, src_port, dst_ip, dst_port, established):
        self.parent = parent
        self.id = id
        self.action = action
        self.proto = proto
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.established = established

    def conds(self):
        conds = []
        if self.proto != 'ip':
            conds.append('protocol == {}'.format(protocols[self.proto]))
        if self.src_ip != 'any':
            conds.append('srcIp == {}'.format(self.src_ip))
        if self.src_port is not None:
            conds.append('srcPort == {}'.format(port_expr(self.src_port)))
        if self.dst_ip != 'any':
            conds.append('dstIp == {}'.format(self.dst_ip))
        if self.dst_port is not None:
            conds.append('dstPort == {}'.format(port_expr(self.dst_port)))
        if self.established:
            conds.append('state == 1')
        return 'true' if len(conds) == 0 else ' && '.join(conds)

    def translate(self):
        return '({}, {})'.format(self.conds(),
                                 translate_action(self.action))

class StandardAcl(object):
    def __init__(self, parent, rules):
        self.parent = parent
        self.rules = rules

    def translate(self, acls, acl_conds):
        for r in self.rules:
            if r.__class__.__name__ != 'Remark':
                acls[r.id].append(r.translate())
                acl_conds[r.id].append(r.conds())


class NamedAcl(object):
    def __init__(self, parent, name, rules):
        self.parent = parent
        self.name = name
        self.rules = rules

    def translate(self, acls):
        acls[self.name] = [r.translate() for r in self.rules if r.__class__.__name__ != 'Remark']
        acl_conds[self.name] = [r.conds() for r in self.rules if r.__class__.__name__ != 'Remark']


class Interface(object):
    def __init__(self, parent, name, settings):
        self.parent = parent
        self.name = name
        self.settings = settings
        self.subnet = None
        self.acls = []
        self.nat = None
        for s in self.settings:
            if s.__class__.__name__ == 'Subnet':
                self.subnet = s
            elif s.__class__.__name__ == 'IfaceAcl':
                self.acls.append((s.acl, s.dir))
            elif s.__class__.__name__ == 'IfaceNat':
                self.nat = s.direction

    def __str__(self):
        if self.subnet is not None:
            return '{}\nSubnet: {}/{}\nNAT: {}\nAcls: {}'.format(
                self.name, self.subnet.ip, self.subnet.mask, self.nat, self.acls)
        return self.name

    def __repr__(self):
        return self.__str__()

class Remark(object):
    def __init__(self, parent, comment):
        self.parent = parent
        self.comment = comment

class Nat(object):
    def __init__(self, parent, direction, list_id, if_name, proto, src_ip,src_port,dst_ip,dst_port):
        self.parent = parent
        self.direction = direction
        self.list_id  = list_id
        self.if_name  = if_name
        self.proto    = proto
        self.src_ip   = src_ip
        self.src_port = src_port
        self.dst_ip   = dst_ip
        self.dst_port = dst_port

class Route(object):
    def __init__(self, parent, subnet, gateway):
        self.parent = parent
        self.subnet = subnet
        self.gateway = gateway


classes = [
    Subnet, StandardAclRule, ExtendedAclRule, StandardAcl, NamedAcl, Interface, Remark, Nat, Route
]

################################################################################
# GRAMMAR

grammar='''
/*
 * We are interested only in parts of the configuration:
 * - the various type of ACLs supported by Cisco devices
 * - interface specifications, where ACLs are applied to
 *    packets passing through the interface.
 */
Config:
    conf_blocks*=ConfigBlock
;

ConfigBlock:
    StandardAcl | NamedAcl | Interface | Nat | Route | End
;

/*
 * Standard ACL rules only consider the source IP address of the packet.
 *
 *   http://www.cisco.com/c/en/us/support/docs/security/ios-firewall/23602-confaccesslists.html#standacl
 */
StandardAclRule:
    'access-list' id=INT action=Action src_ip=Endpoint
;

Remark:
    ('access-list' INT)? 'remark' comment=/.*\n/
;

StandardRule:
  StandardAclRule | Remark
;

/*
 * Extended ACL rules may pose contraints on several packet features,
 * including source and destination
 * addresses and ports.
 *
 *   http://www.cisco.com/c/en/us/support/docs/security/ios-firewall/23602-confaccesslists.html#extacls
 */
ExtendedAclRule:
    ('access-list' id=INT)? action=Action proto=Protocol
    src_ip=Endpoint (src_port=PortSpec)? dst_ip=Endpoint (dst_port=PortSpec)? (established='established')?
    ( 'log-input' | 'log' )?
;


/*
 * A standard ACL consists of a list of standard or extended ACL rules.
 */
Rule:
    StandardAclRule | ExtendedRule
;

StandardAcl:
    rules+=Rule
;

/*
 * Named ACLs allow to group several rules under a control list with a human-readable name.
 *
 *   http://www.cisco.com/c/en/us/support/docs/security/ios-firewall/23602-confaccesslists.html#ipnamacl
 */
ExtendedRule:
    ExtendedAclRule | Remark
;

NamedAcl:
    'ip' 'access-list' 'extended' name=AclId rules+=ExtendedRule (/\s+/ ExtendedRule)*
;

Action:
    'permit' | 'deny'
;

Protocol:
    'ip' | 'icmp' | 'tcp' | 'udp'
;

/* Constraints on addresses may be specified using:
 * - simple IP addresses;
 * - using subnet syntax.
 * For simplicity we don't check whether the matched string is a valid IP address/mask.
 */
Ip:
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
;

Mask:
    Ip | ('/'- INT)
;

Subnet:
    ip=Ip
    mask=Mask
;

Endpoint:
    Subnet | ('host'?- Ip) | 'any'
;

/*
 * Constraints on ports can be specified in terms of a port range or using
 * comparison operators.
 * A port can be specified using the number or the name of the
 * service typically associated to it,
 * according to the mapping given in the file `/etc/services`.
 */
Operator:
    'eq' | 'gt' | 'lt'
;

Port:
    INT | /[A-Za-z\-_]+/
;

PortSpec:
    PortExpr | PortRange
;

PortExpr:
    op=Operator port=Port
;

PortRange:
    'range' from_port=Port to_port=Port
;

/*
 * An interface specification may comprise the declaration of which IP
 * addresses are used in the subnet, which ACLs should be inforced
 * (and in which direction) and possibly other settings that we disregard
 * at the moment.
 */
Interface:
    'interface' name=IfaceName settings*=IfaceSettings
;

IfaceName:
    /[A-Za-z0-9\/.]+/
;

IfaceSettings:
    IfaceSubnet | IfaceAcl | IfaceNat | /.*/
;

IfaceSubnet:
    'ip'- 'address'- Subnet !'secondary'
;

AclId:
   INT | /[A-Za-z\-_]+/
;

Direction:
    'in' | 'out'
;

IfaceAcl:
    'ip' 'access-group' acl=AclId dir=Direction
;

IfaceNat:
    'ip' 'nat' direction=NatDirection
;

NatDirection:
    'inside' | 'outside'
;

IfName:
    /[a-zA-z0-9\-_\/]+/
;

Nat:
    'ip' 'nat' direction=NatDirection 'source'
      ( (('list' list_id=INT)? 'interface' if_name=IfName 'overload'?)
      | ('static' proto=Protocol? src_ip=Ip src_port=Port?
                                  dst_ip=Ip dst_port=Port? 'extendable'?))
;

Route:
   'ip' 'route' subnet=Endpoint gateway=Ip
;

End:
    'end'
;

'''

mm = metamodel_from_str(grammar, classes=classes, auto_init_attributes=False)

################################################################################
# CONFIG PARSING

def strip_comments(contents):
    return re.sub("\!.*\n", "!\n", contents)

def parse_file(contents):
    acls = defaultdict(list)
    acl_conds = defaultdict(list)
    interfaces = {}
    nats = []
    routes = []

    contents = strip_comments(contents)

    for block in read_blocks(contents):
        try:
            m = mm.model_from_str(block)
            for b in m.conf_blocks:
                if b.__class__.__name__ == 'Interface':
                    interfaces[b.name] = b
                elif b.__class__.__name__ == 'Nat':
                    nats.append(b)
                elif b.__class__.__name__ == 'Route':
                    routes.append(b)
                elif b == 'end':
                    pass
                else:
                    b.translate(acls, acl_conds)
        except TextXSyntaxError as e:
            print "<!> Warning: unsupported syntax. Skipping... {}".format(e)
            pass

    return interfaces, acls, acl_conds, nats, routes

def convert_file(interfaces, acls, acl_conds, nats, routes):
    used_acls = set()
    output = ""

    local_addresses = [ ifc.subnet.ip for _,ifc in interfaces.items() if ifc.subnet ]

    # Get default route
    ifcs = filter(lambda (n,ifc): ifc.subnet, interfaces.items())
    try:
        default_route = [r for r in routes if r.subnet.mask == '0.0.0.0'][0] # Only the first one
        for _,ifc in ifcs:
            if IPv4Address(default_route.gateway) in IPv4Network(str(ifc.subnet)):
                ifc.subnet.mask = '0.0.0.0'
                break
        else:
            print "<!> Warning: Cannot find interface for the default gateway!"
    except IndexError:
        print "<!> Warning: no default route!"

    ifcs = sorted(ifcs, key=lambda (_,ifc): IPv4Network(ifc.subnet).numhosts)

    # Interfaces switch/case
    for chain, acldir, variable in [('InF', 'in', 'srcIp'), ('OutF', 'out', 'dstIp')]:
        output += "CHAIN {} DROP:\n".format(chain)
        for _, ifc in ifcs:
            if ifc.acls:
                dir_acls = filter(lambda (n,d): d == acldir, ifc.acls)
                for name, direction in dir_acls:
                    if name not in acls:
                        output += "({} == {}, ACCEPT)\n".format(variable, ifc.subnet)
                    else:
                        output += "({} == {}, GOTO(ACL_{}))\n".format(
                            variable, ifc.subnet, name)
                        used_acls.add(name)
            else:
                output += "({} == {}, ACCEPT)\n".format(variable, ifc.subnet)
        output += "\n"

    # NATs
    inside_subnets = [ ifc.subnet for _,ifc in ifcs if ifc.nat and ifc.nat == 'inside' ]
    outside_subnets = [ ifc.subnet for _,ifc in ifcs if ifc.nat and ifc.nat == 'outside' ]

    nats_inside = [ n for n in nats if n.direction == 'inside' ]
    nats_outside = [ n for n in nats if n.direction == 'outside' ]

    rules_inside = []
    rules_outside = []

    def nat_match(nat, outside=False):
        if outside:
            # TODO: support NAT outside
            raise RuntimeError("NAT outside is not currently implemented.")

        # not static
        if nat.list_id:
            acl = acl_conds[nat.list_id]
            cond_in = [' || '.join('({})'.format(c) for c in acl)]
            cond_in.append('not({})'.format(
                ' || '.join('(dstIp == {})'.format(s)
                            for s in inside_subnets + map(lambda x: x.ip, outside_subnets))))
            target_ip = interfaces[nat.if_name].subnet.ip
            target_in = 'NAT(Id, {})'.format(target_ip)
            rules_inside.append('({}, {})'.format(' && '.join(cond_in), target_in))
            rules_outside.insert(0,'(state == 1, CHECK-STATE(->))')
        # static
        else:
            conds_in = []
            conds_out = []
            target_in = 'NAT(Id, {}:{})'.format(
                nat.dst_ip, 'Id' if nat.dst_port == nat.src_port else nat.dst_port)
            target_out = 'NAT({}:{}, Id)'.format(
                nat.src_ip, 'Id' if nat.dst_port == nat.src_port else nat.src_port)
            if nat.proto:
                conds_in.append('protocol == {}'.format(nat.proto))
                conds_out.append('protocol == {}'.format(nat.proto))
            conds_in.append('srcIp == {}'.format(nat.src_ip))
            conds_out.append('dstIp == {}'.format(nat.dst_ip))
            if nat.proto and nat.src_port and nat.dst_port:
                conds_in.append('srcPort == {}'.format(nat.src_port))
                conds_out.append('dstPort == {}'.format(nat.dst_port))
            conds_in.append('not({})'.format(
                ' || '.join('(dstIp == {})'.format(s)
                            for s in inside_subnets + map(lambda x: x.ip, outside_subnets))))
            conds_out.append('not({})'.format(
                ' || '.join('(srcIp == {})'.format(s)
                            for s in inside_subnets + map(lambda x: x.ip, outside_subnets))))
            rules_inside.append('({}, {})'.format(' && '.join(conds_in), target_in))
            rules_outside.append('({}, {})'.format(' && '.join(conds_out), target_out))

    for n in nats_inside:
        nat_match(n)
    for n in nats_outside:
        nat_match(n, outside=True)

    # output nats
    output += 'CHAIN InN ACCEPT:\n'
    output += '\n'.join(rules_inside)
    output += '\n(true, ACCEPT)\n\n'

    output += 'CHAIN OutN ACCEPT:\n'
    output += '\n'.join(rules_outside)
    output += '\n(true, ACCEPT)\n\n'

    # ACLs
    for name, acl in acls.items():
        if name in used_acls:
            output += "CHAIN ACL_{} DROP:\n".format(name)
            for rule in acl:
                output += str(rule) + "\n"
            output += "(true, DROP)\n\n"

    return output

################################################################################
# TESTS


if __name__ == '__main__':
    import fwsynthesizer
    converter = fwsynthesizer.converter(
        parser=parse_file,
        converter=lambda x,_: convert_file(*x)
    )

    contents = open('../../examples/cisco/cisco_ok.txt').read()

    print converter(contents=contents, interfaces=None)

    p = parse_file(contents)
    print p
