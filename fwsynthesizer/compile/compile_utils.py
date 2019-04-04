import copy
import struct
import os
import pkgutil
import importlib
import fwsynthesizer
from fwsynthesizer.utils import *

import ipaddr
import itertools
import fwsynthesizer.utils.ipaddr_ext as ipaddr_ext
import fwsynthesizer.utils.macaddr as macaddr

from fwsynthesizer.synthesis import Packet, Rule, Any_IP, Any_Port, Any_Mac, Any_protocol, Any_tag
from fwsynthesizer.synthesis.table_printer import inverse_interval


class CompiledRulesets:
    """
    Define the result of a ruleset generation, i.e. some particular rulesets to be assigned to nodes
    """

    def __init__(self):
        self.Rsnat = []
        self.Rdnat = []
        self.Rnat = []
        self.Rfil = []
        self.Rmark = []


class SimplePacket:
    """
    Define a packet which is a cube (no union of segment, fields are segments)
    """

    def __init__(self, srcIp, srcPort, dstIp, dstPort, srcMAC, dstMAC, protocol, state, mark):
        self.srcIp = srcIp
        self.srcPort = srcPort
        self.dstIp = dstIp
        self.dstPort = dstPort
        self.srcMAC = srcMAC
        self.dstMAC = dstMAC
        self.protocol = protocol
        self.state = state
        self.mark = mark

    def any_srcIp(self):
        return str(self.srcIp[0]) == '0.0.0.0' and str(self.srcIp[1]) == '255.255.255.255'

    def any_srcPort(self):
        return self.srcPort[0] == Any_Port[0][0] and self.srcPort[1] == Any_Port[0][1]

    def any_dstIp(self):
        return str(self.dstIp[0]) == '0.0.0.0' and str(self.dstIp[1]) == '255.255.255.255'

    def any_dstPort(self):
        return self.dstPort[0] == Any_Port[0][0] and self.dstPort[1] == Any_Port[0][1]

    def any_protocol(self):
        return self.protocol[0] == Any_protocol[0][0] and self.protocol[1] == Any_protocol[0][1]

    def any_mark(self):
        return self.mark[0] == Any_tag[0][0] and self.mark[1] == Any_tag[0][1]


def expand_packet(packet):
    """
    Given a complex packet return an equivalent list of simple packets

    Args:
        packet: a complex packet of type Packet
    Returns:
        a list of SimplePacket objects
    """
    exploded_packets_parameters = [
        SimplePacket(xs[0], xs[1], xs[2], xs[3], Any_Mac[0], Any_Mac[0], xs[4], [0, 0], xs[5]) for xs in
        combine_lists([packet.srcIp, packet.srcPort, packet.dstIp, packet.dstPort, packet.protocol, packet.mark])]
    return exploded_packets_parameters


def add_protocols(packet):
    """
    Given a complex packet modify the protocol field:
        if every protocol is accepted, but some ports are specified then only protocols that allow ports are listed
        (tcp, udp, smtp)

    Args:
        packet: a complex packet of type Packet
    Returns:
        nothing (just modify the input packet)
    """
    if (not packet.any_srcPort() or not packet.any_dstPort()) and packet.any_protocol():

        portable_protocols = {6, 17, 132}
        packet.protocol = [[prot, prot] for prot in portable_protocols]


def str_protocol(prot_number):
    """
    Given a protocol number return a string containing its symbolic name if exists, its number otherwise:

    Args:
        prot_number: the number of a protocol
    Returns:
        a string containing the symbolic name of the protocol if exists or the number itself otherwise
    """
    try:
        return protocol_names()[str(prot_number)]
    except KeyError:
        return str(prot_number)


def separates_protocols(complex_packet):
    """
    Given a complex packet modify the protocol field, splitting the ranges of protocols into a union of singleton

    Args:
        complex_packet: the complex packet to work on
    Returns:
        nothing (just modify the input packet)
    """
    if not isinstance(complex_packet.protocol[0], basestring) and not complex_packet.any_protocol():
        new_protocols = []
        for interval in complex_packet.protocol:
            if interval[0] == interval[1]:
                new_protocols += [interval]
            else:
                for p in range(interval[0], interval[1] + 1):
                    new_protocols += [[p, p]]
        complex_packet.protocol = new_protocols


def add_protocol_when_port(complex_packet, protocols):
    """
    Given a complex packet return the same with updated list of protocols if the list of source and destination ports
    does not contain all the ports.
    The new protocols are the one passed as parameter

    Args:
        complex_packet: a Packet
        protocols: list of pairs (list with two elements)
    Returns:
        a Packet
    """
    protocolled_complex_packet = copy.deepcopy(complex_packet)
    if complex_packet.any_srcPort() and complex_packet.any_dstPort():
        return protocolled_complex_packet
    else:
        protocolled_complex_packet = protocols
    return protocolled_complex_packet


def translate_IPranges_to_subnets(complex_packet):
    """
    Given a complex packet, returns an equivalent one in which the IP fields are substituted with lists of
    subnets, i.e. strings of type a.a.a.a/n

    Args:
        complex_packet: a Packet
    Returns:
        a Packet (with lists of strings as srcIP and dstIP)
    """
    masked_complex_packet = copy.deepcopy(complex_packet)
    srcIp = []
    if complex_packet.any_srcIp():
        srcIp.append("any")
    else:
        for ip_range in complex_packet.srcIp:
            if ip_range[0] == ip_range[1]:
                srcIp.append(str(ip_range[0]))
            else:
                # srcIp.append(str(ip_range[0]) + "-" + str(ip_range[1]))
                srcIp += [subnet[0] + '/' + str(subnet[1]) for subnet in
                          IPrange_to_subnets(str(ip_range[0]), str(ip_range[1]))]

    dstIp = []
    if complex_packet.any_dstIp():
        dstIp.append("any")
    else:
        for ip_range in complex_packet.dstIp:
            if ip_range[0] == ip_range[1]:
                dstIp.append(str(ip_range[0]))
            else:
                # dstIp.append(str(ip_range[0]) + "-" + str(ip_range[1]))
                dstIp += [subnet[0] + '/' + str(subnet[1]) for subnet in
                          IPrange_to_subnets(str(ip_range[0]), str(ip_range[1]))]

    masked_complex_packet.srcIp = srcIp
    masked_complex_packet.dstIp = dstIp
    return masked_complex_packet


# ----------------------------------------------- more general utils ------------------------------------------------- #


def file_to_dict(path):
    """
    Given a path for a file, it return a dictionary pairing the first word of each line with a list containing the
    remaining words
    Notes that:
    - it ignores the lines starting with # (comments) and blank ones

    Args:
        path: a string containing the path of the file
    Returns:
         a dictionary with string as keys and values, mapping from protocol number to protocol name (e.g '6' -> 'tcp')
    """
    with open(path) as f:
        return {p[0]: p[1:] for p in
                (re.split("\s+", line.strip()) for line in f
                if line.strip() != '' and not line.startswith('#'))}


# def file_to_dict_rev(path):
#     with open(path) as f:
#         return {p[1:]: p[0] for p in
#                 (re.split("\s+", line.strip()) for line in f
#                 if line.strip() != '' and not line.startswith('#'))}


def protocol_names():
    """
    Returns:
         a dictionary with string as keys and values, mapping from protocol number to protocol name (e.g '6' -> 'tcp')
    """
    return {proto[0]: name for name, proto in file_to_dict('/etc/protocols').items()}


def protocol_numbers():
    """
    Returns:
        a dictionary with string as keys and values, mapping from protocol name to protocol number (e.g 'tcp' -> '6')
    """
    return {name: proto[0] for name, proto in file_to_dict('/etc/protocols').items()}


def port_protocols():
    """
    Returns:
         a dictionary with string as keys and values, mapping from port number to protocol number (e.g '22' -> '6')
    """
    return {port[0].split("/")[0]: protocol_numbers()[port[0].split("/")[1]]
            for name, port in file_to_dict('/etc/services').items()}


def combine_lists(list_of_lists):
    """
    Given a list of lists return a list containing the possible concatenations of items such that the first one is taken
    from the first list, the second one from the second list etc.
    Formally:
        If LL = [L1,L2,L3 ... Ln] where Li are lists then
        list_of_lists(LL) returns a list containing the lists [l1,l2,l3 ... ln] such that li is in Li for i = 1,...n

    Args:
        list_of_lists: a list of lists of any length
    Returns:
        a list of lists
    """
    if not list_of_lists:
        return [[]]
    combinations = []
    combinations_rec = combine_lists(list_of_lists[1:])
    for element in list_of_lists[0]:
        for combination_rec in combinations_rec:
            combination = copy.deepcopy(combination_rec)
            combination.insert(0, element)
            combinations.append(combination)
    return combinations


def IPrange_to_subnets(ip1, ip2):
    """
    Given: a pair of strings (ip1, ip2) representing ip addresses of form XXX.XXX.XXX.XXX,
    returns: a list of pairs (ip, masklen) such that
        the union of all the subnets is exactly the range [ip1, ip2]
    """
    ip1_bin = ip_to_bits(ip1)
    ip2_bin = ip_to_bits(ip2)

    return range_to_masks_bin(ip1_bin, ip2_bin)


# ----------------------------------------- IPrange to subnets implementation ---------------------------------------- #


def bits_to_32bits(b):
    return bin(b)[2:].zfill(32)


def ip_to_bits(ip):
    ip_parts = ip.split(".")
    ip_parts.reverse()
    ip_int = 0
    base = 1
    for part in ip_parts:
        ip_int += int(part) * base
        base *= 256
    return bits_to_32bits(ip_int)
# add zero at the end


def bits_to_ip(b):
    int_b = int(b, 2)
    ip = ''
    for i in range(3, -1, -1):
        part = int_b // (256 ** i)
        int_b = int_b - part * (256 ** i)
        ip = ip + str(part)
        if i > 0:
            ip = ip + '.'
    return ip


def range_to_masks_bin(a, b):
    # print(a, b)
    # print(int(a, 2), int(b, 2))
    if b < a:
        print('errore')
        return []
    if a == b:
        return [(bits_to_ip(a), 32)]
    au = a.rfind('1')
    if au == -1:
        ap = '1' * 32
    else:
        ap = a[:au] + '1' * (32 - au)
    # print(au, ap)
    # print(int(ap, 2))

    if ap == b:
        return [(bits_to_ip(a), au + 1)]
    elif int(ap, 2) < int(b, 2):
        ra = range_to_masks_bin(bits_to_32bits(int(ap, 2) + 1), b)
        ra.append((bits_to_ip(a), au + 1))
        return ra
    else:
        bz = b.rfind('0')
        bp = b[:bz] + '0' * (32 - bz)
        if bp == a:
            return [(bits_to_ip(bp), bz + 1)]
        else:
            rb = range_to_masks_bin(a, bits_to_32bits(int(bp, 2) - 1))
            rb.append((bits_to_ip(bp), bz + 1))
            return rb


# ---------------------------------------- Interval representation functions ----------------------------------------- #

def get_gaps(int_list):
    """ Returns the gaps in a list of intervals: inverts the interval using
        its bottom and top values ad universe boundaries """

    int_list = sorted(int_list, key=lambda x: x[0])
    gaps = []
    for i in range(len(int_list)-1):
        a, b = int_list[i]
        c, d = int_list[i+1]
        gaps.append([b+1, c-1])
    return gaps


def inverse_interval(int_list):
    """ Reverse a list of intervals if the number of gaps is less than
        the number of intervals """
    def subtract(b,a):
        if isinstance(a, ipaddr.IPv4Address) or isinstance(a, macaddr.MACAddress):
            a = int(a)
        if isinstance(b, ipaddr.IPv4Address) or isinstance(b, macaddr.MACAddress):
            b = int(b)
        return b - a

    def max_range(int_list):
        return max(subtract(b,a) for a,b in int_list)

    gaps = get_gaps(int_list)

    if gaps and max_range(int_list) > max_range(gaps) and len(int_list) > len(gaps):
        min_ = min(a for a,_ in int_list)
        max_ = max(b for _,b in int_list)
        return ([min_, max_], gaps)
    return ()


def summarize_ip_interval(a,b):
    "Print an ip range either as a subnet in cdir notation or as interval"

    assert isinstance(a, ipaddr.IPv4Address) and isinstance(b, ipaddr.IPv4Address)
    na = struct.unpack(">I", a.packed)[0]
    nb = struct.unpack(">I", b.packed)[0]

    if na == 0 and nb == 0xffffffff:
        return '0.0.0.0/0'

    rest = list(itertools.dropwhile(lambda (x,y): x==y, zip(bin(na)[2:], bin(nb)[2:])))
    if all(x == '0' and y == '1' for x,y in rest):
        return '{}/{}'.format(a, 32-len(rest))
    return '{}-{}'.format(a,b)


def rewrite_with_aliases(intervals, aliases, exact_match=False):
    """ Rewrite a list of intervals splitting them if they contains aliases """

    def make_range(string):
        try:
            return macaddr.MACAddress(string)
        except ValueError:
            try:
                return ipaddr_ext.IPv4Range(string)
            except ipaddr.AddressValueError:
                return ipaddr.IPv4Network(string)

    def to_interval(b):
        if isinstance(b, ipaddr.IPv4Network):
            return b.ip, ipaddr.IPv4Address(b._ip | (0xffffffff >> b.prefixlen))
        if isinstance(b, ipaddr_ext.IPv4Range):
            return b.ip_from, b.ip_to
        if isinstance(b, ipaddr.IPv4Address):
            return b, b
        raise NotImplemented

    # Populate aliases ranges as IPv4Range or IPv4Network
    ranges = {}
    for name in aliases:
        ranges[name] = make_range(aliases[name])

    def find_alias(address):
        matches = []
        for r,interval in ranges.items():
            if address == interval:
                matches.append( (True, r, interval) )
            # if alias is contained in address
            elif ((not isinstance(address, ipaddr.IPv4Address))
                  and interval in address):
                matches.append( (False, r, interval) )
        return matches

    # WARNING: messy code ahead! (but it gets the job done ;P)
    # Rewrite intervals using aliases
    new_ints = []
    names = {}
    for interval in intervals:
        a,b = interval
        # If they are equal and they match a alias, append the alias to names
        if a == b:
            aliases = find_alias(a)
            if any(exact for exact,_,_ in aliases):
                exact, alias, _ = [m for m in aliases if m[0]][0]
                names[a] = alias
            new_ints.append(interval)
        # If they are not equal, try to match an interval
        else:
            # They match a network?
            s = summarize_ip_interval(a,b)
            rng = make_range(s)
            aliases = find_alias(rng)
            if not aliases or s == '0.0.0.0/0':
                new_ints.append(interval)
            elif any(exact for exact,_,_ in aliases):
                exact, alias, _ = [m for m in aliases if m[0]][0]
                names[s] = alias
                new_ints.append(interval)
            elif not exact_match:
                # No exact match, try to split the interval
                # 1) take only the largest matches
                for match in aliases[::]:
                    _, name, network = match
                    if any(network in mnet and name != mname for _, mname, mnet in aliases):
                        aliases.remove(match)
                # 2) convert interval(a,b) -> (a, alias_bottom-1) U alias U (alias_top +1, b)
                #    for every alias
                aliases = sorted([ (to_interval(network), name) for _, name, network in aliases ],
                                 key=lambda ((x,_),__): x)
                for (n, name) in aliases:
                    if n[0] == n[1]:
                        names[n[0]] = name
                    else:
                        names[summarize_ip_interval(*n)] = name
                intervals = []
                aliases_ints = map(lambda x: x[0], aliases)
                (bottom, _) = aliases_ints[0]
                (_, top) = aliases_ints[-1]
                if a < bottom:
                    intervals.append((a, bottom-1))
                if b > top:
                    intervals.append((b, top+1))
                intervals.extend(aliases_ints)
                intervals.extend(filter(lambda (b,t): b <= t, get_gaps(aliases_ints)))
                new_ints.extend(intervals)
            else:
                new_ints.append(interval)

    # return sorted(new_ints, key=lambda x: x[0]), names
    return new_ints, names

