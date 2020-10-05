#!/usr/bin/env python2

import ipaddr
import fwsynthesizer.utils as utils
import fwsynthesizer.utils.macaddr as macaddr
import table_printer

from HaPy import FireWallSynthesizer as Synthesis


Any_IP = [[0, 0xffffffff]]
Any_Port = [[0, 0xffff]]
Any_Mac = [[0, 0xffffffffffff]]
Any_protocol = [[0, 255]]
Any_tag = [[0, 65535]]

LocalFlag  = utils.enum('BOTH', 'LOCAL', 'NOLOCAL')
NatFlag    = utils.enum('ALL', 'FILTER', 'NAT')
TableStyle = utils.enum(UNICODE='unicode', ASCII='ascii', TEX='latex', HTML='html', JSON='json')


class Firewall:
    "Firewall Object that can be synthesized and analyzed"

    def __init__(self, name, diagram, chains, local_addresses):
        """
        Make a Firewall Object

        Args:
            name (str): name of the firewall (displayed in parser error messages)
            diagram (str): diagram file path
            chains (str): chain file contents in the generic language
            local_addresses (List[str]): local addresses of the firewall
        """
        self.name = name
        self.locals = local_addresses
        self.__fw = Synthesis.make_firewall(diagram, name, chains, local_addresses)

    def synthesize(self, local_src=LocalFlag.BOTH, local_dst=LocalFlag.BOTH, query="true"):
        """
        Synthesize a specification

        Args:
            local_src (LocalFlag): constraint for the source address
            local_dst (LocalFlag): constraint for the destination address
            query (str): generic constraint expressed in the query language
        Returns:
            SynthesisOutput object
        """

        rules = Synthesis.synthesize(self.__fw, self.locals, local_src, local_dst, query)

        return SynthesisOutput(self, rules)

    def synthesize_nd(self, local_src=LocalFlag.BOTH, local_dst=LocalFlag.BOTH, query="true"):
        """
        Synthesize non-deterministically dropped packets

         Args:
            local_src (LocalFlag): constraint for the source address
            local_dst (LocalFlag): constraint for the destination address
            query (str): generic constraint expressed in the query language
        Returns:
            SynthesisOutput object
        """
        rules = Synthesis.synthesize_nd(self.__fw, self.locals, local_src, local_dst, query)
        return SynthesisOutput(self, rules)

    def implication(self, other, local_src=LocalFlag.BOTH, local_dst=LocalFlag.BOTH, query="true"):
        """
        Check for implication between two firewalls

        Args:
            other (Firewall): other firewall to check
            local_src (LocalFlag): constraint for the source address
            local_dst (LocalFlag): constraint for the destination address
            query (str): generic constraint expressed in the query language
        Returns:
            boolean value if the second firewall is implied by `self`
        """

        return Synthesis.implication(self.__fw, other.__fw, self.locals, local_src, local_dst, query)

    def equivalence(self, other, local_src=LocalFlag.BOTH, local_dst=LocalFlag.BOTH, query="true"):
        """
        Check for equivalence between two firewalls

        Args:
            other (Firewall): other firewall to check
            local_src (LocalFlag): constraint for the source address
            local_dst (LocalFlag): constraint for the destination address
            query (str): generic constraint expressed in the query language
        Returns:
            boolean value if the second firewall is equivalent to `self`
        """
        return Synthesis.equivalence(self.__fw, other.__fw, self.locals, local_src, local_dst, query)

    def difference(self, other, local_src=LocalFlag.BOTH, local_dst=LocalFlag.BOTH, query="true"):
        """
        Synthesize the difference between two firealls

        Args:
            local_src (LocalFlag): constraint for the source address
            local_dst (LocalFlag): constraint for the destination address
            query (str): generic constraint expressed in the query language
        Returns:
            DiffOutput object
        """
        plus, minus = Synthesis.difference(self.__fw, other.__fw, self.locals, local_src, local_dst, query)
        return DiffOutput(self, other, plus, minus)


class Packet(object):
    "Packet Object"

    def __init__(self, srcIp, srcPort, dstIp, dstPort, srcMac, dstMac, protocol, state, mark=[[0, 0]]):
        "Make a Packet form list of intervals"

        self.srcIp = [ [ipaddr.IPv4Address(ip & 0xffffffff) for ip in ips] for ips in srcIp ]
        self.dstIp = [ [ipaddr.IPv4Address(ip & 0xffffffff) for ip in ips] for ips in dstIp ]
        self.srcPort = [ [port & 0xffff for port in ports] for ports in srcPort]
        self.dstPort = [ [port & 0xffff for port in ports] for ports in dstPort]
        self.srcMac = [ [macaddr.MACAddress(mac & 0xffffffffffff) for mac in macs] for macs in srcMac ]
        self.dstMac = [ [macaddr.MACAddress(mac & 0xffffffffffff) for mac in macs] for macs in dstMac ]
        self.protocol = protocol
        self.state = state
        self.mark = mark

    def __repr__(self):
        return "#<Packet {}:{} => {}:{} [{}, {}, {}] [{}]>".format(
            self.srcIp, self.srcPort, self.dstIp, self.dstPort,
            self.srcMac, self.dstMac, self.protocol, self.state)

    def any_srcIp(self):
        return str(self.srcIp[0][0]) == '0.0.0.0' and str(self.srcIp[0][1]) == '255.255.255.255'

    def any_srcPort(self):
        return self.srcPort[0][0] == Any_Port[0][0] and self.srcPort[0][1] == Any_Port[0][1]

    def any_dstIp(self):
        return str(self.dstIp[0][0]) == '0.0.0.0' and str(self.dstIp[0][1]) == '255.255.255.255'

    def any_dstPort(self):
        return self.dstPort[0][0] == Any_Port[0][0] and self.dstPort[0][1] == Any_Port[0][1]

    def any_protocol(self):
        return self.protocol[0][0] == Any_protocol[0][0] and self.protocol[0][1] == Any_protocol[0][1]

    def any_mark(self):
        return self.mark[0][0] == Any_tag[0][0] and self.mark[0][1] == Any_tag[0][1]


class Rule(object):
    "FWS Rule Object"

    def __init__(self, packet_in, packet_out):
        "Make a Rule form two packets"

        self.packet_in = packet_in
        self.packet_out = packet_out

        self.srcIp = packet_in.srcIp
        self.dstIp = packet_in.dstIp
        self.srcPort = packet_in.srcPort
        self.dstPort = packet_in.dstPort
        self.srcMac = packet_in.srcMac
        self.dstMac = packet_in.dstMac
        self.protocol = packet_in.protocol
        self.state = packet_in.state
        self.snatIp = packet_out.srcIp
        self.snatPort = packet_out.srcPort
        self.dnatIp = packet_out.dstIp
        self.dnatPort = packet_out.dstPort

        self.type = 'NAT' if any((self.snatIp, self.snatPort, self.dnatIp, self.dnatPort)) \
                    else 'FILTER'

    def __repr__(self):
        return "#<Rule {} {} {}>".format(self.type, self.packet_in, self.packet_out)


class SynthesisOutput:
    "Firewall synthesis output"

    def __init__(self, fw, rules):
        self.firewall = fw
        self.__rules = rules

    def get_rules(self):
        "Get the rules as lists of Rule objects"
        rules = [ Synthesis.mrule_list(r) for r in self.__rules ]
        return [ Rule(Packet(*pin), Packet(*pout)) for pin,pout in rules ]

    def print_table(self, table_style=TableStyle.UNICODE, local_src=LocalFlag.BOTH,
                    local_dst=LocalFlag.BOTH, nat=NatFlag.ALL,
                     projection=[], aliases={}):
        """
        Print the table showing the synthesis

        Args:
            table_style (TableStyle): select the style of the table
            local_src (LocalFlag): hide local addresses if explicitly removed from ranges in the source IP
            local_dst (LocalFlag): hide local addresses if explicitly removed from ranges in the destination IP
            nat (NatFlag): show only nat or filter rules
        """
        rules = self.get_rules()
        hide_src = local_src == LocalFlag.NOLOCAL
        hide_dst = local_dst == LocalFlag.NOLOCAL
        hide_nats = nat == NatFlag.FILTER
        hide_filters = nat == NatFlag.NAT
        table_printer.print_table(
            rules, table_style, [ipaddr.IPv4Address(a) for a in self.firewall.locals],
            hide_src, hide_dst, hide_nats, hide_filters,
            projection, aliases=aliases)

    def get_rules_no_duplicates(self):
        rules = [Synthesis.mrule_list(r) for r in self.__rules]

        for rule in rules:
            for pkt in rule:
                for field in pkt:
                    field.sort()
        change = True
        while change:
            change = False
            i = 0
            while i < len(rules) - 1:
                j = i + 1
                while j < len(rules):

                    if rules[i][1] != rules[j][1]:
                        j = j + 1
                        continue
                    diff = None
                    for z in range(0, len(rules[i][0])):
                        if rules[i][0][z] != rules[j][0][z]:
                            if diff is not None:
                                diff = None
                                break
                            diff = z
                    #  When I make the union, len change and also my position
                    if diff is not None:
                        change = True
                        rules[i][0][diff].sort()
                        rules[j][0][diff].sort()
                        union_z = segment_set_union(rules[i][0][diff], rules[j][0][diff])
                        rules[i][0][diff] = union_z
                        del rules[j]
                        j = i + 1
                    else:
                        j = j + 1
                i = i + 1
        return [Rule(Packet(*pin), Packet(*pout)) for pin, pout in rules]

    def print_table_no_duplicates(self):
        table_style = TableStyle.UNICODE
        local_src = LocalFlag.BOTH
        local_dst = LocalFlag.BOTH
        nat = NatFlag.ALL
        projection = []
        aliases = {}

        rules = self.get_rules_no_duplicates()
        hide_src = local_src == LocalFlag.NOLOCAL
        hide_dst = local_dst == LocalFlag.NOLOCAL
        hide_nats = nat == NatFlag.FILTER
        hide_filters = nat == NatFlag.NAT

        table_printer.print_table(
            rules, table_style, [ipaddr.IPv4Address(a) for a in self.firewall.locals],
            hide_src, hide_dst, hide_nats, hide_filters,
            projection, aliases=aliases)


class DiffOutput:
    "Firewall difference output"
    def __init__(self, fw, fw1, plus, minus):
        self.firewall  = fw
        self.firewall2 = fw1
        self.__plus = plus
        self.__minus = minus

    def get_rules(self):
        "Get the rules as tuple of lists of Rule objects"
        plus = [ Synthesis.mrule_list(r) for r in self.__plus ]
        minus = [ Synthesis.mrule_list(r) for r in self.__minus ]
        return ( [ Rule(Packet(*pin), Packet(*pout)) for pin,pout in plus ],
                 [ Rule(Packet(*pin), Packet(*pout)) for pin,pout in minus ] )

    def print_table(self, table_style=TableStyle.UNICODE,
                    local_src=LocalFlag.BOTH, local_dst=LocalFlag.BOTH, projection=[], aliases={}):
        """
        Print the table showing the synthesis

        Args:
            table_style (TableStyle): select the style of the table
            local_src (LocalFlag): hide local addresses if explicitly removed from ranges in the source IP
            local_dst (LocalFlag): hide local addresses if explicitly removed from ranges in the destination IP
        """
        plus, minus = self.get_rules()
        hide_src = local_src == LocalFlag.NOLOCAL
        hide_dst = local_dst == LocalFlag.NOLOCAL
        table_printer.print_diff_table(
            self.firewall.name, self.firewall2.name, plus, minus,
            table_style, [ipaddr.IPv4Address(a) for a in self.firewall.locals],
            hide_src, hide_dst, projection=projection, aliases=aliases)



def segment_set_union(set1, set2):
    if set1 == []:
        return set2
    if set2 == []:
        return set1
    # there is an intersection and they are not adjacent
    if (set1[0][0] <= set2[0][0] and set1[0][1] >= set2[0][0] - 1) or \
        (set2[0][0] <= set1[0][0] and set2[0][1] >= set1[0][0] - 1):
            if set1[0][1] > set2[0][1]:
                return segment_set_union([[min(set1[0][0], set2[0][0]), set1[0][1]]] + set1[1:], set2[1:])
            else:
                return segment_set_union(set1[1:], [[min(set1[0][0], set2[0][0]), set2[0][1]]] + set2[1:])
    # else there is no intersection
    if set1[0][0] <= set2[0][0]:
        return set1[:1] + segment_set_union(set1[1:], set2)
    else:
        return set2[:1] + segment_set_union(set1, set2[1:])
