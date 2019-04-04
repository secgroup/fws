from compile_utils import *


def ruleset_generation_iptables(rules):
    """
    Given a list of rules produces different rulesets for compilation

    Args:
        rules: list of Rule objects representing the policy
    Returns:
        CompiledRuleset object
    """

    rulesets = CompiledRulesets()
    tag = 0
    for rule in rules:
        if rule.packet_in.state == [[0, 1]]:
            rule.packet_in.state = [[0, 0]]
        if rule.packet_in.state != [[0, 0]]:
            continue

        if rule.type == 'FILTER':
            rulesets.Rfil.append(rule)
        else:
            # Since we will mark packets as first thing we avoid to check if the mark is already applied, in Rmark the
            # tag field is Any instead of []
            rulesets.Rmark.append(Rule(rule.packet_in,  Packet([], [], [], [], [], [], [], [], [[tag, tag]])))

            packet_to_nat = \
                Packet(Any_IP, Any_Port, Any_IP, Any_Port, Any_Mac, Any_Mac, Any_protocol, [[0, 0]], [[tag, tag]])

            rulesets.Rfil.append(Rule(packet_to_nat, Packet([], [], [], [], [], [], [], [], [])))
            if rule.packet_out.srcIp != [] or rule.packet_out.srcPort != []:
                snated_packet = copy.deepcopy(rule.packet_out)
                snated_packet.dstIp = [[]]
                snated_packet.dstPort = [[]]
                rulesets.Rsnat.append(Rule(packet_to_nat, snated_packet))

            if rule.packet_out.dstIp != [] or rule.packet_out.dstPort != []:
                dnated_packet = copy.deepcopy(rule.packet_out)
                dnated_packet.srcIp = [[]]
                dnated_packet.srcPort = [[]]
                rulesets.Rdnat.append(Rule(packet_to_nat, dnated_packet))

            tag += 1
    return rulesets


def iptables_scan_match(complex_packet):
    """
    Scan a given complex packet, returning a list of iptables match such that the packet contains the values that
    verifies at least one of the matches.

    Args:
        complex_packet: on object of type Packet
    Returns:
        a list of string containing iptables matches
    """
    add_protocols(complex_packet)
    # compute inverse packt to choose the best representation
    inverse_pkt = [inverse_interval(complex_packet.srcIp), inverse_interval(complex_packet.srcPort),
                   inverse_interval(complex_packet.dstIp), inverse_interval(complex_packet.dstPort),
                   inverse_interval(complex_packet.protocol), inverse_interval(complex_packet.mark)]

    # this is needed to check that the first part of the reverse packet contain all possible values
    minimum = ["0.0.0.0", "0", "0.0.0.0", "0", "0", "0"]
    maximum = ["255.255.255.255", "65535", "255.255.255.255", "65535", "255", "1"]

    # Todo post refactoring, for the momento we do it only for protocols because range are not supported
    # for each field, if the value can be expressed as a negation of an interval then we substitute a string
    #   representing that negation inside the field of the packet
    for i in range(len(inverse_pkt)):
        inverse_field = inverse_pkt[i]
        if inverse_field != () and \
                str(inverse_field[0][0]) == minimum[i] and str(inverse_field[0][1]) == maximum[i] and \
                len(inverse_field[1]) == 1:

            segment_to_negate = inverse_field[1][0]
            if i == 0 or i == 2:
                negated_subnet = IPrange_to_subnets(str(segment_to_negate[0]), str(segment_to_negate[1]))
                if negated_subnet[0][1] == 32:
                    negated_value = str(negated_subnet[0][0])
                else:
                    negated_value = str(negated_subnet[0][0]) + '/' + str(negated_subnet[0][1])
            else:
                if segment_to_negate[0] == segment_to_negate[1]:
                    negated_value = str(segment_to_negate[0])
                else:
                    negated_value = str(segment_to_negate[0]) + '-' + str(segment_to_negate[1])

            # if i == 0:
            #     complex_packet.srcIp = ["" + negated_value]
            # if i == 1:
            #     complex_packet.srcPort = ["" + negated_value]
            # if i == 2:
            #     complex_packet.dstIp = ["" + negated_value]
            # if i == 3:
            #     # print(negated_value)
            #     complex_packet.dstPort = ["" + negated_value]
            if i == 4:
                # print(negated_value, protocol_names()[str(negated_value[0])])
                negated_protocol = str_protocol(negated_value[0])
                complex_packet.protocol = ["" + negated_protocol]

    # separates ranges of protocols
    separates_protocols(complex_packet)

    packets = expand_packet(complex_packet)
    # packets = filter(coherent_ports_protocol_packet, packets)
    matches = []

    for packet in packets:
        match = ''
        match_iprange = False

        if packet.srcIp[0] == packet.srcIp[1]:
            match += " -s " + str(packet.srcIp[0])
        elif not packet.any_srcIp():
            match_iprange = True
            match += " --match iprange --src-range " + str(packet.srcIp[0]) + "-" + str(packet.srcIp[1])

        if packet.srcPort[0] == packet.srcPort[1]:
            match += " --sport " + str(packet.srcPort[0])
        elif not packet.any_srcPort():
            match += " --sport " + str(packet.srcPort[0]) + ":" + str(packet.srcPort[1])

        if packet.dstIp[0] == packet.dstIp[1]:
            match += " -d " + str(packet.dstIp[0])
        elif not packet.any_dstIp():
            if not match_iprange:
                match += " --match iprange"
            match += " --dst-range " + str(packet.dstIp[0]) + "-" + str(packet.dstIp[1])

        if packet.dstPort[0] == packet.dstPort[1]:
            match += " --dport " + str(packet.dstPort[0])
        elif not packet.any_dstPort():
            match += " --dport " + str(packet.dstPort[0]) + ":" + str(packet.dstPort[1])

        # thanks to preprocessing it is not possible to have ranges
        if isinstance(packet.protocol, basestring):
            print(packet.protocol)
            match += " ! -p " + str(packet.protocol)
        elif not packet.any_protocol():
            match += " -p " + str_protocol(packet.protocol[0])

        # since we have to compile only configurations produced by ours algorithm:
        # we consider only one possible mark for each packet
        if len(packet.mark) > 0 and not packet.any_mark():
            match += " --match mark --mark " + str(packet.mark[0])

        matches.append(match)
    return matches


def concretise_iptables(rulesets):
    """
    Given a compiled ruleset representing an IFCL firewall for iptables, translates it in the target configuration
    language (i.e. iptables own language)

    Args:
        rulesets: CompiledRuleset object
    Returns:
        string containing the iptables configuration
    """
    policy = ("\n*mangle\n"
              ":PREROUTING ACCEPT [0:0]\n"
              ":OUTPUT ACCEPT [0:0]\n\n")

    for rule in rulesets.Rmark:
        for match in iptables_scan_match(rule.packet_in):
            # Note that I build the ruleset, hence I know that there is only a single tag assigned
            policy += "-A PREROUTING" + match + " -j MARK --set-mark " + str(rule.packet_out.mark[0][0]) + "\n"
    for rule in rulesets.Rmark:
        for match in iptables_scan_match(rule.packet_in):
            # Note that I build the ruleset, hence I know that there is only a single tag assigned
            policy += "-A OUTPUT" + match + " -j MARK --set-mark " + str(rule.packet_out.mark[0][0]) + "\n"

    policy += ("\nCOMMIT\n\n"
               "*nat\n"
               ":PREROUTING ACCEPT [0:0]\n"
               ":INPUT ACCEPT [0:0]\n"
               ":OUTPUT ACCEPT [0:0]\n"
               ":POSTROUTING ACCEPT [0:0]\n\n")

    for rule in rulesets.Rdnat:
        for match in iptables_scan_match(rule.packet_in):
            policy += "-A PREROUTING" + match + \
                      " -j DNAT --to-destination " + \
                      (str(rule.packet_out.dstIp[0][0]) if rule.packet_out.dstIp != [] else "") + \
                      (":" + str(rule.packet_out.dstPort[0][0]) if rule.packet_out.dstPort != [] else "") + "\n"
    for rule in rulesets.Rdnat:
        for match in iptables_scan_match(rule.packet_in):
            policy += "-A OUTPUT" + match + \
                      " -j DNAT --to-destination " + \
                      (str(rule.packet_out.dstIp[0][0]) if rule.packet_out.dstIp != [] else "") + \
                      (":" + str(rule.packet_out.dstPort[0][0]) if rule.packet_out.dstPort != [] else "") + "\n"

    for rule in rulesets.Rsnat:
        for match in iptables_scan_match(rule.packet_in):
            policy += "-A INPUT" + match + \
                      " -j SNAT --to-source " + \
                      (str(rule.packet_out.srcIp[0][0]) if rule.packet_out.srcIp != [] else "") + \
                      (":" + str(rule.packet_out.srcPort[0][0]) if rule.packet_out.srcPort != [] else "") + "\n"
    for rule in rulesets.Rsnat:
        for match in iptables_scan_match(rule.packet_in):
            policy += "-A POSTROUTING" + match + \
                      " -j SNAT --to-source " + \
                      (str(rule.packet_out.srcIp[0][0]) if rule.packet_out.srcIp != [] else "") + \
                      (":" + str(rule.packet_out.srcPort[0][0]) if rule.packet_out.srcPort != [] else "") + "\n"

    policy += ("\nCOMMIT\n\n"
               "*filter\n"
               ":INPUT DROP [0:0]\n"
               ":FORWARD DROP [0:0]\n"
               ":OUTPUT DROP [0:0]\n\n")

    for rule in rulesets.Rfil:
        for match in iptables_scan_match(rule.packet_in):
            policy += "-A INPUT" + match + " -j ACCEPT \n"
    for rule in rulesets.Rfil:
        for match in iptables_scan_match(rule.packet_in):
            policy += "-A OUTPUT" + match + " -j ACCEPT \n"
    for rule in rulesets.Rfil:
        for match in iptables_scan_match(rule.packet_in):
            policy += "-A FORWARD" + match + " -j ACCEPT \n"

    return policy

