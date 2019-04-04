from compile_utils import *


def ruleset_generation_pf(rules):
    """
    Given a list of rules produces different rulesets for compilation

    Args:
        rules: list of Rule objects representing the policy
    Returns:
        Compiled_ruleset Object
    """
    rulesets = CompiledRulesets()
    postponed_snat = []
    postponed_dnat = []
    postponed_fil = []
    tag = 0
    for rule in rules:
        if rule.packet_in.state == [[0, 1]]:
            rule.packet_in.state = [[0, 0]]
        if rule.packet_in.state != [[0, 0]]:
            continue

        if rule.type == 'FILTER':
            rulesets.Rfil.append(rule)
        else:
            marked_packet = \
                Packet(Any_IP, Any_Port, Any_IP, Any_Port, Any_Mac, Any_Mac, Any_protocol, [[0, 0]], [[tag, tag]])

            if rule.packet_out.srcIp != [] or rule.packet_out.srcPort != []:
                snatted_packet = copy.deepcopy(rule.packet_out)
                snatted_packet.dstIp = [[]]
                snatted_packet.dstPort = [[]]

                marked_snatted_packet = copy.deepcopy(snatted_packet)
                marked_snatted_packet.mark = [[tag, tag]]

                postponed_snat.append(Rule(rule.packet_in, marked_snatted_packet))
                rulesets.Rsnat.append(Rule(marked_packet, snatted_packet))

            if rule.packet_out.dstIp != [] or rule.packet_out.dstPort != []:

                dnatted_packet = copy.deepcopy(rule.packet_out)
                dnatted_packet.srcIp = [[]]
                dnatted_packet.srcPort = [[]]

                marked_dnatted_packet = copy.deepcopy(dnatted_packet)
                marked_dnatted_packet.mark = [[tag, tag]]

                postponed_dnat.append(Rule(rule.packet_in, marked_dnatted_packet))
                rulesets.Rdnat.append(Rule(marked_packet, dnatted_packet))

            postponed_fil.append(Rule(rule.packet_in, Packet([], [], [], [], [], [], [], [], [[tag, tag]])))
            rulesets.Rfil.append(Rule(marked_packet, Packet([], [], [], [], [], [], [], [], [])))

            tag += 1
    rulesets.Rsnat += postponed_snat
    rulesets.Rdnat += postponed_dnat
    rulesets.Rfil += postponed_fil
    return rulesets


def pf_scan_match(complex_packet):
    """
    Scan a given complex packet, returning a list of pf match such that the packet contains the values that
    verifies at least one of the matches.

    Args:
        complex_packet: on object of type Packet
    Returns:
        a list of string containing pf matches
    """
    # compute inverse packt to choose the best representation
    inverse_pkt = [inverse_interval(complex_packet.srcIp), inverse_interval(complex_packet.srcPort),
                   inverse_interval(complex_packet.dstIp), inverse_interval(complex_packet.dstPort),
                   inverse_interval(complex_packet.protocol), inverse_interval(complex_packet.mark)]

    # this is needed to check that the first part of the reverse packet contain all possible values
    minimum = ["0.0.0.0", "0", "0.0.0.0", "0", "0", "0"]
    maximum = ["255.255.255.255", "65535", "255.255.255.255", "65535", "255", "1"]

    # Todo post refactoring, note that in pf you cannot negate protocols
    # for each field, if the value can be expressed as a negation of an interval then we substitute a string
    #   representing that negation inside the field of the packet

    # separates ranges of protocols
    separates_protocols(complex_packet)
    
    packets = expand_packet(complex_packet)
    matches = []

    for packet in packets:
        match = ''

        if not packet.any_protocol():
            # we don't have protocols range because we split them
            match += " proto " + str_protocol(packet.protocol[0])

        match += ' from '

        if packet.any_srcIp():
            match += "any "
        else:
            match += str(packet.srcIp[0])
            if packet.srcIp[0] != packet.srcIp[1]:
                match += " - " + str(packet.srcIp[1])

        if not packet.any_srcPort():
            match += " port " + str(packet.srcPort[0])
            if packet.srcPort[0] != packet.srcPort[1]:
                match += ":" + str(packet.srcPort[1])

        match += ' to '

        if packet.any_dstIp():
            match += "any "
        else:
            match += str(packet.dstIp[0])
            if packet.dstIp[0] != packet.dstIp[1]:
                match += " - " + str(packet.dstIp[1])

        if not packet.any_dstPort():
            match += " port " + str(packet.dstPort[0])
            if packet.dstPort[0] != packet.dstPort[1]:
                match += ":" + str(packet.dstPort[1])

        # since we have to compile only configurations produced by our algorithm:
        # we consider only one possible mark for each packet
        if len(packet.mark) > 0 and not packet.any_mark():
            match += " tagged " + str(packet.mark[0])

        matches.append(match)
    return matches


def concretise_pf(rulesets):
    """
    Given a compiled ruleset representing an IFCL firewall for pf, translates it in the target configuration
    language (i.e. pf own language)

    Args:
        rulesets: CompiledRuleset object
    Returns:
        string containing the pf configuration
    """
    policy = "\n### NAT rules ###\n\n"

    for rule in rulesets.Rsnat:
        for match in pf_scan_match(rule.packet_in):
            policy += "nat " + match + " -> " + str(rule.packet_out.srcIp[0][0]) + \
                      (" tag " + str(rule.packet_out.mark[0][0]) if rule.packet_out.mark != [] else "") + "\n"
            # if rule.packet_out.srcIp == [] then we have an error, the source port cannot be modified by pf
    for rule in rulesets.Rdnat:
        for match in pf_scan_match(rule.packet_in):
            policy += "rdr " + match + " -> " + \
                      (str(rule.packet_out.dstIp[0][0]) if rule.packet_out.dstIp != [] else "") + \
                      (" port " + str(rule.packet_out.dstPort[0][0]) if rule.packet_out.dstPort != [] else "") + \
                      (" tag " + str(rule.packet_out.mark[0][0]) if rule.packet_out.mark != [] else "") + "\n"

    policy += "\n\n### Filtering rules ###\n\nblock all\n"

    for rule in rulesets.Rfil:
        for match in pf_scan_match(rule.packet_in):
            policy += "pass" + match + \
                      (" tag " + str(rule.packet_out.mark[0][0]) if rule.packet_out.mark != [] else "") + "\n"

    return policy
