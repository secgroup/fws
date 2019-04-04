from compile_utils import *


class ipfw_configuration:
    def __init__(self):
        self.nat_spec = ""
        self.nat_count = 0
        self.rule_spec = "ipfw -q add 0000 check-state\n"
        self.rule_count = 1

    def add_snat_rule(self, rule):

        # case1: We want to change only the sourceIp of the packet
        if rule.packet_out.srcIp != [] and rule.packet_out.srcIp[0][0] == rule.packet_out.srcIp[0][1] and \
                rule.packet_out.srcPort == []:
            self.nat_spec += "ipfw nat " + str(self.nat_count) + " config ip " + str(rule.packet_out.srcIp[0][0]) + "\n"

            match_pair = self.scan_match(rule.packet_in)

            temp_rule_spec = ""
            temp_rule_spec_unfinished = []

            for match in match_pair[0]:
                temp_rule_spec_unfinished += [["ipfw -q add " + str(self.rule_count).zfill(4) + " skipto ", match + "\n"]]
                self.rule_count += 1

            for match in match_pair[1]:
                temp_rule_spec += "ipfw -q add " + str(self.rule_count).zfill(4) + " nat " + str(self.nat_count)
                if rule.packet_out.mark != []:
                    temp_rule_spec += " tag " + str(rule.packet_out.mark[0][0])
                temp_rule_spec += match + " out" + "\n"
                self.rule_count += 1

            for temp_rule in temp_rule_spec_unfinished:
                self.rule_spec += temp_rule[0] + str(self.rule_count).zfill(4) + " " + temp_rule[1]

            self.rule_spec += temp_rule_spec

            self.nat_count += 1
        else:
            print("Warning: non-expressible SNAT\n")

    def add_dnat_rule(self, rule):

        # case2: We want to change only the destIp and the destIp is a singleton
        if len(rule.packet_in.dstIp) == 1 and rule.packet_in.dstIp[0][0] == rule.packet_in.dstIp[0][1] and \
                rule.packet_out.dstIp != [] and rule.packet_out.dstPort == []:
            self.nat_spec += "ipfw nat " + str(self.nat_count) + " config redirect_address " + str(rule.packet_in.dstIp[0][0]) + \
                " " + str(rule.packet_out.dstIp[0][0]) + "\n"

            match_pair = self.scan_match(rule.packet_in)

            temp_rule_spec = ""
            temp_rule_spec_unfinished = []

            for match in match_pair[0]:
                temp_rule_spec_unfinished += [["ipfw -q add " + str(self.rule_count).zfill(4) + " skipto ", match + "\n"]]
                self.rule_count += 1

            for match in match_pair[1]:
                temp_rule_spec += "ipfw -q add " + str(self.rule_count).zfill(4) + " nat " + str(self.nat_count)
                if rule.packet_out.mark != []:
                    temp_rule_spec += " tag " + str(rule.packet_out.mark[0][0])
                temp_rule_spec += match + " in" + "\n"
                self.rule_count += 1

            for temp_rule in temp_rule_spec_unfinished:
                self.rule_spec += temp_rule[0] + str(self.rule_count).zfill(4) + " " + temp_rule[1]

            self.rule_spec += temp_rule_spec

            self.nat_count += 1
        # case3: destPort is a singleton and (of course we want to change one or two between destPort and destIp),
        #   if destIp is not to change then it needs to be a singleton to, and the protocol must be a singleton
        elif len(rule.packet_in.dstPort) == 1 and rule.packet_in.dstPort[0][0] == rule.packet_in.dstPort[0][1] and \
                (rule.packet_out.dstIp != [] or
                 len(rule.packet_in.dstIp) == 1 and rule.packet_in.dstIp[0][0] == rule.packet_in.dstIp[0][1]):

            if rule.packet_out.dstIp != []:
                target_ip = str(rule.packet_out.dstIp[0][0])
            else:
                target_ip = str(rule.packet_in.dstIp[0][0])
            if rule.packet_out.dstPort != []:
                target_port = str(rule.packet_out.dstPort[0][0])
            else:
                target_port = str(rule.packet_in.dstPort[0][0])

            if rule.packet_in.protocol != [[6, 6]] and rule.packet_in.protocol != [[17, 17]]:
                nat_protocols = [[6, 6], [17, 17]]
            else:
                nat_protocols = rule.packet_in.protocol

            for protocol_intreval_singleton in nat_protocols:
                self.nat_spec += "ipfw nat " + str(self.nat_count) + " config redirect_port " + \
                            protocol_names()[str(protocol_intreval_singleton[0])] + \
                            target_ip + ":" + target_port + " " + str(rule.packet_in.dstPort[0][0]) + "\n"

            match_pair = self.scan_match(rule.packet_in)

            temp_rule_spec = ""
            temp_rule_spec_unfinished = []

            for match in match_pair[0]:
                temp_rule_spec_unfinished += [["ipfw -q add " + str(self.rule_count).zfill(4) + " skipto ", match + "\n"]]
                self.rule_count += 1

            for match in match_pair[1]:
                temp_rule_spec += "ipfw -q add " + str(self.rule_count).zfill(4) + " nat " + str(self.nat_count)
                if rule.packet_out.mark != []:
                    temp_rule_spec += " tag " + str(rule.packet_out.mark[0][0])
                temp_rule_spec += match + " in" + "\n"
                self.rule_count += 1

            for temp_rule in temp_rule_spec_unfinished:
                self.rule_spec += temp_rule[0] + str(self.rule_count).zfill(4) + " " + temp_rule[1]

            self.rule_spec += temp_rule_spec

            self.nat_count += 1
        else:
            print("Warning: non-expressible DNAT\n")

    def add_allow_rule(self, rule):
        match_pair = self.scan_match(rule.packet_in)

        temp_rule_spec = ""
        temp_rule_spec_unfinished = []

        for match in match_pair[0]:
            temp_rule_spec_unfinished += [["ipfw -q add " + str(self.rule_count).zfill(4) + " skipto ", match + "\n"]]
            self.rule_count += 1

        for match in match_pair[1]:
            temp_rule_spec += "ipfw -q add " + str(self.rule_count).zfill(4) + " allow" + match + "\n"
            self.rule_count += 1

        for temp_rule in temp_rule_spec_unfinished:
            self.rule_spec += temp_rule[0] + str(self.rule_count).zfill(4) + " " + temp_rule[1]

        self.rule_spec += temp_rule_spec

    def scan_match(self, complex_packet):
        """
        Scan a given complex packet, returning a list of ipfw match such that the packet contains the values that
        verifies at least one of the matches.

        Args:
            complex_packet: on object of type Packet
        Returns:
            (skip_matches, apply_matches): a pair of lists of strings each one representing an ipfw match,
                skip_matches : is the list of matches that defines condition under which the rule is NOT applied
                apply_matches : is the list of matches that defines condition under which the rule is applied
                --- the first one have precedence: the packets on which the rule is to apply are the ones that do not
                    verify the skip_mathces AND do verify the apply matches
        """

        # compute inverse packt to choose the best representation
        inverse_pkt = [inverse_interval(complex_packet.srcIp), inverse_interval(complex_packet.srcPort),
                          inverse_interval(complex_packet.dstIp), inverse_interval(complex_packet.dstPort),
                          inverse_interval(complex_packet.protocol), inverse_interval(complex_packet.mark)]

        # for conditions expressed as negation we will put skipto, with all matches that cannot verify the actual rule
        skip_matches = []
        # context is a rule that accept all values for every fields but one, for which there is a hole
        skip_matches_context = [("all from ", " to any"), ("all from any ", " to any"),
                                ("all from any to ", ""), ("all from any to any ", ""), ("", " from any to any")]
        # for each field we add matches that check only that field into skip_matches
        for i in range(len(inverse_pkt)):
            inverse_field = inverse_pkt[i]
            if inverse_field != () and len(inverse_field[1]) > 1:
                for interval in inverse_field[1]:
                    if i == 0 or i == 2:
                        negated_subnet = IPrange_to_subnets(str(interval[0]), str(interval[1]))
                        if negated_subnet[0][1] == 32:
                            negated_value = str(negated_subnet[0][0])
                        else:
                            negated_value = str(negated_subnet[0][0]) + '/' + str(negated_subnet[0][1])
                    else:
                        if interval[0] == interval[1]:
                            negated_value = str(interval[0])
                        else:
                            negated_value = str(interval[0]) + '-' + str(interval[1])

                    skip_matches.append(skip_matches_context[i][0] + negated_value + skip_matches_context[i][1])

        # if we check negation before the rule, then we check the positive part of inverse_pkt in the final rules
        for i in range(len(inverse_pkt)):
            inverse_field = inverse_pkt[i]
            if inverse_field != ():
                if i == 0:
                    complex_packet.srcIp = [inverse_field[0]]
                elif i == 1:
                    complex_packet.srcPort = [inverse_field[0]]
                elif i == 2:
                    complex_packet.dstIp = [inverse_field[0]]
                elif i == 3:
                    complex_packet.dstPort = [inverse_field[0]]
                elif i == 4:
                    complex_packet.protocol = [inverse_field[0]]

        # we substitute address-range with Ip-range notation (with masks)
        masked_complex_packet = translate_IPranges_to_subnets(complex_packet)

        # if accepted values of some field can be expressed as negation of a single segment then we do it that way

        # this is needed to check that the first part of the reverse packet contain all possible values
        minimum = ["0.0.0.0", "0", "0.0.0.0", "0", "0", "0"]
        maximum = ["255.255.255.255", "65535", "255.255.255.255", "65535", "255", "1"]
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

                if i == 0:
                    masked_complex_packet.srcIp = ["not " + negated_value]
                if i == 1:
                    masked_complex_packet.srcPort = ["not " + negated_value]
                if i == 2:
                    masked_complex_packet.dstIp = ["not " + negated_value]
                if i == 3:
                    # print(negated_value)
                    masked_complex_packet.dstPort = ["not " + negated_value]
                if i == 4:
                    # print(negated_value, protocol_names()[str(negated_value[0])])
                    negated_protocol = protocol_names()[str(negated_value[0])]
                    masked_complex_packet.protocol = [" not " + negated_protocol]

        # since we cannot predicate over union of segments we calculate the cartesian product,
        # obtaining a list of simple packets
        packets = expand_packet(masked_complex_packet)

        # finally we translate each simple packet into a match for apply_matches
        apply_matches = []
        for packet in packets:
            match = ''

            # if the field is already a string, then it is a negation and we take it as it is
            if isinstance(packet.protocol, basestring):
                match += packet.protocol
            elif packet.any_protocol():
                match += " all"
            else:
                # 2 possibilities: we have all except for one protocol p, then we check not p
                # we assume we don't have protocols range, since negated version is used
                try:
                    match += " " + protocol_names()[str(packet.protocol[0])]
                except KeyError:
                    print("unrecognized protocol number")
                    match += " all"

            match += ' from ' + packet.srcIp

            # if the field is already a string, then it is a negation and we take it as it is
            if isinstance(packet.srcPort, basestring):
                match += " " + packet.srcPort
            elif not packet.any_srcPort():
                match += " " + str(packet.srcPort[0])
                if packet.srcPort[0] != packet.srcPort[1]:
                    match += "-" + str(packet.srcPort[1])

            match += ' to ' + packet.dstIp

            # if the field is already a string, then it is a negation and we take it as it is
            if isinstance(packet.dstPort, basestring):
                match += " " + packet.dstPort
            elif not packet.any_dstPort():
                match += " " + str(packet.dstPort[0])
                if packet.dstPort[0] != packet.dstPort[1]:
                    match += "-" + str(packet.dstPort[1])

            # since we have to compile only configurations produced by ours algorithm:
            # we consider only one possible mark for each packet
            if len(packet.mark) > 0 and not packet.any_mark():
                match += " tagged " + str(packet.mark[0])

            apply_matches.append(match)

        return skip_matches, apply_matches

    def get_config(self):
        return self.nat_spec + "\n" + self.rule_spec + \
               "ipfw -q add " + str(self.rule_count).zfill(4) + " deny all from any to any"


def ruleset_generation_ipfw(rules):
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
        # We do NOT consider the behaviour of established connection, not new packets will be managed in default way
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

            # ipfw requires lots of info about the input packet, since we never change DNAT more than once we
            # leave all the matches about destination (port and IP), and since we cannot change the protocol, we leave
            # the matches about protocol. These are the only two fields that can be useful in expressing DNAT
            if rule.packet_out.dstIp != [] or rule.packet_out.dstPort != []:

                dnatted_packet = copy.deepcopy(rule.packet_out)
                dnatted_packet.srcIp = [[]]
                dnatted_packet.srcPort = [[]]

                marked_dnatted_packet = copy.deepcopy(dnatted_packet)
                marked_dnatted_packet.mark = [[tag, tag]]

                marked_packet_with_dest_and_protocol = copy.deepcopy(rule.packet_in)
                marked_packet_with_dest_and_protocol.srcIp = Any_IP
                marked_packet_with_dest_and_protocol.srcPort = Any_Port
                marked_packet_with_dest_and_protocol.mark = [[tag, tag]]

                postponed_dnat.append(Rule(rule.packet_in, marked_dnatted_packet))
                rulesets.Rdnat.append(Rule(marked_packet_with_dest_and_protocol, dnatted_packet))

            postponed_fil.append(Rule(rule.packet_in, Packet([], [], [], [], [], [], [], [], [[tag, tag]])))
            rulesets.Rfil.append(Rule(marked_packet, Packet([], [], [], [], [], [], [], [], [])))

            tag += 1
    rulesets.Rsnat += postponed_snat
    rulesets.Rdnat += postponed_dnat
    rulesets.Rfil += postponed_fil
    return rulesets


def concretise_ipfw(rulesets):
    """
    Given a compiled ruleset representing an IFCL firewall for pf, translates it in the target configuration
    language (i.e. pf own language)

    Args:
        rulesets: CompiledRuleset object
    Returns:
        string containing the pf configuration
    """

    config = ipfw_configuration()
    for rule in rulesets.Rfil:
        config.add_allow_rule(rule)
    for rule in rulesets.Rsnat:
        config.add_snat_rule(rule)
    for rule in rulesets.Rdnat:
        config.add_dnat_rule(rule)
    return config.get_config()
