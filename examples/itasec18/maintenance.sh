#!/bin/bash

SYNTHESIS="fws"

echo "POLICY MAINTENANCE"
echo "=================="
echo

echo "=> Analysis: EQUIVALENCE"
echo "- Check the equivalence between policies after the first wrong attempt: the DROP rule has"
echo "  been placed at the end of the ruleset, thus it has no effect"
echo "- Files: iptables.txt and iptables_wrong_update_1.txt"
echo -n "Output: "
${SYNTHESIS} iptables equivalence -i interfaces -f iptables.txt -s iptables_wrong_update_1.txt
echo

echo "=> Analysis: RELATED RULES"
echo "- Check which rules affect the processing of HTTP packets on the wrong policy"
QUERY_R="protocol == tcp && dstPort == 80 && state == NEW"
echo "- Query: ${QUERY_R}"
${SYNTHESIS} iptables query -i interfaces -f iptables_wrong_update_1.txt -q "${QUERY_R}"
echo

echo "=> Analysis: EQUIVALENCE"
echo "- Check the equivalence between policies after the second wrong attempt: the DROP rule has"
echo "  been placed before all the rules of the other requirements"
echo "- Files: iptables.txt and iptables_wrong_update_2.txt"
echo -n "Output: "
${SYNTHESIS} iptables equivalence -i interfaces -f iptables.txt -s iptables_wrong_update_2.txt
echo

echo "=> Analysis: DIFFERENCE"
echo "- Check the difference between policies projected on HTTP packets: the DROP rule is also"
echo "  preventing HTTP communication with the DMZ"
QUERY_D="protocol == tcp && dstPort == 80"
echo "- Query: ${QUERY_D}"
${SYNTHESIS} iptables diff -i interfaces -f iptables.txt -s iptables_wrong_update_2.txt -q "${QUERY_D}" --forward
echo

echo "=> Analysis: DIFFERENCE"
echo "- Check the difference between policies (projected on HTTP packets) after the correct update: now the"
echo "  host can communicate over HTTP with the DMZ"
QUERY_D="protocol == tcp && dstPort == 80"
echo "- Query: ${QUERY_D}"
${SYNTHESIS} iptables diff -i interfaces -f iptables.txt -s iptables_correct_update.txt -q "${QUERY_D}" --forward
echo
