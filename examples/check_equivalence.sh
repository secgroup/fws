#!/bin/bash

QUERIES=( \
  "((srcIp == 10.0.1.0/24 && dstIp == 10.0.2.0/24) || (srcIp == 10.0.2.0/24 && dstIp == 10.0.1.0/24)) && state == NEW" \
  "(dstIp' == 10.0.1.15 || dstIp' == 10.0.2.15) && state == NEW" \
  "srcIp == 10.0.0.0/16 && not (dstIp' == 10.0.0.0/16) && state == NEW" \
  "srcIp == 172.16.0.254 && state == NEW" \
)
PARAMS=("--forward" "--forward" "--forward" "--output")
NAMES=("Requirement 1" "Requirement 2" "Requirements 3,4" "Requirement 5")

echo "EQUIVALENCE"
echo "==========="
echo
echo "policies/iptables.rules"
echo "policies-update/ipfw.sh"
echo
for I in {0..3}; do
    echo "# ${NAMES[$I]}"
    fws iptables equivalence -i policies/interfaces -f policies/iptables.rules \
                             -sf ipfw -s policies-update/ipfw.sh \
                             -q "${QUERIES[$I]}" ${PARAMS[$I]}
done
