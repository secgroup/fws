#!/bin/bash

SYNTHESIS="fws"

NAMES=("iptables" "ipfw" "pf")
FILES=("iptables.rules" "ipfw.sh" "pf.conf")

STYLE=$1

test_firewalls () {
    for I in {0..2}; do
        echo "-> ${NAMES[$I]}"
        CMD="${SYNTHESIS} ${NAMES[$I]} synthesis -f policies/${FILES[$I]} -i policies/interfaces $STYLE"
        $CMD $2 -q "$1"
    done
}

echo "POLICY VERIFICATION"
echo "==================="
echo

echo "# REQUIREMENT 1"
echo "=> Internal Networks (10.0.1.0/24 and 10.0.2.0/24) should freely communicate"
QUERY1="((srcIp == 10.0.1.0/24 && dstIp == 10.0.2.0/24) || (srcIp == 10.0.2.0/24 && dstIp == 10.0.1.0/24)) && state == NEW"
PARMS1="--forward"
echo "=> Parameters: $PARMS1"
echo "=> Query: $QUERY1 "
test_firewalls "$QUERY1" "$PARMS1"
echo -e "\n"

echo "# REQUIREMENT 2"
echo "=> Connection to Firewall are translated DNAT on 10.0.1.15 and 10.0.2.15 on port 22 and 443"
QUERY2="(dstIp' == 10.0.1.15 || dstIp' == 10.0.2.15) && state == NEW"
PARMS2="--nat --forward"
echo "=> Parameters: $PARMS2"
echo "=> Query: $QUERY2 "
test_firewalls "$QUERY2" "$PARMS2"
echo -e "\n"

echo "# REQUIREMENT 3,4"
echo "=> Connections to the internet are allowed only to 80 and 443 and source address is translated to 172.16.0.254"
QUERY3="srcIp == 10.0.0.0/16 && not (dstIp' == 10.0.0.0/16) && state == NEW"
PARMS3="--forward"
echo "=> Parameters: $PARMS3"
echo "=> Query: $QUERY3"
test_firewalls "$QUERY3" "$PARMS3"
echo -e "\n"

echo "# REQUIREMENT 5"
echo "=> Firewall host 172.16.0.254 can connect to any host"
QUERY4="srcIp == 172.16.0.254 && state == NEW"
PARMS4="--output"
echo "=> Parameters: $PARMS4"
echo "=> Query: $QUERY4 "
test_firewalls "$QUERY4" "$PARMS4"
echo

