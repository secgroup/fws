#!/bin/bash

SYNTHESIS="fws"

run () {
    CMD="${SYNTHESIS} iptables synthesis -f iptables.txt -i interfaces"
    $CMD $2 -q "$1"
}

echo "POLICY VERIFICATION"
echo "==================="
echo

echo "# REQUIREMENT 1,2"
echo "=> Hosts from the Internet can connect to the HTTPS server (54.230.203.47) in the DMZ"
echo "=> LAN hosts (10.0.0.0/8) can connect to any host in the DMZ (54.230.203.0/24)"
QUERY1="dstIp == 54.230.203.0/24 && state == NEW"
PARMS1="--forward"
echo "=> Parameters: $PARMS1"
echo "=> Query: $QUERY1 "
run "$QUERY1" "$PARMS1"
echo -e "\n"

echo "# REQUIREMENT 3"
echo "=> LAN hosts can connect to the Internet over HTTP and HTTPS (with source NAT on address 23.1.8.15)"
QUERY2="srcIp == 10.0.0.0/8 && not(dstIp == 54.230.203.0/24) && state == NEW"
PARMS2="--forward"
echo "=> Parameters: $PARMS2"
echo "=> Query: $QUERY2 "
run "$QUERY2" "$PARMS2"
echo -e "\n"
