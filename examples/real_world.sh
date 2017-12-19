#!/bin/bash

echo == REAL WORLD EXAMPLE QUERIES ==
echo

echo - Home Router -
echo \"Connections to the external address are DNATed to 192.168.1.130 on ports 22,80,443,1194\"
echo QUERY: \"dstIp == 117.195.222.105\"
echo PARAMS: \"--forward\"
fws iptables synthesis -i "real-world/home-router-openwrt-lede/interfaces" \
                       -f "real-world/home-router-openwrt-lede/router.rules" \
                       -q "dstIp == 117.195.222.105" --forward -t
echo

echo - Memphis Testbed -
echo \"Which hosts can reach the internal testbed network?\"
echo QUERY: \"dstIp == 145.30.196.192/27\"
echo PARAMS: \"--forward\"
fws iptables synthesis -i "real-world/memphis_testbed/interfaces" \
                       -f "real-world/memphis_testbed/iptables-save" \
                       -q "dstIp == 145.30.196.192/27" --forward -t
echo 

echo - veroneau.net -
echo \"Which hosts of the 91.2036.0.0/16 can reach the web server?\"
echo "QUERY: \"srcIp == 91.236.0.0/16 && dstPort == 80\""
echo PARAMS: \"--input\"
fws iptables synthesis -i "real-world/veroneau.net/interfaces" \
                       -f "real-world/veroneau.net/iptables-save" \
                       -q "srcIp == 91.236.0.0/16 && dstPort == 80" --input -t
echo

echo - Medium-Sized Company -
echo \"Which are the hosts the internal network can connect to on port 80?\"
echo "QUERY: \"srcIp == 172.16.2.0/24 && dstPort == 80 && protocol == tcp\""
echo PARAMS: \"--nat --forward\"
fws iptables synthesis -i "real-world/medium-sized-company/interfaces" \
                       -f "real-world/medium-sized-company/iptables-save.iptables_mainfw_31.01.2016" \
                       -q "srcIp == 172.16.2.0/24 && dstPort == 80 && protocol == tcp" --forward --nat -t
echo 

