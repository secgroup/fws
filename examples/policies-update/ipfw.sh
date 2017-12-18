# NAT setup. The first line defines the SNAT for packets leaving the firewall through the interface
# ext (Requirement 4), the other two lines specify to perform DNAT on packets arriving to the ports
# 22 and 443 of the firewall (Requirement 2)
ipfw -q nat 1 config if ext unreg_only reset \
                     redirect_port tcp 10.0.1.15:443 443 \
                     redirect_port tcp 10.0.2.15:22  22

# Allow established packets
ipfw -q add 00001 check-state

# Requirement 1: Allow arbitrary traffic between internal networks
ipfw -q add 00010 allow all from 10.0.0.0/16 to 10.0.0.0/16

# Requirement 2: Apply DNAT on packets arriving to the external interface of the firewall
ipfw -q add 00100 nat 1 ip from any to 172.16.0.254 in # recv ext

# Requirement 2: Allow SSH/HTTPS incoming traffic to the corresponding hosts and responses from 
# these services
ipfw -q add 00200 allow tcp from any to 10.0.1.15 443 keep-state
#ipfw -q add 00201 skipto 1000 tcp from 10.0.1.15 443 to any

ipfw -q add 00300 allow tcp from any to 10.0.2.15 22 keep-state
#ipfw -q add 00301 skipto 1000 tcp from 10.0.2.15 22 to any

# Requirements 3 and 4: Allow HTTP/HTTPS outgoing traffic 
ipfw -q add 00500 skipto 1000 tcp from 10.0.0.0/16 to any 80,443 setup keep-state

# Requirement 5: Allow arbitrary outgoing traffic by the firewall
ipfw -q add 00501 allow ip from me to any setup keep-state

# Drop all the other packets
ipfw -q add 00999 deny all from any to any

# Apply SNAT to outgoing connnections
ipfw -q add 01000 nat 1 ip from any to not 10.0.0.0/16 out
ipfw -q add 01001 allow ip from any to any

