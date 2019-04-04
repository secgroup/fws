#!/usr/bin/env python2

import fwsynthesizer as fws

"""
Using fws as a python library
example code
"""

POLICY = "examples/policies/iptables.rules"
INTERFACES = "examples/policies/interfaces"

# Import the forntend and interfaces
frontend = fws.import_frontend("iptables")
interfaces = fws.load_interfaces(INTERFACES)
# Convert the input policy to IFCL
local_addresses = fws.get_local_addresses(interfaces)
chain = frontend.language_converter(open(POLICY).read(), interfaces)
# Make the firewall object
firewall = fws.Firewall(name=frontend.name,
                        diagram=frontend.diagram,
                        chains=chain,
                        local_addresses=local_addresses)

syn_out = firewall.synthesize(query="srcIp == 10.0.0.0/16")
rules = syn_out.get_rules()

syn_out.print_table()

print rules
print rules[0]
print rules[0].type
print rules[0].srcIp

from fwsynthesizer.synthesis.table_printer import print_table
print_table(rules)
