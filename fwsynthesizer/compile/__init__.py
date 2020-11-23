#!/usr/bin/env python2

from compile_iptables import *
from compile_ipfw import *
from compile_pf import *

TARGETS = ['iptables', 'ipfw', 'pf']

def fw_compile(semantics, target):
    """
    Compile a semantics into a configuration file for the target language

    Args:
        semantics: SynthesisOutput object
        target: language we want to compile to
    Returns:
        string containing the configuration file
    """
    if target == 'iptables':
        ruleset_list = ruleset_generation_iptables(semantics.get_rules_no_duplicates())
        configuration = concretise_iptables(ruleset_list)
    elif target == 'ipfw':
        ruleset_list = ruleset_generation_ipfw(semantics.get_rules_no_duplicates())
        configuration = concretise_ipfw(ruleset_list)
    elif target == 'pf':
        ruleset_list = ruleset_generation_pf(semantics.get_rules_no_duplicates())
        configuration = concretise_pf(ruleset_list)
    else:
        print("Target language is not supported")
        raise Exception

    return configuration
