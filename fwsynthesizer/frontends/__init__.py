#!/usr/bin/env python2

import os
import pkgutil
import importlib
import fwsynthesizer
from fwsynthesizer.utils import *

FRONTENDS = [ x[1] for x in pkgutil.iter_modules(__path__) ]

class Frontend:
    "Frontend object"
    def __init__(self, name, diagram, language_converter,
                 query_configuration=None, interfaces_enabled=True):
        """
        Make a Frontend object

        Args:
            name (str): frontend name
            diagram (str): diagram file path
            language_converter (Callable[[str,dict], str]): converter callable
            query_configuration (callable): query configuration loop
            interfaces_enabled (bool): do or do not consider the interfaces
        """
        self.name = name
        self.diagram = diagram
        self.language_converter = language_converter
        self.query_configuration = query_configuration
        self.interfaces_enabled = interfaces_enabled


def import_frontend(name):
    """
    Import a frontend from the frontend package.
    Note: each frontend is a python script that must contain a `frontend` variable
          with the definition of the Frontend object
    """
    if name in FRONTENDS:
        frontend = importlib.import_module('.'+name, package="fwsynthesizer.frontends").frontend
        frontend.diagram = os.path.join(os.path.dirname(fwsynthesizer.__file__), frontend.diagram)
        return frontend
    elif os.path.exists(name) and os.path.isfile(name):
        return Frontend(name="Generic",
                        diagram=os.path.abspath(name),
                        language_converter=lambda x,_: x,
                        interfaces_enabled=False)
    else:
        raise RuntimeError("Invalid Frontend '{}'!".format(name))


class LanguageConverter:
    "Callable object that converts a configuration file to the generic language"
    def __init__(self, parser, converter):
        self.parser = parser
        self.converter = converter

    def __call__(self, contents, interfaces):
        contents   = preprocess(contents)
        ast        = self.parser(contents)
        rules      = self.converter(ast, interfaces)
        return rules


def converter(parser, converter):
    "Make a LanguageConverter object"
    return LanguageConverter(parser, converter)


def query_configuration(get_lines, delete_rule):
    "Query a configuration and show all the rules that affect the selected packets"

    def query_loop(name, diagram, contents, interfaces, query,
                   languageconverter):
        contents = preprocess(contents)
        local_addresses = get_local_addresses(interfaces)
        lines = get_lines(contents)
        rules = languageconverter.parser(contents)
        rules_contents = languageconverter.converter(rules, interfaces)
        firewall = fwsynthesizer.Firewall(name, diagram, rules_contents, local_addresses)

        for i in range(0, len(lines)):
            rules1 = delete_rule(rules, i)
            rules_contents1 = languageconverter.converter(rules1, interfaces)
            test = fwsynthesizer.Firewall("{}_{}".format(name, i), diagram,rules_contents1, local_addresses)
            res = firewall.equivalence(test, query=query)
            if not res: print lines[i]

    return query_loop
