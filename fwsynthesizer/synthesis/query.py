#!/usr/bin/env python2

import time
import sys
import fwsynthesizer

from datetime import timedelta
from collections import namedtuple
from parsec import *
from fwsynthesizer.parsers.utils import *
import fwsynthesizer.utils as utils
from fwsynthesizer.frontends import FRONTENDS
from fwsynthesizer.compile import *

################################################################################
## Utils

def table_to_flags(pair):
    "Convert a table definition (string,string) to local/nat flags"

    table, subtable = map(lambda s: s.strip(), pair)
    local_flags = {
        'forward': (fwsynthesizer.LocalFlag.NOLOCAL, fwsynthesizer.LocalFlag.NOLOCAL),
        'input': (fwsynthesizer.LocalFlag.NOLOCAL, fwsynthesizer.LocalFlag.LOCAL),
        'output': (fwsynthesizer.LocalFlag.LOCAL, fwsynthesizer.LocalFlag.NOLOCAL),
        'loopback': (fwsynthesizer.LocalFlag.LOCAL, fwsynthesizer.LocalFlag.LOCAL),
        'all': (fwsynthesizer.LocalFlag.BOTH, fwsynthesizer.LocalFlag.BOTH)
    }
    nat_flags = {
        'filter': fwsynthesizer.NatFlag.FILTER,
        'nat': fwsynthesizer.NatFlag.NAT,
        'all': fwsynthesizer.NatFlag.ALL
    }
    return (local_flags.get(table, local_flags['all']),
            nat_flags.get(subtable, nat_flags['all']))

NAMES = {"srcIp": "srcIp", "dstIp": "dstIp",
         "srcPort": "srcPort", "dstPort": "dstPort",
         "srcMac": "srcMac", "dstMac": "dstMac",
         "snatIp": "srcIp'", "dnatIp": "dstIp'",
         "snatPort": "srcPort'", "dnatPort": "dstPort'",
         "srcIp'": "srcIp'", "dstIp'": "dstIp'", # Old style names
         "srcPort'": "srcPort'", "dstPort'": "dstPort'", # old style names
         "protocol": "protocol", "state": "state"}

################################################################################
## Expression Types

class QTrue():
    def render(self):
        return 'true'

class And(namedtuple('And', ['fst', 'snd'])):
    def render(self):
        return '({} && {})'.format(self.fst.render(), self.snd.render())

class Or(namedtuple('Or', ['fst', 'snd'])):
    def render(self):
        return '({} || {})'.format(self.fst.render(), self.snd.render())

class Not(namedtuple('Not', ['fst'])):
    def render(self):
        return 'not ({})'.format(self.fst.render())

class Match(namedtuple('Match', ['variable', 'value'])):
    def render(self):
        value = self.value
        if isinstance(self.value, Port):
            value = self.value.value
        if isinstance(self.value, PortRange):
            value = '{}-{}'.format(self.value.bottom, self.value.top)
        return '{} == {}'.format(self.variable, value)

class MatchList(namedtuple('MatchList', ['variable', 'value'])):
    def render(self):
        expr = Match(self.variable, self.value[0])
        for v in self.value[1:]:
            expr = Or(expr, Match(self.variable, v))
        return expr.render()

################################################################################
## FWSInterpreter

class UnboundAliasError(RuntimeError): pass
class UnboundVariableError(RuntimeError): pass
class UnknownTableStyle(RuntimeError): pass
class FWSError(RuntimeError): pass

class FWSInterpreter(object):
    def __init__(self):
        self.variables = {}
        self.show_time = False
        self.table_style = fwsynthesizer.TableStyle.UNICODE
        self.verbose = False

    def get_variable(self, varname):
        try:
            val = self.variables[varname]
        except KeyError:
            raise UnboundVariableError(varname)
        return val


Policy = namedtuple('Policy', ['firewall', 'frontend', 'config'])

class FWSCmd(object):
    def eval(self, fws_interpreter): raise NotImplemented

class Nop(FWSCmd):
    def eval(self, fws):
       pass

class Echo(FWSCmd, namedtuple('Echo', ['line'])):
    def eval(self, fws):
        print self.line

class ShowTime(FWSCmd):
    def eval(self, fws):
        fws.show_time = True

class TableStyle(FWSCmd, namedtuple('TableStyle', ['style'])):
    def eval(self, fws):
        if not self.style in [fwsynthesizer.TableStyle.UNICODE,
                              fwsynthesizer.TableStyle.ASCII,
                              fwsynthesizer.TableStyle.TEX,
                              fwsynthesizer.TableStyle.HTML,
                              fwsynthesizer.TableStyle.JSON]:
            raise UnknownTableStyle(self.style)
        fws.table_style = self.style

class VerboseMode(FWSCmd):
    def eval(self, fws):
        fws.verbose = not fws.verbose
        fwsynthesizer.synthesis.Synthesis.set_verbose(fws.verbose)

class ShowIdentifier(FWSCmd, namedtuple('ShowIdentifier', ['variable'])):
    def eval(self, fws):
        print fws.get_variable(self.variable)

class Assignment(FWSCmd, namedtuple('Assignment', ['variable', 'value'])):
    def eval(self, fws):
        fws.variables[self.variable] = self.value.eval(fws)

class LoadPolicy(FWSCmd, namedtuple('LoadPolicy', ['frontend', 'file', 'config'])):
    def eval(self, fws):
        config = fwsynthesizer.load_config(self.config)
        frontend = fwsynthesizer.import_frontend(self.frontend)

        policy_contents = open(self.file).read()
        chain_contents = frontend.language_converter(policy_contents, config['interfaces'])
        local_addresses = fwsynthesizer.get_local_addresses(config['interfaces'])
        firewall = fwsynthesizer.Firewall(name=self.file,
                                          diagram=frontend.diagram,
                                          chains=chain_contents,
                                          local_addresses=local_addresses)
        return Policy(firewall, frontend, config)

class Nondeterminism(FWSCmd, namedtuple('Nondeterminism', ['p', 'projection', 'table', 'query'])):
    def eval(self, fws):
        policy = fws.get_variable(self.p)
        firewall, frontend = policy.firewall, policy.frontend
        table_style = fws.table_style
        aliases = policy.config['aliases']
        query = replace_aliases(self.query, aliases).render()
        (localSrc, localDst), nat = table_to_flags(self.table)
        if nat != fwsynthesizer.NatFlag.ALL:
            raise FWSError("Non determinism only supported on /all !")
        rules = firewall.synthesize_nd(localSrc, localDst, query)
        rules.print_table(table_style, localSrc, localDst, nat,
                          aliases=aliases, projection=self.projection)

class Synthesis(FWSCmd, namedtuple('Synthesis', ['p', 'projection', 'table', 'query', 'option'])):
    def eval(self, fws):
        policy = fws.get_variable(self.p)
        aliases = policy.config['aliases']
        interfaces = policy.config['interfaces']
        query = replace_aliases(self.query, aliases).render()
        firewall, frontend = policy.firewall, policy.frontend
        (localSrc, localDst), nat = table_to_flags(self.table)
        table_style = fws.table_style

        # Synthesize a specification optionally splitting the synthesis into
        # the four `local` cases
        def synthesize(query, split_synthesis):
            if fws.show_time:
                start_t = time.time()

            if (frontend.interfaces_enabled
                and split_synthesis
                and localDst == fwsynthesizer.LocalFlag.BOTH
                and localSrc == fwsynthesizer.LocalFlag.BOTH):
                for name, localsrc, localdst in \
                    [("FORWARD",  fwsynthesizer.LocalFlag.NOLOCAL, fwsynthesizer.LocalFlag.NOLOCAL),
                     ("INPUT",    fwsynthesizer.LocalFlag.NOLOCAL, fwsynthesizer.LocalFlag.LOCAL),
                     ("OUTPUT",   fwsynthesizer.LocalFlag.LOCAL,   fwsynthesizer.LocalFlag.NOLOCAL),
                     ("LOOPBACK", fwsynthesizer.LocalFlag.LOCAL,   fwsynthesizer.LocalFlag.LOCAL)]:

                    print "\n"+name
                    rules = firewall.synthesize(localsrc, localdst, query)
                    print
                    rules.print_table(table_style, localsrc, localdst, nat,
                                      aliases=aliases, projection=self.projection)
            else:
                rules = firewall.synthesize(localSrc, localDst, query)
                print
                rules.print_table(table_style, localSrc, localDst, nat,
                                  aliases=aliases, projection=self.projection)

            if fws.show_time:
                print "\nSynthesis Time: {}".format(timedelta(seconds = time.time() - start_t))

        # Synthesize all the pairs (subnet,subnet)
        if frontend.interfaces_enabled and self.option == 'interfaces':
            for ifc_from in interfaces:
                for ifc_to in interfaces:
                    subnet_from, subnet_to = interfaces[ifc_from][0], interfaces[ifc_to][0]

                    if subnet_from == subnet_to: continue
                    if '127.0.0.0' in subnet_from or '127.0.0.0' in subnet_to: continue

                    squery = (query + " && " +
                              utils.constrain_interface(interfaces, "srcIp", ifc_from) + " && " +
                              utils.constrain_interface(interfaces, "dstIp", ifc_to))

                    print "\n-> SUBNETS: {} ({}) -> {} ({})".format(ifc_from, subnet_from, ifc_to, subnet_to)
                    synthesize(squery, False)
        else: synthesize(query, query == "true")


class Comparison(FWSCmd, namedtuple('Comparison', ['analysis', 'p1', 'p2', 'projection','table', 'query'])):
    def eval(self, fws):
        policy1 = fws.get_variable(self.p1)
        policy2 = fws.get_variable(self.p2)
        aliases1 = policy1.config['aliases']
        aliases2 = policy2.config['aliases']

        if not aliases1 == aliases2:
            print("<!> Warning: the two policies have different aliases."
                  "Using `{}` aliases...".format(self.p1))

        query = replace_aliases(self.query, aliases1).render()
        (localSrc, localDst), nat = table_to_flags(self.table)
        table_style = fws.table_style

        if nat != fwsynthesizer.NatFlag.ALL:
            raise FWSError("{} only supported on /all !"
                           .format(self.analysis.capitalize()))


        if self.analysis == 'implication':
            res = policy1.firewall.implication(policy2.firewall, localSrc, localDst, query=query)
            print "{}Implied.".format("Not " if not res else "")

        if self.analysis == 'equivalence':
            res = policy1.firewall.equivalence(policy2.firewall, localSrc, localDst, query=query)
            print "{}Equivalent.".format("Not " if not res else "")

        if self.analysis == 'diff':
            diff = policy1.firewall.difference(policy2.firewall, localSrc, localDst, query=query)
            sys.stderr.write('\n\n')
            diff.print_table(table_style, localSrc, localDst,
                             aliases=aliases1, projection=self.projection)


class Related(FWSCmd, namedtuple('Related', ['p', 'query'])):
    def eval(self, fws):
        policy = fws.get_variable(self.p)
        aliases = policy.config['aliases']
        query = replace_aliases(self.query, aliases).render()
        interfaces = policy.config['interfaces']
        frontend = policy.frontend
        diagram_file = frontend.diagram
        fw = policy.firewall
        file_contents = open(fw.name).read()

        if frontend.query_configuration:
            frontend.query_configuration(fw.name, diagram_file, file_contents,
                                    interfaces, query, frontend.language_converter)
        else:
            raise RuntimeError(
                "The selected frontend ({}) does not support the query function!"
                .format(frontend.name))


class Ifcl(FWSCmd, namedtuple('Ifcl', ['p'])):
    def eval(self, fws):
        policy = fws.get_variable(self.p)
        file_contents = open(policy.firewall.name).read()
        print policy.frontend.language_converter(file_contents, policy.config['interfaces'])

class Aliases(FWSCmd, namedtuple('Aliases', ['p'])):
    def eval(self, fws):
        policy = fws.get_variable(self.p)
        aliases = policy.config['aliases']
        for a in aliases:
            print "{}: {}".format(a, aliases[a])
        print

class Locals(FWSCmd, namedtuple('Locals', ['p'])):
    def eval(self, fws):
        policy = fws.get_variable(self.p)
        locals_ = policy.firewall.locals
        for ip in locals_:
            print "local {}".format(ip)
        print
        
class Porting(FWSCmd, namedtuple('Porting', ['p', 'target', 'file'])):
    def eval(self, fws):
        policy = fws.get_variable(self.p)
        firewall, frontend = policy.firewall, policy.frontend

        if self.target not in ["iptables", "pf", "ipfw"]:
            raise FWSError(
                "Invalid target language; must be one of iptables, pf or ipfw")

        semantics = firewall.synthesize()
        configuration = fw_compile(semantics, self.target)
        if self.file:
            with open(self.file, 'w') as f:
                f.write(configuration)
        else:
            print configuration


################################################################################
## PARSERS

help_message = (
    "FireWall Synthesizer Help\n"
    "\n"
    "Frontends: {}\n\n".format(", ".join(FRONTENDS)) +
    "MISC\n"
    "help                         show this help                                 \n"
    "echo LINE                    xdisplay LINE                                  \n"
    "P = load_policy(FRONTEND, RULES, CONF)                                      \n"
    "                             load policy RULES into P                       \n"
    "\n"
    "SETTINGS\n"
    "table_syle                   select table style (unicode, ascii, latex)     \n"
    "show_time                    display execution times                        \n"
    "verbose_mode                 display debug informations                     \n"
    "\n"
    "ANALYSES\n"
    "synthesis(POLICY) [in MODE/NAT] [project (FIELD, ...)] [where EXPR] [by interfaces]\n"
    "                             Synthesize a specification                     \n"
    "nondet(POLICY) [in MODE]     [project (FIELD, ...)] [where EXPR]            \n"
    "                             Syntesize non-deterministically dropped packets\n"
    "equivalence(P1,P2) [in MODE] [where EXPR]                                   \n"
    "                             Check for policy equivalence                   \n"
    "implication(P1,P2) [in MODE] [where EXPR]                                   \n"
    "                             Check for policy implication                   \n"
    "diff(P1,P2) [in MODE] where EXPR                                            \n"
    "                             Synthesize difference between two firewalls    \n"
    "related(P) where EXPR        Display rules related to the selected packets  \n"
    "\n"
    "COMPILING\n"
    "ifcl(POLICY)                 Convert a configuration to the generic language\n"
    "porting(P, TARGET[, FILE])   Compile the policy P into the TARGET language  \n"
)

# Token that ignores newlines
token_endl = lambda p: many(space_endls) >> p << many(space_endls)
sym = lambda p: token_endl(string(p))

until0 = lambda s: (many(none_of(s))).parsecmap(''.join)
litstr = token_endl(between(string('"'), string('"'), until0('"')))

or_symbol = lambda *lst: reduce(lambda a,b: a^b, map(sym, lst))
identifier = regex('[a-zA-Z\-\_][a-zA-Z0-9\-\_]*')
parens = lambda p: between(sym('('), sym(')'), p)

list_of = lambda p: sym("(") >> sepBy1(p, sym(",")) << sym(")")

# TODO: show warning if dnatIp is used in filter query
fields = or_symbol(*NAMES).parsecmap(lambda n: NAMES[n])

echo = (sym('echo') >> litstr).parsecmap(Echo)
ifcl = sym('ifcl') >> parens(identifier).parsecmap(lambda p: Ifcl(p))
aliases = sym('aliases') >> parens(identifier).parsecmap(lambda p: Aliases(p))
locals_ = sym('locals') >> parens(identifier).parsecmap(lambda p: Locals(p))
setting = (sym('help').parsecmap(lambda _: Echo(help_message)) ^
           sym('show_time').parsecmap(lambda _: ShowTime()) ^
           sym('verbose_mode').parsecmap(lambda _: VerboseMode()) ^
           sym('table_style') >> identifier.parsecmap(lambda s: TableStyle(s)))

@generate
def porting():
    _      = yield sym('porting')
    _      = yield sym('(')
    p      = yield identifier
    target = yield sym(',') >> identifier
    write  = yield optional(sym(',') >> litstr)
    _      = yield sym(')')
    preturn ( Porting(p, target, write) )

@generate
def comparison():
    analysis = yield or_symbol('equivalence', 'implication', 'diff')
    p1, p2   = yield parens((identifier << sym(',')) + identifier)
    projection = yield option(sym('project') >> list_of(fields), [])
    table    = yield option(sym('in') >> table_name, ('all', 'all'))
    query    = yield option(sym('where') >> expression, QTrue())
    preturn ( Comparison(analysis, p1, p2, projection, table, query) )

@generate
def synthesis():
    analysis   = yield or_symbol('synthesis', 'nondet')
    policy     = yield parens(identifier)
    projection = yield option(sym('project') >> list_of(fields), [])
    table      = yield option(sym('in') >> table_name, ('all', 'all'))
    query      = yield option(sym('where') >> expression, QTrue())
    option_    = yield option(sym('by') >> sym('interfaces'), None)
    if analysis == 'synthesis':
        preturn ( Synthesis(policy, projection, table, query, option_) )
    preturn ( Nondeterminism(policy, projection, table, query) )

@generate
def related():
    _      = yield sym('related')
    policy = yield parens(identifier)
    query  = yield option(sym('where') >> expression, QTrue())
    preturn ( Related(policy, query) )

@generate
def load_policy():
    name                      = yield token_endl(identifier)
    _                         = yield sym('=')
    _                         = yield sym('load_policy')
    (frontend, fpath), config = yield parens( ((identifier | litstr) << sym(',')) +
                                              (litstr << sym(',')) + litstr )
    preturn ( Assignment(name, LoadPolicy(frontend, fpath, config)) )

@generate
def fws_command():
    cmd = yield ( echo ^ setting ^ aliases ^ locals_ ^ porting ^ comparison ^ synthesis ^
                  related ^ ifcl ^ load_policy ^ comment.parsecmap(lambda _: Nop()) ^
                  identifier.parsecmap(lambda n: ShowIdentifier(n)) )
    preturn ( cmd )


################################################################################
## PARSER

@generate
def table_name():
    tables = ['forward', 'input', 'output', 'loopback', 'all']
    subtables = ['filter', 'nat', 'all']
    res = yield or_symbol(*tables) + (option(sym('/') >> or_symbol(*subtables), 'all'))
    preturn(res)

@generate
def term():
    true_ = token_endl(regex('(?i)true')).parsecmap(lambda _: True)
    false_ = token_endl(regex('(?i)false')).parsecmap(lambda _: False)
    value = (mac_addr ^ identifier ^ ip_range ^ ip_subnet ^ ip_addr ^ port_range ^ port)
    assignment = (fields + (sym('=') >> value)).parsecmap(lambda p: Match(*p))
    list_match = (fields + (sym('in') >> list_of(value))).parsecmap(lambda p: MatchList(*p))
    res = yield (true_ | false_ | assignment ^ list_match)
    preturn (res)

@generate
def expression():
    @generate
    def exp_single():
        res = yield (token_endl(regex('(?i)not')) >> sub_exp).parsecmap(Not)
        preturn (res)

    parentesized = parens(expression)
    sub_exp = parentesized ^ exp_single ^ term
    and_ = (sub_exp + (token_endl(regex('(?i)and') | string('&&'))
                       >> expression)).parsecmap(lambda p: And(*p))
    or_ = (sub_exp + (token_endl(regex('(?i)or') | string('||'))
                      >> expression)).parsecmap(lambda p: Or(*p))
    exp_double = and_ ^ or_
    res = yield (exp_double ^ exp_single ^ parentesized ^ term)
    preturn (res)


################################################################################
## ALIASES

def walk(fn, expr):
    if isinstance(expr, And) or isinstance(expr, Or):
        fst = walk(fn, expr.fst)
        snd = walk(fn, expr.snd)
        return expr.__class__(fst, snd)
    if isinstance(expr, Not):
        fst = walk(fn, expr.fst)
        return Not(fst)
    return fn(expr)

def replace_aliases(expr, aliases):
    PROTOS = protocols()

    # check that every alias has been substituted:
    # we should move all the checks/exceptions in the python code
    # since the haskell ones cannot be catched
    def expanded(value):
        return (isinstance(value, IPv4Address) or
                isinstance(value, IPv4Network) or
                isinstance(value, IPv4Range) or
                isinstance(value, Port) or
                isinstance(value, PortRange) or
                isinstance(value, MACAddress) or
                value in ['*', 'NEW', 'ESTABLISHED'] or
                value in PROTOS)

    def fn(match):
        if isinstance(match, Match):
            value = aliases.get(match.value, match.value)
            if isinstance(value, list):
                return MatchList(match.variable, value)
            if not expanded(value):
                raise UnboundAliasError(value)
            return Match(match.variable, value)
        if isinstance(match, MatchList):
            values = [ aliases.get(v, v) for v in match.value ]
            for v in values:
                if not expanded(v):
                    raise UnboundAliasError(v)
            return MatchList(match.variable, values)
        if isinstance(match, QTrue):
            return match
        raise RuntimeError('Invalid Match Object')

    return walk(fn, expr)

################################################################################
## REPL

class FWSRepl(object):

    INTRO = "FireWall Synthesizer - Language-independent Synthesis of Firewall Policies"
    PROMPT = "FWS> "

    def __init__(self):
        self.fws = FWSInterpreter()
        self.multiline_mode = False
        self.prompt = self.PROMPT

    def eval_file(self, path):
        "Parse and evaluate an entire fws script"
        contents = open(path).read()
        self.eval_string(contents)

    def eval_string(self, contents):
        commands = many1(fws_command << many(space|endl)).parse_strict(contents)
        for cmd in commands:
            try:
                cmd.eval(self.fws)
            except UnboundAliasError as e:
                raise RuntimeError("<!> Unbound alias: {}".format(e.message))
            except UnboundVariableError as e:
                raise RuntimeError("<!> Unbound variable: {}".format(e.message))
            except UnknownTableStyle as e:
                raise RuntimeError("<!> Unknown table style: {}".format(e.message))
            except FWSError as e:
                raise RuntimeError("<!> FWS Error: {}".format(e.message))

    def repl(self):
        import readline

        if self.INTRO:
            print self.INTRO

        while True:
            try:
                line = raw_input(self.prompt)
                line = line.rstrip('\r\n')
                lines = [line]
                if ';' in line:
                    lines = map(lambda x: x.strip(), line.split(';'))
                for line in lines:
                    ast = self.parseline(line)
                    ast.eval(self.fws)
            except EOFError:
                print "EOF"
                break
            except IOError as e:
                print "<!> IOError: {}".format(e)
            except ParseError as e:
                print "<!> Parse error: {}".format(e)
            except UnboundAliasError as e:
                print "<!> Unbound alias: {}".format(e.message)
            except UnboundVariableError as e:
                print "<!> Unbound variable: {}".format(e.message)
            except UnknownTableStyle as e:
                print "<!> Unknown table style: {}".format(e.message)
            except FWSError as e:
                print "<!> FWS Error: {}".format(e.message)

    def parseline(self, line):
        if line:
            return fws_command.parse_strict(line)
        return Nop()

################################################################################
## TESTS

if __name__ == '__main__':
    terp = FWSRepl()
    if len(sys.argv) == 1:
        terp.repl()
    else:
        terp.eval_file(sys.argv[1])
