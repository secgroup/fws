#!/usr/bin/env python2

import itertools
import struct
import ipaddr
import fwsynthesizer.utils as utils
import fwsynthesizer.utils.table as table
import fwsynthesizer.utils.macaddr as macaddr
import fwsynthesizer.utils.ipaddr_ext as ipaddr_ext

header = [ ("srcIp", "Source IP"), ("srcPort", "Source Port"),
           ("srcIp'", "SNAT IP"), ("srcPort'", "SNAT Port"),
           ("dstIp'", "DNAT IP"),("dstPort'", "DNAT Port"),
           ("dstIp", "Destination IP"), ("dstPort", "Destination Port"),
           ("srcMac", "Source MAC"), ("dstMac", "Destination MAC"),
           ("protocol", "Protocol"), ("state", "State")]

filter_projection = ['srcIp', 'srcPort', 'dstIp', 'dstPort', 'srcMac', 'dstMac',
                     'protocol', 'state']

protos = {int(proto): name for name, proto in utils.protocols().items()}
states = {0: 'NEW', 1: 'ESTABLISHED'}


def show_interval(interval, top=65535, bottom=0, names={}):
    "Show interval (as '*' if it represents all numbers and replace names)"

    a,b = sorted(interval)
    if a == bottom and b == top: return '*'
    if a == b:
        name = names.get(a)
        return '{}'.format(name if name else a)

    if isinstance(a, ipaddr.IPv4Address) and isinstance(b, ipaddr.IPv4Address):
        s = summarize_ip_interval(a, b)
        name = names.get(s)
        return '{}'.format(name if name else s)

    return '{}-{}'.format(a,b)


def summarize_ip_interval(a,b):
    "Print an ip range either as a subnet in cdir notation or as interval"

    assert isinstance(a, ipaddr.IPv4Address) and isinstance(b, ipaddr.IPv4Address)
    na = struct.unpack(">I", a.packed)[0]
    nb = struct.unpack(">I", b.packed)[0]

    if na == 0 and nb == 0xffffffff:
        return '0.0.0.0/0'

    rest = list(itertools.dropwhile(lambda (x,y): x==y, zip(bin(na)[2:], bin(nb)[2:])))
    if all(x == '0' and y == '1' for x,y in rest):
        return '{}/{}'.format(a, 32-len(rest))
    return '{}-{}'.format(a,b)

def get_gaps(int_list):
    """ Returns the gaps in a list of intervals: inverts the interval using
        its bottom and top values ad universe boundaries """

    int_list = sorted(int_list, key=lambda x: x[0])
    gaps = []
    for i in range(len(int_list)-1):
        a, b = int_list[i]
        c, d = int_list[i+1]
        gaps.append([b+1, c-1])
    return gaps

def inverse_interval(int_list):
    """ Reverse a list of intervals if the number of gaps is less than
        the number of intervals """

    def subtract(b,a):
        if isinstance(a, ipaddr.IPv4Address) or isinstance(a, macaddr.MACAddress):
            a = int(a)
        if isinstance(b, ipaddr.IPv4Address) or isinstance(b, macaddr.MACAddress):
            b = int(b)
        return b - a

    def max_range(int_list):
        return max(subtract(b,a) for a,b in int_list)

    gaps = get_gaps(int_list)

    if gaps and max_range(int_list) > max_range(gaps) and len(int_list) > len(gaps):
        min_ = min(a for a,_ in int_list)
        max_ = max(b for _,b in int_list)
        return ([min_, max_], gaps)
    return ()

def rewrite_with_aliases(intervals, aliases, exact_match=False):
    """ Rewrite a list of intervals splitting them if they contains aliases """

    def make_range(string):
        try:
            return macaddr.MACAddress(string)
        except ValueError:
            try:
                return ipaddr_ext.IPv4Range(string)
            except ipaddr.AddressValueError:
                return ipaddr.IPv4Network(string)

    def to_interval(b):
        if isinstance(b, ipaddr.IPv4Network):
            return b.ip, ipaddr.IPv4Address(b._ip | (0xffffffff >> b.prefixlen))
        if isinstance(b, ipaddr_ext.IPv4Range):
            return b.ip_from, b.ip_to
        if isinstance(b, ipaddr.IPv4Address):
            return b, b
        raise NotImplemented

    # Populate aliases ranges as IPv4Range or IPv4Network
    ranges = {}
    for name in aliases:
        ranges[name] = make_range(aliases[name])

    def find_alias(address):
        matches = []
        for r,interval in ranges.items():
            if address == interval:
                matches.append( (True, r, interval) )
            # if alias is contained in address
            elif ((not isinstance(address, ipaddr.IPv4Address))
                  and interval in address):
                matches.append( (False, r, interval) )
        return matches

    # WARNING: messy code ahead! (but it gets the job done ;P)
    # Rewrite intervals using aliases
    new_ints = []
    names = {}
    for interval in intervals:
        a,b = interval
        # If they are equal and they match a alias, append the alias to names
        if a == b:
            aliases = find_alias(a)
            if any(exact for exact,_,_ in aliases):
                exact, alias, _ = [m for m in aliases if m[0]][0]
                names[a] = alias
            new_ints.append(interval)
        # If they are not equal, try to match an interval
        else:
            # They match a network?
            s = summarize_ip_interval(a,b)
            rng = make_range(s)
            aliases = find_alias(rng)
            if not aliases or s == '0.0.0.0/0':
                new_ints.append(interval)
            elif any(exact for exact,_,_ in aliases):
                exact, alias, _ = [m for m in aliases if m[0]][0]
                names[s] = alias
                new_ints.append(interval)
            elif not exact_match:
                # No exact match, try to split the interval
                # 1) take only the largest matches
                for match in aliases[::]:
                    _, name, network = match
                    if any(network in mnet and name != mname for _, mname, mnet in aliases):
                        aliases.remove(match)
                # 2) convert interval(a,b) -> (a, alias_bottom-1) U alias U (alias_top +1, b)
                #    for every alias
                aliases = sorted([ (to_interval(network), name) for _, name, network in aliases ],
                                 key=lambda ((x,_),__): x)
                for (n, name) in aliases:
                    if n[0] == n[1]:
                        names[n[0]] = name
                    else:
                        names[summarize_ip_interval(*n)] = name
                intervals = []
                aliases_ints = map(lambda x: x[0], aliases)
                (bottom, _) = aliases_ints[0]
                (_, top) = aliases_ints[-1]
                if a < bottom:
                    intervals.append((a, bottom-1))
                if b > top:
                    intervals.append((b, top+1))
                intervals.extend(aliases_ints)
                intervals.extend(filter(lambda (b,t): b <= t, get_gaps(aliases_ints)))
                new_ints.extend(intervals)
            else:
                new_ints.append(interval)

    # return sorted(new_ints, key=lambda x: x[0]), names
    return new_ints, names


def show_field(lst, default='-', top=65534, bottom=0, names={}, hide=[], aliases={}):
    "Show rule field as a list of lines (table column)"

    if not lst:
        return [default]

    inverse = inverse_interval(lst)
    if inverse:
        tot, ngaps = inverse
        gaps = []
        for g in ngaps:
            if g[0] != g[1] or g[0] not in hide:
                gaps.append(g)

        if aliases:
            gaps, names1 = rewrite_with_aliases(gaps, aliases)
            tot, names2 = rewrite_with_aliases([tot], aliases, exact_match=True)
            tot = tot[0]
            names1.update(names2)
            names = dict(names, **names1)

        if not gaps:
            return ['{}'.format(show_interval(tot, top, bottom, names))]

        if len(gaps) == 1:
            return ['{} \\ {{{}}}'.format(
                show_interval(tot, top, bottom, names), show_interval(gaps[0], top, bottom, names))]

        return ([ '{} \\ {{'.format(show_interval(tot, top, bottom, names))] +
                ['  '+show_interval(g, top, bottom, names) for g in gaps] +
                [ '}' ])

    if aliases:
        lst, names1 = rewrite_with_aliases(lst, aliases)
        names = dict(names, **names1)

    return sorted(show_interval(i, top, bottom, names) for i in lst)


def rule_to_rowg(rule, hide=[], hide_src=False, hide_dst=False, prefix=[], aliases={}):
    "Turn a rule object into a list of strings (to be used as row_group)"

    def ljust(lst, n, fillvalue=''):
        return lst + [fillvalue] * (n - len(lst))

    bottom_ip = ipaddr.IPv4Address(0)
    top_ip = ipaddr.IPv4Address(2**32-1)
    bottom_mac = macaddr.MACAddress(0)
    top_mac = macaddr.MACAddress(2**48-1)

    hidesrc = hide if hide_src else []
    hidedst = hide if hide_dst else []

    columns = [
        show_field( rule.srcIp,    default='*', bottom=bottom_ip, top=top_ip, hide=hidesrc, aliases=aliases),
        show_field( rule.srcPort,  default='*', bottom=0, top=2**16-1),
        show_field( rule.snatIp,   default='-', bottom=bottom_ip, top=top_ip, hide=hidesrc, aliases=aliases),
        show_field( rule.snatPort, default='-', bottom=0, top=2**16-1),
        show_field( rule.dnatIp,   default='-', bottom=bottom_ip, top=top_ip, hide=hidedst, aliases=aliases),
        show_field( rule.dnatPort, default='-', bottom=0, top=2**16-1),
        show_field( rule.dstIp,    default='*', bottom=bottom_ip, top=top_ip, hide=hidedst, aliases=aliases),
        show_field( rule.dstPort,  default='*', bottom=0, top=2**16-1),
        show_field( rule.srcMac,   default='*', bottom=bottom_mac, top=top_mac),
        show_field( rule.dstMac,   default='*', bottom=bottom_mac, top=top_mac),
        show_field( rule.protocol, default='*', bottom=0, top=2**8-1, names=protos),
        show_field( rule.state,    default='*', bottom=0, top=1, names=states),
    ]
    if prefix:
        columns = [prefix] + columns
    length = max(len(l) for l in columns)
    strings = [ ljust(l, length) for l in columns ]
    return zip(*strings)

# TODO: check projection (nat field on filter table)
def print_table(rules, table_style='unicode',
                local_address=[], hide_src=False, hide_dst=False,
                hide_nats=False, hide_filters=False, projection=[], aliases={}):

    """Print a list of rules into a table, dividing filters and nats
       and optionally hiding local addresses"""

    def display_table(rules, projection=[]):
        t = table.Table(header, style=table_style)
        t.project(projection)
        for rule in rules:
            t.append_row_group(rule_to_rowg(rule, local_address, hide_src, hide_dst, aliases=aliases))
        print t.render()

    filters = [rule for rule in rules if rule.type == 'FILTER']
    nats = [rule for rule in rules if rule.type == 'NAT']

    if filters and not hide_filters:
        display_table(filters, projection=filter_projection if not projection else projection)
    if nats and not hide_nats:
        display_table(nats, projection=projection)


def print_diff_table(name_plus, name_minus, rules_plus, rules_minus,
                     table_style='unicode',
                     local_address=[], hide_src=False, hide_dst=False,
                     projection=[], aliases={}):
    """Print a tuple of rules into a table dividing additions and deletions
       prefixing each row with a + or a -"""

    def display_table(rules, projection=[]):
        t = table.Table([('diff', '+/-')] + header, style=table_style)
        t.project(projection)
        for (plus, rule) in rules:
            t.append_row_group(rule_to_rowg(rule, local_address, hide_src, hide_dst,
                                            prefix = ['+'] if plus else ['-'], aliases=aliases))
        print t.render()

    if not rules_plus and not rules_minus:
        return

    print "+++", name_plus
    print "---", name_minus

    filters = ([(True, rule) for rule in rules_plus if rule.type == 'FILTER'] +
               [(False, rule) for rule in rules_minus if rule.type == 'FILTER'])
    nats = ([(True, rule) for rule in rules_plus if rule.type == 'NAT'] +
            [(False, rule) for rule in rules_minus if rule.type == 'NAT'])

    if filters:
        display_table(filters, projection=['diff']+filter_projection if not projection else ['diff'] + projection)
    if nats:
        display_table(nats, projection=['diff']+projection if projection else [])

if __name__ == '__main__':
    # TESTS
    print rewrite_with_aliases([(ipaddr.IPv4Address('10.0.0.0'), ipaddr.IPv4Address('10.0.2.255')), (ipaddr.IPv4Address('127.0.0.1'), ipaddr.IPv4Address('127.0.0.1'))], {'lan0': '10.0.1.0/24', 'lan1': '10.0.2.0/24'})
