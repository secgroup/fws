import tempfile

import fwsynthesizer
from fwsynthesizer.frontends import FRONTENDS
from fwsynthesizer.compile import TARGETS

from parsec import *
from fwsynthesizer.parsers.utils import *
from fwsynthesizer.synthesis.query import *

import os

from flask import Flask, request, jsonify, Response, redirect, abort, send_from_directory

from contextlib import contextmanager
import ctypes
import os, sys
import time
import threading
import logging
import json

libc = ctypes.CDLL(None)
c_stdout = ctypes.c_void_p.in_dll(libc, 'stdout')
c_stderr = ctypes.c_void_p.in_dll(libc, 'stderr')

@contextmanager
def stdout_stderr_redirector(fd, fderr):
    # The original fd stdout points to. Usually 1 on POSIX systems.
    original_stdout_fd = sys.stdout.fileno()
    original_stderr_fd = sys.stderr.fileno()

    def _redirect_stdout(to_fd):
        libc.fflush(c_stdout) # Flush the C-level buffer stdout
        sys.stdout.close() # Flush and close sys.stdout - also closes the file descriptor (fd)
        os.dup2(to_fd, original_stdout_fd) # Make original_stdout_fd point to the same file as to_fd
        sys.stdout = os.fdopen(original_stdout_fd, 'wb', 0) # Create a new sys.stdout that points to the redirected fd

    def _redirect_stderr(to_fd):
        libc.fflush(c_stderr)
        sys.stderr.close()
        os.dup2(to_fd, original_stderr_fd)
        sys.stderr = os.fdopen(original_stderr_fd, 'wb', 0)
        
    saved_stdout_fd = os.dup(original_stdout_fd)
    saved_stderr_fd = os.dup(original_stderr_fd)
    try:
        _redirect_stdout(fd)
        _redirect_stderr(fderr)
        # Yield to caller, then redirect stdout back to the saved fd
        yield
        _redirect_stdout(saved_stdout_fd)
        _redirect_stderr(saved_stderr_fd)
    finally:
        os.close(saved_stdout_fd)
        os.close(saved_stderr_fd)


app = Flask(__name__, static_url_path=os.path.abspath(os.path.join(__file__,'static')))

# This is needed as our trick with fds breaks flask!
log = logging.getLogger('werkzeug')
log.disabled = True

active_interpreters = {}


@app.after_request
def after_request(response):
    header = response.headers
    header['Access-Control-Allow-Origin'] = '*'
    header['Access-Control-Allow-Headers'] = '*'
    return response


@app.route('/frontends')
def list_frontends():
    return jsonify(FRONTENDS)

@app.route('/compiler/targets')
def list_targets():
    return jsonify(TARGETS)

@app.route('/new_repl')
def new_interpreter():
    global active_interpreters
    
    terp = FWSRepl()
    terp.fws.table_style = fwsynthesizer.TableStyle.HTML
    active_interpreters[id(terp)] = terp
    return jsonify({'value': id(terp)})

@app.route('/<int:interpreter>/load_policy', methods=['POST'])
def load_policy(interpreter):
    args = request.json
    fws = active_interpreters[interpreter].fws
    name = args["name"]
    frontend = args["frontend"]
    policy = args["policy"]
    conf = args["conf"]
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp_policy, tempfile.NamedTemporaryFile(delete=False) as tmp_config:
            
            tmp_policy.write(args["policy"]); tmp_policy.flush()
            tmp_config.write(args["conf"]); tmp_config.flush()

            Assignment(
                args["name"],
                LoadPolicy(
                    frontend = args["frontend"],
                    file     = tmp_policy.name,
                    config   = tmp_config.name
                )).eval(fws)
    except ParseError as e:
        return jsonify({'error': 'Parse Error', 'msg': str(e)})
    return jsonify({'value': args["name"]})

@app.route('/<int:interpreter>/eval', methods=['POST'])
def eval_string(interpreter):
    args = request.json
    terp = active_interpreters[interpreter] 
    terp.fws.table_style = fwsynthesizer.TableStyle.HTML
    contents = args['contents']

    (r,w) = os.pipe()
    
    def producer():
        with stdout_stderr_redirector(w, w):
            try:
                terp.eval_string(contents.encode())
            except RuntimeError as e:
                print(str(e))
        os.close(w)

    def generate():
        rd = None
        while rd != '':
            rd = os.read(r,100)
            yield rd
        os.close(r)
        raise StopIteration

    threading.Thread(target=producer).start()
        
    return Response(generate(), mimetype='text/html')
            
 
@app.route('/compiler/translate', methods=['POST'])
def translate_tables():
    args = request.json
    target = args['target']
    fwspolicy = json.loads(args['fwspolicy'])
    

    mrules = policy_to_mrules(fwspolicy)
    semantics = fwsynthesizer.SynthesisOutput(None, mrules, mrules_precomputed=True)
    configuration = fw_compile(semantics, target)
    
    return jsonify({'value': configuration})

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/<folder>/<path:path>')
def send_js(folder,path):
    if folder not in ['js', 'fonts', 'css', 'img']:
        return abort(404)
    return app.send_static_file(os.path.join(folder, path))

def start_app(host="localhost", port="5095"):
    app.run(
        host=host,
        port=port,
        debug=False,
        threaded=True,
        processes=1,
    )

################################################################################
## Compiler

def policy_to_mrules(fwspolicy):
    aliases = fwspolicy['aliases']
    local_addresses = [ [x,x] for x in
                        [ struct.unpack(">I", ipaddr.IPv4Address(ip).packed)[0] for ip in fwspolicy['locals'] ]]

    def remove_docs(intervals):
        if isinstance(intervals, DOC):
            new_ints = intervals.to_cubes()
        else:
            new_ints = []
            for i in intervals:
                if isinstance(i, DOC):
                    new_ints.extend(i.to_cubes())
                else:
                    new_ints.append(i)
        return new_ints
    
    def remove_locals_if(mode, modes, intervals):
        if mode not in modes:
            return intervals

        if isinstance(intervals, DOC):
            intervals.diffs.extend(local_addresses)
            return intervals
        new_ints = []
        for i in intervals:
            new_ints.append(DOC(i, local_addresses))
        return new_ints


    def expand_and_parse(tables, mode):
        mrules = []
        
        for rules in tables:
            is_snat = not all("SNAT" not in f for f in rules['field_names'])
            is_dnat = not all("DNAT" not in f for f in rules['field_names'])
    
            for r in rules['table']:
                for rep in aliases:
                    for field in r:
                        r[field] = r[field].replace(*rep)

                pin = map(remove_docs, [
                    # srcIp, srcPort, dstIp, dstPort, srcMac, dstMac, protocol, state[, mark]   
                    remove_locals_if(
                        mode, ['forward', 'input'],
                        interval_parser(ip_range_parser(), [0, 2**32-1]).parse_strict(r['srcIp'].encode())),
                    interval_parser(port_parser, [0, 2**16-1]).parse_strict(r['srcPort'].encode()),
                    remove_locals_if(
                        mode, ['forward', 'output'] if not ("dstIp'" in r and r["dstIp'"].strip() != '-') else [],
                        interval_parser(ip_range_parser(), [0, 2**32-1]).parse_strict(r['dstIp'].encode())),
                    interval_parser(port_parser, [0, 2**16-1]).parse_strict(r['dstPort'].encode()),
                    interval_parser(mac_parser, [0, 2**48-1]).parse_strict(r['srcMac'].encode()),
                    interval_parser(mac_parser, [0, 2**48-1]).parse_strict(r['dstMac'].encode()),
                    interval_parser(protocol_parser, [0, 255]).parse_strict(r['protocol'].encode()),
                    interval_parser(state_parser, [0,1]).parse_strict(r['state'].encode()),
                ])
                pout = [[], [], [], [], [], [], [], []]
                
                if is_snat or is_dnat:
                    # nat
                    pout = map(remove_docs, [
                        interval_parser(ip_range_parser(), [0, 2**32-1]).parse_strict(r["srcIp'"].encode())
                        if "srcIp'" in r and r["srcIp'"].strip() != "-" else [],
                        interval_parser(port_parser, [0, 2**16-1]).parse_strict(r["srcPort'"].encode())
                        if "srcPort'" in r and r["srcPort'"].strip() != "-" else [],
                        remove_locals_if(mode, ['forward', 'output'], interval_parser(ip_range_parser(), [0, 2**32-1]).parse_strict(r["dstIp'"].encode()))
                        if "dstIp'" in r and r["dstIp'"].strip() != "-" else [],
                        interval_parser(port_parser, [0, 2**16-1]).parse_strict(r["dstPort'"].encode())
                        if "dstPort'" in r and r["dstPort'"].strip() != "-" else [],
                        [], [], [], []])

                mrules.append([pin, pout])
        return mrules


    rules = []
    rules.extend( expand_and_parse(fwspolicy['forward'], 'forward') )
    rules.extend( expand_and_parse(fwspolicy['input'], 'input') )
    rules.extend( expand_and_parse(fwspolicy['output'], 'output') )
    rules.extend( expand_and_parse(fwspolicy['loopback'], 'loopback') )
    
    return rules


def ip_range_parser():

    def to_interval(b):
        if isinstance(b, ipaddr.IPv4Network):
            return b.ip, ipaddr.IPv4Address(b._ip | (0xffffffff >> b.prefixlen))
        if isinstance(b, ipaddr_ext.IPv4Range):
            return b.ip_from, b.ip_to
        if isinstance(b, ipaddr.IPv4Address):
            return b, b
        raise NotImplemented

    def make_int_interval(elm):
        a, b = to_interval(elm)
        return [ struct.unpack(">I", a.packed)[0], struct.unpack(">I", b.packed)[0] ]
    
    return (ip_range ^ ip_subnet ^ ip_addr).parsecmap(make_int_interval)

protos = {name: int(proto) for name, proto in utils.protocols().items()}
states = {'NEW':0, 'ESTABLISHED': 1}

def hr_parser(mappings):
    
    def name_to_interval(e):
        v = mappings[e]
        return [v,v]

    return regex('[a-zA-Z]+').parsecmap(name_to_interval)

protocol_parser = hr_parser(protos)
state_parser = hr_parser(states)
port_parser = (port_range ^ port).parsecmap(
    lambda p:
    [int(p.value), int(p.value)] if isinstance(p, Port) else \
    [int(p.bottom), int(p.top)] if isinstance(p, PortRange) else [])

mac_parser = mac_addr.parsecmap(lambda mac: [mac._mac, mac._mac])

class DOC(object):
    def __init__(self, rng, diffs):
        self.range = rng
        self.diffs = diffs

    def __repr__(self):
        return 'DOC(range={}, diffs={})'.format(self.range, self.diffs)
    
    def to_cubes(self):
        min_, max_ = self.range
        sgaps = sorted(filter(lambda x: min(*x) >= min_ and max(*x) <= max_, self.diffs),
                      key=lambda x: x[0])
        # gaps need to be mutually exclusive

        gaps = []
        for gap in sgaps:
            (gb, gt) = gap

            if gaps == []:
                gaps.append(gap)
            else:
                (nb, nt) = gaps[-1]
                if gb >= nb  and gb <= nt and gt <= nt:
                    # included, do nothing
                    pass
                elif gb >= nb and gb <= nt and gt >= nt:
                    # overlapping, replace nt
                    gaps[-1] = [nb, gt]
                else:
                    gaps.append(gap)
            
        ints = [[min_, max_]]
        for (bottom, top) in gaps:
            last_min, last_max = ints[-1]

            if bottom == last_min:
                assert top+1 < last_max
                ints[-1] = [top+1, last_max]
            elif top == last_max:
                assert bottom-1 > last_min
                ints[-1] = [last_min, bottom-1]
            else:
                ints[-1] = [last_min, bottom-1]
                ints.append([top+1, last_max])

        for (bottom, top) in gaps:
            assert (bottom <= top)
        for (bottom, top) in ints:
            assert (bottom <= top)
        return ints
                

def interval_parser(elem_parser, elem_all): # -> Parser[ Union[DOC, List[Intervals]] ]
    token_endl = lambda p: many(space_endls) >> p << many(space_endls)
    
    star = string('*').parsecmap(lambda _: [elem_all])
    multiple = sepBy(elem_parser, space_endls)
    negate = (
        (token_endl(regex('\*\s+\\\\').parsecmap(lambda _: elem_all)
                    ^ (token_endl(elem_parser) << token_endl(string("\\")))) +
         between(token_endl(string("{")), token_endl(string("}")), multiple))).parsecmap(
             lambda (rng, dffs): DOC(rng, dffs))

    return (token_endl(negate ^ star ^ multiple) )


