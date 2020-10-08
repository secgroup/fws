import tempfile

import fwsynthesizer
from fwsynthesizer.frontends import FRONTENDS

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
    fwspolicy = args['fwspolicy']

    # TODO
    
    return jsonify({'value': None})

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
