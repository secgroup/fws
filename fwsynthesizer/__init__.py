#!/usr/bin/env python2

import argparse
import os
import sys
import time
from datetime import timedelta

from frontends import *
from synthesis import *
from utils import *

import synthesis.query as ui
import web

import sys

from compile import *

################################################################################
# MAIN

def main():
    parser = argparse.ArgumentParser(
        description="FireWall Synthesizer - Language-independent Synthesis of Firewall Policies")

    parser.add_argument("-m","--mode", help="FWS mode (web, cli), default=web", required=False, default="web")
    parser.add_argument("script", metavar="SCRIPT",
                        help="FWS Script (cli mode)", nargs='?')
    args = parser.parse_args()

    if args.mode == "web":
        web.start_app(host="0.0.0.0")
    elif args.mode == "cli":

        terp = ui.FWSRepl()
        if args.script:
            terp.eval_file(args.script)
        else:
            terp.repl()
    else:
        print("fws: error: invalid mode!")
        sys.exit(1)
