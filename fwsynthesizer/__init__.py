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

from compile import *

################################################################################
# MAIN

def main():
    parser = argparse.ArgumentParser(
        description="FireWall Synthesizer - Language-independent Synthesis of Firewall Policies")

    parser.add_argument("script", metavar="SCRIPT",
                        help="FWS Script", nargs='?')
    args = parser.parse_args()

    terp = ui.FWSRepl()
    if args.script:
        terp.eval_file(args.script)
    else:
        terp.repl()
