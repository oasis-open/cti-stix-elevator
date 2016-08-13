# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import sys

def info(fmt, *args):
    msg = fmt % args
    print "[INFO]", msg

def warn(fmt, *args):
    msg = fmt % args
    sys.stderr.write("[WARN] %s\n" % msg)

def error(fmt, *args):
    msg = fmt % args
    sys.stderr.write("[ERROR] %s\n" % msg)
