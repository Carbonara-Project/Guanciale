#!/usr/bin/env python

__author__ = "Andrea Fioraldi, Luigi Paolo Pileggi"
__copyright__ = "Copyright 2017, Carbonara Project"
__license__ = "BSD 2-clause"
__email__ = "andreafioraldi@gmail.com, willownoises@gmail.com"

from idautils import *
from idaapi import *
from idc import *
import os

# --------> LUIGI <-----------

for seg in idautils.Segments():
	print idc.SegName(seg), idc.SegStart(seg), idc.SegEnd(seg)