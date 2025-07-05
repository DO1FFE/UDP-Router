#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
"""
AX25 over UDP router - Logging Module

Copyright (c) 2005 by DAP900, Daniel Parthey

E-Mail  : pada@hrz.tu-chemnitz.de
Homepage: http://nd0chz.webhop.org/

-------------------------------------------------------------------------------
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.
  
You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
-------------------------------------------------------------------------------
"""

# Import python modules
import os, sys

# global variable which can keep a handle of the logfile
logfile = None

def open_logfile(workdir, filename):
  """
  open logfile for writing output messages
  """
  # declare logfile handle as global
  global logfile
  # if logfile path is a relative path, prepend the working directory
  if not os.path.isabs(filename):
    filename = os.path.join(workdir, filename)
  # open the logfile in unbuffered mode
  logfile = open(filename, "w")

def log(string):
  """
  write to the logfile
  string - the string that should be written to the logfile
  """
  logfile.write(string)
  logfile.flush()

def log_print(string):
  """
  write to the logfile and print on stdout
  string - the string that should be printed and written to the logfile
  """
  sys.stdout.write(string)
  log(string)

