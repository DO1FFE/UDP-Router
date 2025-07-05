#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
"""
AX25 over UDP router - Debug Module

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
import sys

# Import axrouter modules
from const import *

def dump_string(string, file=None):
  """convert contents of a string into character, decimal and hexadecimal"""
  # if no file is given, use stdout for output
  if file is None:
    file = sys.stdout
  # begin strings with a quote
  posstring = "\""
  hexstring = "\""
  charstring = "\""
  # analyze each character of the string
  for position in range(len(string)):
    # convert character into an integer number
    ordinal = ord(string[position])
    # output position of character
    posstring += " %3i" % (position)
    # convert character into hex
    hexstring += "\\x%02X" % (ordinal)
    # convert character into something printable
    shifted_char = ordinal >> 1
    if chr(shifted_char).isalnum(): charstring += "%4s" % (chr(shifted_char))
    else:                           charstring += "%4s" % ("?")
  # end strings with a quote
  posstring  += "\""
  hexstring  += "\""
  charstring += "\""
  return posstring + NL + hexstring + NL + charstring + NL
