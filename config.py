#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
"""
AX25 over UDP router - Configuration File

Copyright (c) 2005 by DAP900, Daniel Parthey

E-Mail  : pada@hrz.tu-chemnitz.de
Homepage: http://nd0chz.webhop.org/
"""

# Routing table, default: { } (empty)
# Write callsigns in CAPITAL letters, they are case-sensitive!
routes = {
   ('NODES',  0): ('127.0.0.1',               9393),
   ('CB0ESN', 0): ('127.0.0.1',		      9393),
   ('CB0ESN', 1): ('127.0.0.1',                 91),
   ('CB0DLN', 8): ('cb0dln.dyndns.org',         93),
   ('DNX530', 0): ('217.172.183.190',           93),
   ('KS1NOD', 0): ('195.16.245.57',             93),
   ('I01SRV', 0): ('83.169.7.48',            40000),
   ('I02SRV', 0): ('85.214.73.38',              93),
   ('DOK346', 0): ('dok346.dyndns.org',         93),
   ('LNK404', 0): ('85.25.133.163',             93),
   ('AT2SN',  0): ('at2sn.sytes.net',           94),
   ('CB0RG',  0): ('62.75.171.215',             93),
   ('DNX399', 0): ('85.214.42.234',  			93),
   ('RB1NET', 0): ('rb1net.dyndns.info',        93),
   ('CB1GBZ', 0): ('mik710.homeip.net',         93),
   ('CB0NET', 0): ('88.198.40.37',              95),
   ('FT0NOD', 0): ('217.18.177.46',				93),
   ('DNO266', 0): ('dno266.dyndns.org',			98),
   ('WA1NET', 0): ('wa1net.dawic.de',			93),
   ('I01SAA', 0): ('62.75.171.117',            205),
   ('KR2GAT', 0): ('62.75.171.117',             93),
   ('DNX274', 0): ('dnx274.dyndns.org',         93)
   
}

# IP to listen on for packets, default: 0.0.0.0 (all network interfaces)
listen = "0.0.0.0"

# Port number for incoming and outgoing UDP packets, default: 10093
udp_port = 93

# Route lifetime in seconds, default: 3600
lifetime = 172800

# Filename for output messages (absolute path or relative to the program dir)
logfile = "axrouter.log"

# More messages (0=no / 1=yes), default: 0
verbose = 0

# Debug level (0..9)
debug = 1
