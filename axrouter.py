#!/usr/bin/env python3
# -*- coding: iso-8859-1 -*-

# PROGRAMM VERSION
__version__ = "0.0.1"

"""
AX25 over UDP router

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

# Import python libraries
import getopt, os, socket, sys, time, traceback

# Import axrouter modules
from const import *
import l2
import config
import debug
import logfile

# maximum size of route table
MAXIMUM_NUMBER_OF_ROUTES = 1000

# Configuration defaults
conf = {
  'listen'      : "0.0.0.0",      # bind to all interfaces by default
  'udp_port'    : 10093,          # default UDP port
  'lifetime'    : 3600,           # default route lifetime in seconds
  'logfile'     : "axrouter.log", # logfile
  'quiet'       : False,          # quiet is disabled by default
  'verbose'     : False,          # verbose is disabled by default
  'debug'       : 0,              # debug mode is disabled by default
}

def show_usage():
  print("""
AX25 over UDP router - Version %s

Copyright (c) 2005 by DAP900, Daniel Parthey

E-Mail  : pada@hrz.tu-chemnitz.de
Homepage: http://nd0chz.webhop.org/

Options:

  -h  --help               print this help
  -l  --listen=<IP>        bind to specific interface, default: ANY
  -o  --logfile=<filename> write log messages to this file
  -q  --quiet              no output
  -u  --udp_port=<port>    listen for incoming packets on this UDP port
  -v  --verbose            output more information (only if quiet is not set)
  -V  --version            print version number
  -d  --debug=<0..9>       print debug messages (0=none, ... 9=all)

Usage:  %s [OPTIONS]
""" % (__version__, sys.argv[0]))

class UDP_Router:
  """
  Object that handles the routing table, learning and timeout of routes.
  It also routes packets and sends them to the correct recipient.

  socket  - the udp socket to which outgoing packets should be sent
  """
  def __init__(self, udp_socket):
    """
    Initializes the UDP_Router object
    """
    # open server datagram socket and store handle in variable self.udp_socket
    self.__create_udp_socket()
    # read the initial routing table and resolve hostnames
    self.__build_routing_table()
    # lifetimes have not been aged yet
    self.route_aging_timestamp = None

  def __create_udp_socket(self):
    """
    create UDP server socket where we listen for packets
    and bind the socket to the configured port number
    """
    # create UDP server socket
    try:
      self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except:
      logfile.log_print("could not create UDP socket"+NL)
      sys.exit(1)

    # bind to port given at the command line
    if conf['quiet'] is False:
      logfile.log_print("Listen for incoming packets on %s:%i UDP: " % \
                     (conf['listen'], conf['udp_port']))
    try:
      self.udp_socket.bind((conf['listen'], conf['udp_port']))
      if conf['quiet'] is False: logfile.log_print("OK"+NL)
    except Exception as error_message:
      if conf['quiet'] is False: logfile.log_print("FAILED"+NL)
      logfile.log_print("could not bind %s:%i" % \
                     (conf['listen'], conf['udp_port']) + NL)
      print(error_message)
      try:
        traceback.print_exc(file=logfile.logfile)
      except: pass
      sys.exit(1)

  def serve_forever(self):
    "UDP Server loop - waits for and handles packets"
    if conf['quiet'] is False:
      logfile.log_print((time.asctime(time.localtime()) + \
                     ": axrouter %s is up and running" % (__version__) + NL))
    while True:
      try:
        # receive AX25 packet over UDP (maximum UDP frame length of 64 KB)
        packet, source_addr = self.udp_socket.recvfrom(2<<15)
        # analyse, learn and send packet to the correct recipient
        self.__route_packet(source_addr, packet)
        # timeout count down (aging of routes)
        self.__age_routes()
      except KeyboardInterrupt:
        raise

  def shutdown(self):
    "Cleanly shut down the UDP router"
    # close server socket
    if conf['quiet'] is False:
      logfile.log_print("Close router socket: ")
    try:
      self.udp_socket.close()
      if conf['quiet'] is False: logfile.log_print("OK"+NL)
    except Exception as error_message:
      if conf['quiet'] is False:
        logfile.log_print("FAILED"+NL)
        print(error_message)
        try:
          traceback.print_exc(file=logfile.logfile)
        except: pass
    # close logfile
    if conf['quiet'] is False:
      print("Close logfile:", end=' ')
    try:
      logfile.logfile.close()
      if conf['quiet'] is False: print("OK")
    except Exception as error_message:
      if conf['quiet'] is False:
        print("FAILED")
        print(error_message)

  def __build_routing_table(self):
    """
    Build a routing table out of the initial routes dictionary in routes.py
    
    """
    # start with an empty routing table
    self.routing_table = {}

    # load routes from router configuration
    if conf['quiet'] is False:
      logfile.log_print("Load route configuration from config.py: ")
    try:
      # load routes configuration variable
      routes = config.routes
      if conf['quiet'] is False:
        logfile.log_print("OK"+NL)
    except Exception as error_message:
      # start with empty route configuration if it cannot be imported
      routes = {}
      if conf['quiet'] is False:
        logfile.log_print("FAILED")
        print(error_message)
        try:
          traceback.print_exc(file=logfile.logfile)
        except: pass

    # build routing table and resolve DNS hostnames
    if conf['debug'] >= 3:
      logfile.log_print(NL+"--- Resolving hostnames ---"+NL+NL)
    for route in routes.items():
      # extract information from route list (split the list)
      try:
        # split information
        ((callsign, ssid),(hostname, port)) = route
        # convert ssid to an integer (probably the user has given a string)
        ssid = int(ssid)
        # convert port to an integer (probably the user has given a string)
        port = int(port)
      # handle parsing errors of routes.py config file
      except Exception as error_message:
        print("Error: Syntax error in file routes.py")
        print(error_message)
        try:
          traceback.print_exc(file=logfile.logfile)
        except: pass
        sys.exit(1)
      # print information about the resolved hostname
      if conf['debug'] >= 3:
        logfile.log_print("%6s-%-2i:%45s:%-5i  Hostname: " % \
                       (callsign, ssid, hostname, port))
      # resolve hostname
      try:
        ip = socket.gethostbyname(hostname)
        if conf['debug'] >= 3:
          logfile.log_print("OK"+NL)
        # add new routes only if current route table is not too large
        if len(self.routing_table) < MAXIMUM_NUMBER_OF_ROUTES:
          # build route entry for internal routing table
          self.routing_table[(callsign, ssid)] = {
            'conf_host' : hostname,            # configured hostname or IP
            'conf_port' : port,                # configured port
            'ip'        : ip,                  # dynamically resolved IP address
            'port'      : port,                # dynamic port number
            'proto'     : 'udp',               # protocol is always UDP (yet)
            'lifetime'  : conf['lifetime'],  # start with default lifetime
          }
        else:
          if conf['quiet'] is False:
            logfile.log_print("Route table too large!"+NL)
      # do not add route if the resolving process failed
      except:
        if conf['debug'] >= 3:
          logfile.log_print("FAILED"+NL)
    # print newline after resolve table
    if conf['debug'] >= 3: logfile.log_print(NL)
    # routing table is built
    self.__print_routing_table()

  def __age_routes(self):
    """
    decrease the lifetime of routes, so they become forgotten sometimes
    and forget or renew (resolve) route entries if necessary
    """
    # take current time in seconds since Epoch
    current_time = int(time.time())

    # if this is not the first aging run, decrease lifetimes
    if self.route_aging_timestamp is not None:
      # check if we are later in time than at the last aging run
      if current_time > self.route_aging_timestamp:
        # age routes, because it is at least one second later
        # remember all routes
        all_route_entries = list(self.routing_table.keys())
        # iterate all routes and update or delete routes
        for route_entry in all_route_entries:
          # decrease lifetime by the amount of passed time since last aging
          self.routing_table[route_entry]['lifetime'] = \
            max( 0,
                 self.routing_table[route_entry]['lifetime'] -
                   (current_time - self.route_aging_timestamp)
               )
          # expiration/renewage of routes
          if self.routing_table[route_entry]['lifetime'] == 0:
            # if route is user defined (hostname configured), renew it
            if self.routing_table[route_entry]['conf_host'] is not None:
              hostname = self.routing_table[route_entry]['conf_host']
              if conf['debug'] >= 3:
                logfile.log_print("Resolve %s because route has expired: " % \
                               (hostname))
              # resolve the configured hostname to renew the IP
              try:
                ip = socket.gethostbyname(hostname)
                if conf['verbose'] is True: logfile.log_print("OK"+NL)
                # renew route entry and reset lifetime to default
                self.routing_table[route_entry]['ip']      =ip
                self.routing_table[route_entry]['lifetime']=conf['lifetime']
              except:
                if conf['verbose'] is True: logfile.log_print("FAILED"+NL)
            # if route is dynamically learned (no hostname), delete it
            else:
              del self.routing_table[route_entry]
            
        # print routing table with new lifetimes after aging
        if conf['verbose'] is True:
          self.__print_routing_table()
      # print an error, if it is earlier than at the last route aging
      elif current_time < self.route_aging_timestamp:
        if conf['quiet'] is False:
          logfile.log_print("Warning: time shift backwards, lifetimes keep the same")
      
    # remember time in seconds since Epoch for the next aging run
    self.route_aging_timestamp = current_time
      
  def __learn_route(self, source_call, source_ssid, ip_port):
    # learn route only if source_call is not empty
    ip, port = ip_port
    if source_call is not None:
      # inform the interested user about the learned route
      if conf['verbose'] is True or conf['debug'] >= 7:
        logfile.log_print("Learning route %s-%i --> %s:%i " % \
                       (source_call, source_ssid, ip, port))
        self.__print_routing_table()
      # if route is already in routing table
      if (source_call, source_ssid) in self.routing_table:
        # dynamically update the route (IP and port)
        self.routing_table[(source_call, source_ssid)]['ip']   = ip
        self.routing_table[(source_call, source_ssid)]['port'] = port
        # restart lifetime counter
        self.routing_table[(source_call, source_ssid)]['lifetime'] = \
          conf['lifetime']
      # if route is not in the routing table
      else:
        # add new routes only if current route table is not too large
        if len(self.routing_table) < MAXIMUM_NUMBER_OF_ROUTES:
          # create a new route for the given ax25 source callsign
          self.routing_table[(source_call, source_ssid)] = {
            'conf_host' : None,               # no configured hostname (dyn.)
            'conf_port' : 0,                  # no configured port     (dyn.)
            'ip'        : ip,                 # learn IP address dynamically
            'port'      : port,               # learn port number dynamically
            'proto'     : 'udp',              # protocol is always UDP (yet)
            'lifetime'  : conf['lifetime'], # restart with default lifetime
          }
        else:
          if conf['quiet'] is False:
            logfile.log_print("Route table full! Increase MAXIMUM_NUMBER_OF_ROUTES")

  def __print_routing_table(self):
    """prints the routing table"""
    if conf['verbose'] is True:
      logfile.log_print(NL+"--- Routing Table ---"+NL+NL)
      logfile.log_print("%-10s%30s %21s%7s%-11s" % \
                     ("Callsign", \
                      "Configured Route", \
                      "Dynamic Route", \
                      "", \
                      "Lifetime")+NL)
      for (callsign,ssid),route in self.routing_table.items():
        # print and log route
        logfile.log_print("%6s-%-2i:%30s:%-5i %15s:%-5i %02i:%02i:%02i"%\
              ( \
                callsign, \
                ssid, \
                route['conf_host'], \
                route['conf_port'], \
                route['ip'], \
                route['port'], \
                route['lifetime']        / 3600, \
                route['lifetime'] % 3600 / 60, \
                route['lifetime'] % 60, \
              )+NL)
      logfile.log_print(NL)

  def __route_packet(self, ip_source_address, packet):
    """
    Packet routing and learning function
    * analyse packet
    * learn route when appropriate packet type occurs
    * print packet source call, destination call, control byte and pollflag
    * send packet to the appropriate recipient
    """

    # decode the frame and return the information in a dictionary
    # for documentation of the returned data structure, see
    # module l2.py and search for decode_frame()
    try:
      frame_info = l2.decode_frame(packet, conf['debug'])
    except l2.InvalidFrameException as error_message:
      if conf['quiet'] == False:
        logfile.log_print("Packet decoding error (contents of packet logged)")
        logfile.log(debug.dump_string(packet))
        # print exception and log traceback
        print(error_message)
        try:
          traceback.print_exc(file=logfile.logfile)
        except: pass
      return

    # Print Monitor Line
    if conf['debug'] >= 7:
      # From
      monitor  = "fm "
      monitor += frame_info['from_id']['callsign']
      monitor += "-"
      monitor += "%i" % (frame_info['from_id']['ssid'])
      # To
      monitor += " to "
      monitor += frame_info['to_id']['callsign']
      monitor += "-"
      monitor += "%i" % (frame_info['to_id']['ssid'])
      # via
      if len(frame_info['via_list']) > 0:
        monitor += " via"
        # print repeater list
        for via_index in range(len(frame_info['via_list'])):
          monitor += " %s-%i" % (frame_info['via_list'][via_index]['callsign'],
                                 frame_info['via_list'][via_index]['ssid'])
          # add a * to the current via repeater
          if via_index == frame_info['via_list_sender_index']:
            monitor += "*"
      # ctl
      monitor += " ctl "
      monitor += frame_info['frame_type']
      # poll bit
      if frame_info['poll_flag'] == True: monitor += "+"
      else:                               monitor += "-"
      # pid
      if 'protocol_id' in frame_info:
        monitor += " pid %02X" % (frame_info['protocol_id'])
      # protocol
      if 'protocol' in frame_info:
        monitor += " (%s)" % (frame_info['protocol'])
      # Sender
      monitor += " ["
      monitor += frame_info['sender_id']['callsign']
      monitor += "-"
      monitor += "%i" % (frame_info['sender_id']['ssid'])
      # Recipient
      monitor += " -> "
      monitor += frame_info['recipient_id']['callsign']
      monitor += "-"
      monitor += "%i" % (frame_info['recipient_id']['ssid'])
      monitor += "]"
      logfile.log_print(monitor+NL)

    # learn route to sender of packet
    self.__learn_route(frame_info['sender_id']['callsign'],
                       frame_info['sender_id']['ssid'],
                       ip_source_address)

    # routing: find recipient IP:port for a destcall:ssid from routing table
    ip_destination_address = None

    # try to find a routing entry for the destination callsign and ssid
    if (frame_info['recipient_id']['callsign'],
          frame_info['recipient_id']['ssid']) in self.routing_table:
      ip_destination_address = (
        self.routing_table[
          (frame_info['recipient_id']['callsign'],
           frame_info['recipient_id']['ssid'])
        ]['ip'],
        self.routing_table[
          (frame_info['recipient_id']['callsign'],
           frame_info['recipient_id']['ssid'])
        ]['port'],
      )
    # if no route was found -> print error message
    elif conf['quiet'] is False:
      logfile.log_print("No route to %s-%i" % \
                      (frame_info['recipient_id']['callsign'], \
                       frame_info['recipient_id']['ssid'])+NL)
    
    # if packet could be routed -> forward original packet to the recipient
    if ip_destination_address is not None:
      # split ip_destination_address into IP and port
      destination_ip, destination_port = ip_destination_address
      # prevent direct loops and send forward packets only if the routed
      # recipient is different from the sender where the packet came from!
      if ip_destination_address != ip_source_address:
        # try to send packet
        try:
          if conf['debug'] >= 3:
            logfile.log_print("Sending UDP packet for %s-%i to %s:%i" % \
                            (frame_info['recipient_id']['callsign'],
                             frame_info['recipient_id']['ssid'],
                             destination_ip,
                             destination_port)+NL)
          self.udp_socket.sendto(packet, ip_destination_address)
        except:
          if conf['quiet'] is False:
            logfile.log_print("Could not send UDP packet for %s-%i to %s:%i" % \
                            (frame_info['recipient_id']['callsign'],
                             frame_info['recipient_id']['ssid'],
                             destination_ip,
                             destination_port)+NL)
      # Direct loop detected! (route recipient is also sender of udp packet)
      elif conf['quiet'] is False:
        logfile.log_print("FATAL: Route for %s-%i is looped back to %s:%i" % \
                        (frame_info['recipient_id']['callsign'],
                         frame_info['recipient_id']['ssid'],
                         destination_ip,
                         destination_port)+NL)

def load_configuration():
  """
  evaluate command line options and arguments and
  load router configuration from config.py
  """
  # evaluate command line arguments
  try:
    # short options needing an argument are followed by a colon
    cmdline_opts, cmdline_args = \
      getopt.getopt( sys.argv[1:], \
        "d:hl:o:qu:vV",
        [ \
          "debug=", \
          "help", \
          "listen=", \
          "logfile=", \
          "quiet", \
          "udp_port=", \
          "verbose", \
          "version", \
        ]
      )
  except getopt.GetoptError as error_message:
    print("GetOpt Error:", end=' ')
    print(error_message)
    show_usage()
    sys.exit(1)

  # load verbose value from config file
  try:
    if config.verbose:
      conf['verbose'] = True
  except: pass

  # load debug value from config file
  try:
    conf['debug'] = int(config.debug)
  except: pass

  # evaluate command line options
  for option, argument in cmdline_opts:

    # help
    if option in ("-h", "--help"):
      show_usage()
      sys.exit()

    # version
    if option in ("-V", "--version"):
      print(__version__)
      sys.exit(0)

    # be verbose
    if option in ("-v", "--verbose"):
      conf['verbose'] = True

    # set debug level
    if option in ("-d", "--debug"):
      try:
        conf['debug'] = int(argument)
        # raise Exception if debug level is out of range 0..9
        if conf['debug'] not in list(range(0,10)): raise Exception
      except:
        print("option debug: illegal debug level")
        show_usage()
        sys.exit(1)

    # be quiet (overrides verbose and debug)
    if option in ("-q", "--quiet"):
      conf['quiet']   = True
      conf['verbose'] = False
      conf['debug']   = 0

  # load route lifetime from config file
  try:
    conf['lifetime'] = config.lifetime
  except: pass

  # load bind IP from config file
  try:
    conf['listen'] = config.listen
  except: pass

  # load logfile path and filename from config file
  try:
    conf['logfile'] = config.logfile
  except: pass

  # load listen udp port from config file
  try:
    conf['udp_port'] = config.udp_port
  except: pass
  
  # evaluate command line options which can override the config file
  for option, argument in cmdline_opts:

    # bind to the interface with a specific IP
    if option in ("-l", "--listen"):
      conf['listen'] = argument

    # logfile name
    if option in ("-o", "--logfile"):
      conf['logfile'] = argument

    # listen for incoming UDP packets on a specified port
    if option in ("-u", "--udp_port"):
      try:
        conf['udp_port'] = int(argument)
      except:
        print("option udp_port: illegal port number")
        show_usage()
        sys.exit(1)

def show_configuration():
  """
  print and log configuration items to stdout and the logfile
  """
  # inform about configured options
  if conf['quiet'] is False:
    # collect option list in string "opts"
    opts = NL + "--- Options ---" + NL
    opts+= NL
    opts+= "debug    = %i" % (conf['debug']) + NL
    opts+= "lifetime = %i" % (conf['lifetime']) + NL
    if conf['listen']!="0.0.0.0":
      opts += "listen   = %s" % (conf['listen']) + NL
    else:
      opts += "listen   = all network interfaces" + NL
    opts+= "udp_port = %i" % (conf['udp_port']) + NL
    opts+= "verbose  = %s" % (conf['verbose']) + NL
    opts+= NL
    opts+= "--- Internal Options ---" + NL + NL
    opts+= "workdir  = %s" % (conf['workdir']) + NL
    opts+= NL
    # write options to stdout and logfile
    logfile.log_print(opts)

def open_logfile():
  """
  open logfile for writing output messages
  """
  # print a message that we try to open the logfile
  if conf['quiet'] is False:
    print("Open logfile %s:" % (conf['logfile']), end=' ')
  # try to open logfile in same directory as the router executable
  try:
    logfile.open_logfile(conf['workdir'], conf['logfile'])
    if conf['quiet'] is False:
      print("OK")
  except Exception as error_message:
    if conf['quiet'] is False:
      print("FAILED")
      print(error_message)
    sys.exit(1)

def main():
  # determine absolute directory where the router is situated, there we work
  conf['workdir'] = os.path.abspath(os.path.dirname(sys.argv[0]))

  # load configuration and evaluate command line arguments
  load_configuration()

  # open logfile for writing and store file handle in variable
  # "logfile.logfile", logfile must be opened early for logging later errors
  open_logfile()

  # print and log important configuration items
  show_configuration()

  # create router object and load configured routes
  router = UDP_Router((conf['listen'], conf['udp_port']))
  try:
    # run server loop
    router.serve_forever()
  # handle Strg-c
  except KeyboardInterrupt:
    # prevent a traceback
    logfile.log_print("Interrupted with Strg-C" + NL)
    pass
  # handle errors
  except:
    # cleanly shut down on error
    try:
      # log the error traceback
      traceback.print_exc(file=logfile.logfile)
    except: pass
    raise

  # always do the following: try to close server socket and logfile
  try:
    router.shutdown()
  except: pass

if __name__ == "__main__":
  # run main() routine
  main()
