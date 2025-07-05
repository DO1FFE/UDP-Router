#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
"""
AX25 over UDP router - Layer2 module

Copyright (c) 2005 by DAP900, Daniel Parthey

E-Mail  : pada@hrz.tu-chemnitz.de
Homepage: http://nd0chz.webhop.org/

AX25 Protocol Specification:
http://www.tapr.org/tapr/html/ax25.html

---------------------------------------------------------------------------
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
---------------------------------------------------------------------------
"""
###############################################################################
# L2 lengths of frame content
###############################################################################
L2CALEN   = 6                   # length of callsign in layer2
L2SSIDLEN = 1                   # length of SSID in layer2
L2IDLEN   = L2CALEN + L2SSIDLEN # callsign + 1 byte SSID = length of ID
L2INUM    = 2                   # number of IDs in From/To field
L2VNUM    = 8                   # number of IDs in Via field
L2ILEN    = L2INUM * L2IDLEN    # length of From/To field
L2VLEN    = L2VNUM * L2IDLEN    # length of Via field
L2AFLEN   = L2ILEN + L2VLEN     # length of L2 address field (AF)
L2HLEN    = L2AFLEN + 2         # length of L2 header (H)
                                #
                                # (2+8) * 7 = 70 bytes address
                                #           +  1 byte control
                                #           +  1 Byte PID
                                #           ----
                                #            72 bytes frame header
L2MILEN   = 256                 # maximum length of info field (load)
L2MFLEN   = L2MILEN + L2HLEN    # maximum L2 frame length
                                #
                                #      72 bytes header
                                #   + 256 bytes info
                                #   -----
                                #     328 bytes maximum frame length
                                #
###############################################################################
# layer2 control frame types (result after correct masking, see AX25 spec.)
###############################################################################
                                   #                       Command/   Poll/ (1)
                                   #   type       group    Response   Final (0)
# I-Frames (Information)           # ----------------------------------------
L2CI     = 0x00                    #      I         I         C         P
# S-Frames (Supervisory)           #
L2CRR    = 0x01 # Recv Ready       #     RR         S        C/R       P/F
L2CRNR   = 0x05 # Recv Not Ready   #    RNR         S        C/R       P/F
L2CREJ   = 0x09 # REJect           #    REJ         S        C/R       P/F
L2CSREJ  = 0x0D # Selective REJect #   SREJ         S        C/R       P/F
# U-Frames (Unnumbered)            #
L2CSABME = 0x6F # Connect Req EAX  #   SABM (EAX)   U         C         P
L2CSABM  = 0x2F # Connect Req      #   SABM         U         C         P
L2CDISC  = 0x43 # Disconnect Req.  #   DISC         U         C         P
L2CDM    = 0x0F # Disconnect Mode  #     DM         U         R         F
L2CUA    = 0x63 # Unnumbered Ack   #     UA         U         R         F
L2CFRMR  = 0x87 # Frame Reject     #   FRMR         U         R         F
L2CUI    = 0x03 # Unnumbered Info  #     UI         U        C/R       P/F
L2CXID   = 0xAF # Exchange Ident.  #    XID         U        C/R       P/F
L2CTEST  = 0xE3 # Test Frame       #   TEST         U        C/R       P/F
                                   #
###############################################################################
# layer2 control special bits
###############################################################################
# Address-ID Masks
L2CH     = 0x80                 # "has been repeated" (in via address ssid)
L2CEOA   = 0x01                 # end of address (last id in address field?)
# Control Byte Masks
L2CPF    = 0x10                 # poll/final bit

###############################################################################
# l2 packet contents
###############################################################################
#
# TOCALL
# IDBYTE
#
# FMCALL
# IDBYTE
#
# VIACALL
# IDBYTE
#
# ... up to 8 VIACALL's ...
#
# FMCALL/TOCALL/VIACALL Bytes
# bits:  87654321
# data:  CCCCCCCE
# legend:
#   C = Callsign Character as ASCII (0..127)
#   E = "End of address" bit -> this callsign is the last one in address field
#
# IDBYTE after callsign
# bits:  87654321
# data:  H..SSSSE
# legend:
#   S = SSID bits
#   H = "has been repeated" control bit (mask L2CH)
#   E = "End of address" bit -> this callsign is the last one in address field
# 
###############################################################################
# Frame Check Sequence (FCS) constants (CRC calculation)
###############################################################################
# FCS lookup table with 256 unsigned short integers of 16 Bit
# (taken from RFC 1171 - Appendix B)
FCS_LOOKUP_TABLE = (
  0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
  0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
  0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
  0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
  0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
  0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
  0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
  0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
  0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
  0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
  0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
  0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
  0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
  0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
  0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
  0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
  0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
  0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
  0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
  0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
  0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
  0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
  0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
  0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
  0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
  0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
  0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
  0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
  0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
  0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
  0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
  0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78)
# Initial FCS value
FCS_INIT_VALUE = 0xffff
# Good final FCS value
FCS_GOOD_FINAL = 0xf0b8
###############################################################################

# Import axrouter modules
import debug
import logfile
from const import *

# Exceptions
class InvalidFrameException (Exception):
  """Raised when an invalid frame is found"""
  pass

class FrameTooShortException (InvalidFrameException):
  """Raised when the frame is too short"""
  pass

class FrameDecodingException (InvalidFrameException):
  """Raised when there are problems with the decoding"""
  pass

class FrameInvalidFCSException (InvalidFrameException):
  """Raised when the frame check sequence (CRC) test fails"""
  pass

def extract_callsign(address):
  """
  Decode callsign from string with encoded callsign and id.
  If the address string was too short to extract a callsign and SSID
  raise a FrameDecodingException.
  """
  # empty callsign at the beginning
  callsign = ""
  # if string is too short for complete callsign and id -> return no callsign
  if (len(address) < L2IDLEN):
    raise FrameDecodingException("address id too short")
  # decode all bytes of the address until maximum callsign length is
  # reached or an "end of address" flag is found in the least significant bit
  for position in range(L2CALEN): # 0..L2CALEN-1
    # decode character (right shift character and cut off most-left, 8th bit)
    char = chr((ord(address[position]) >> 1) & 0x7F)
    # append the character to the decoded callsign string (if it is no space)
    if char != " ":
      callsign += chr((ord(address[position]) >> 1) & 0x7F)
  # return the complete callsign (without SSID)
  return callsign

def extract_ssid(address):
  """
  extract SSID from address and return it as an integer from 0 to 15
  or raise a FrameDecodingException
  """
  # SSID is the bits 2 to 5 of the last callsign byte
  # 87654321
  # ...SSSS.
  try:
    # select last, 7th byte (L2CALEN) of address (0..6) (6 byte call + 1 ssid)
    # a single right shift of SSID byte and bitmask 00001111 extract the SSID
    return (ord(address[L2CALEN]) >> 1) & 0x0F;
  except:
    # SSID byte could not be read?
    raise FrameDecodingException("extracting the ssid from address failed")

def get_sender_id(packet):
  """
  returns the address (and index in the via list) of the real sending station

  return dictionary
  {
    'address': the part from the address field which contains the
               real sender callsign (From-Field or current repeater)
               and its ID (in a still encoded form)
    'via_index': index in the list of via callsigns which is the currently
                 sending repeater (the one which is followed by a *)
                 or None if no Via repeater is the sender
  }
                  
  Expects that the packet is valid and long enough to contain Dest/Src field.
  """
  # remember From-address
  source_address = packet[1*L2IDLEN:2*L2IDLEN]
  # if there are no via repeaters, immediately return destination callsign
  # and "no via repeater"
  if ord(packet[2*L2IDLEN-1]) & L2CEOA != 0:
    return {'address': source_address, 'via_index': None}
  # cut off To and From address and go to the first Via repeater (index 0)
  current_repeater = packet[2*L2IDLEN:]
  via_index        = 0
  # remember the previous via call (fork principle)
  previous_repeater = None
  # while via address contains a complete callsign ID
  # search all "Via" repeater addresses (terminated with L2CEOA-in-SSID-Byte)
  # for the last repeated address (this repeater* becomes the source call)
  while (len(current_repeater) >= L2IDLEN):
    # if current repeater is repeated (L2CH)
    if (ord(current_repeater[L2IDLEN-1]) & L2CH) != 0:
      # if this is the last repeater address (EOA - end of address is set)
      if ord(current_repeater[L2IDLEN-1]) & L2CEOA != 0:
        # return current repeater callsign with ID and its index
        return {'address': current_repeater[:L2IDLEN], 'via_index': via_index}
      # else if this is NOT the last repeater address (EOA not set)
      else:
        # remember current repeater as "previous repeater"
        previous_repeater = current_repeater
        # go on to next repeater (cut off first repeater ID and increase index)
        current_repeater  = current_repeater[L2IDLEN:]
        via_index        += 1
    # else if current is not repeated (not L2CH):
    else:
      # if repeater is the first one (no previous repeater) then break
      # and use the From-Field as source callsign
      if previous_repeater is None: break
      # if there is a repeater* before the current viacall, it is the source
      return {'address': previous_repeater, 'via_index': via_index-1}
  # return the From-address with its ID
  return {'address': source_address, 'via_index': None}

def get_recipient_id(packet):
  """
  Return the part from the address field which contains the
  real recipient callsign and its ID (in a still encoded form).
  Expects that the packet is valid and long enough to contain Dest/Src field.
  """
  # remember To-address
  destination_address = packet[:L2IDLEN]
  # if there are no via repeaters, immediately return destination callsign
  if ord(packet[2*L2IDLEN-1]) & L2CEOA != 0: return destination_address
  # cut off To and From address
  current_repeater = packet[2*L2IDLEN:]
  # search all "Via" repeater addresses (terminated with L2CEOA-in-SSID-Byte)
  # for the first non-repeated address (this repeater is the destination call)
  while (len(current_repeater) >= L2IDLEN):
    # if current repeater address is not repeated,
    # we have found the destination callsign
    if (ord(current_repeater[L2IDLEN-1]) & L2CH) == 0:
      # return repeater callsign with ID
      return current_repeater
    # current repeater is repeated
    else:
      # if we encounter the "last" address (EOA flag in SSID byte) break
      if ord(current_repeater[L2IDLEN-1]) & L2CEOA != 0: break
      # if current repeater is repeated, we have to continue our search at
      # the next repeater -> cut off one repeater ID at the beginning)
      current_repeater = current_repeater[L2IDLEN:]
  # no valid repeater found -> return To-field as destination callsign
  return destination_address

def get_next_address(packet, ptr):
  """
  Return the next address (callsign with ID) starting from position ptr
  in packet and if this is the last address (if there are no more addresses)
  return dictionary
  {
    'address': string(7) encoded callsign and SSID
    'last':    bool if this is the last callsign
    'ptr':     position in string after the callsign and ssid (new pointer)
  }
  or None if no more addresses were found
  """
  # check if packet is long enouth, else return None
  if len(packet[ptr:]) >= L2IDLEN:
    # declare result dictionary
    result = {}
    # check if this is the last address (EOA flag is set?)
    if ord(packet[ptr+L2IDLEN-1]) & L2CEOA != 0:
      result['last'] = True
    else:
      result['last'] = False
    # get the address and id
    result['address'] = packet[ptr:ptr+L2IDLEN]
    # return the new position pointer (ptr)
    result['ptr'] = ptr+L2IDLEN
    # return the result dictionary
    return result
  # packet content is not long enough to get another address
  else:
    return None

def int2str_reversed(integer):
  """
  convert an integer to a byte-reversed-string (little endian)
  for example 0x2F4BE317 becomes "\x17\xE3\x4B\x2F"
  """
  string = ""
  while integer > 0:
    # add least significant byte to string
    string += chr(integer & 0xFF);
    # remove 8 bits (one byte) from integer
    integer = integer >> 8
  return string

def fcs16(fcs, data):
  """
  Calculate a new fcs given the current fcs and the new data.
  The algorithm has been adapted from RFC 1171 (PPP) - Appendix B (FCS)
  """
  rest = data
  while (len(rest) > 0):
    # calculate fcs for one byte
    fcs = (fcs >> 8) ^ FCS_LOOKUP_TABLE[(fcs ^ ord(rest[0])) & 0xff];
    # cut off the byte which is done now
    rest = rest[1:]
  return fcs
  
def crc_compute(data):
   """
   Return the computed CRC16 for data
   """
   return fcs16(FCS_INIT_VALUE, data) ^ 0xffff;

def crc_ok(data):
  """
  Check if the CRC16 of data is correct
  Return True if it is correct, otherwise False
  """
  fcs = fcs16(FCS_INIT_VALUE, data)
  if fcs == FCS_GOOD_FINAL:
    return True
  else:
    return False
  
def decode_frame(packet, debugvalue):
  """
  Decodes the contents of an AX25 Layer2 Frame and return the following
  information in a python dictionary.

  'sender_id':
    Sender callsign+ssid who really sends the packet (can be a repeater)
  'recipient_id':
    Recipient callsign+ssid who really receives the packet (can be a repeater)
  'to_id':
    From callsign+ssid (first address from the packet, length is L2IDLEN)
  'from_id':
    From callsign+ssid (second address from the packet, length is L2IDLEN)
  'via_list':
    List of Via callsign+ssid (length is L2IDLEN)
  'via_list_sender_index':
    The index for the via_ids list, which via address is the sender with a *
    (only available when via_id's is not empty)
  'control_byte':
    One byte which identifies the frame type and state (always available)
  'poll_flag':
    Bit which tells if the P/F Flag is set or not (True/False)
  'frame_format':
    Format group of the frame (packet structure)
    Can be "U" (Unnumbered), "I" (Information) or "S" (Supervisory packet)
  'frame_type':
    Frame type as a string (like on the monitor)
  'recv_seqnr':
    Sequence number for reception (number of the next expected frame mod 8)
  'send_seqnr':
    Sequence number for sending (number of the currently sent frame mod 8)
  'protocol_id':
    One byte which identifies the protocol
    Only in I and UI frames, check it with has_key() 
  'protocol':
    String which describes the protocol
    Only in I and UI frames, check it with has_key() 
  'data':
    Information (data content) of the packet (only ni I and UI frames)
    Only in I and UI frames, check it with has_key() 

  On invalid packets, an InvalidFrameException is raised and
  the return value is undefined.
  """

  # check if packet is too short, at least: Dest (7) + Src (7) + Control (1)
  if len(packet) < 2*L2IDLEN+1:
    raise FrameTooShortException("frame too short")

  # CRC check of packet
  if not crc_ok(packet):
    raise FrameInvalidFCSException("frame check sequence error")

  # dump packet, if debug mode is "full"
  if debugvalue >= 9:
    logfile.log_print(NL + "--- Dump of received AX25 Packet BEGIN ---" + NL)
    logfile.log_print(debug.dump_string(packet))
    logfile.log_print("--- Dump of received AX25 Packet END ---" + NL)

  # prepare frame_info dictionary which will be returned as the result
  frame_info = {}
  # Frame-Type is unknown by default (if it cannot be detected)
  frame_info['frame_type'] = "UNKN"

  if debugvalue >= 8:
    logfile.log_print(NL + "--- Packet information BEGIN ---")

  # get To-field (at the beginning of the packet)
  address_dict = get_next_address(packet, 0)
  if not address_dict:
    raise FrameDecodingException("failed to read the TO field")
  # decode callsign and ssid
  frame_info['to_id'] = {
    'callsign': extract_callsign(address_dict['address']),
    'ssid':     extract_ssid    (address_dict['address'])
  }
  # jump behind the "To" field (read the new pointer from the previous result)
  ptr = address_dict['ptr']
  # get From-field (directly behind TO field)
  address_dict = get_next_address(packet, ptr)
  if not address_dict:
    raise FrameDecodingException("failed to read the FROM field")
  # decode callsign and ssid
  frame_info['from_id'] = {
    'callsign': extract_callsign(address_dict['address']),
    'ssid':     extract_ssid    (address_dict['address'])
  }
  # get all VIA fields as a list
  frame_info['via_list'] = []
  # collect via's as long as the last callsign has not been seen
  while address_dict['last'] == False:
    # go to the next repeater
    ptr = address_dict['ptr']
    # get this via repeater address string if possible
    address_dict = get_next_address(packet, ptr)
    # break when no more repeaters were found
    if address_dict is None: break
    # if a repeater was found, append its ID (callsign+ssid) to the via_list
    frame_info['via_list'].append(
      {'callsign': extract_callsign(address_dict['address']),
       'ssid':     extract_ssid    (address_dict['address'])}
    )

  # get the id of the real sender (only if From/To/Via extracted fine)
  sender_address_and_index = get_sender_id(packet)
  frame_info['sender_id'] = {
    'callsign': extract_callsign(sender_address_and_index['address']),
    'ssid':     extract_ssid    (sender_address_and_index['address'])
  }
  # get the index of the real sender in the via list (the repeater with a *)
  frame_info['via_list_sender_index'] = sender_address_and_index['via_index']

  # get the id of the real recipient (only if From/To/Via extracted fine)
  recipient_address = get_recipient_id(packet)
  frame_info['recipient_id'] = {
    'callsign': extract_callsign(recipient_address),
    'ssid':     extract_ssid    (recipient_address)
  }

  # print To and From field in debug mode
  if debugvalue >= 8:
    logfile.log("From         : %s-%i" % \
                 (frame_info['from_id']['callsign'], \
                  frame_info['from_id']['ssid']) + NL)
    logfile.log("To           : %s-%i" % \
                 (frame_info['to_id']['callsign'], \
                  frame_info['to_id']['ssid']) + NL)
    logfile.log("Via          : %s" % \
                 (frame_info['via_list']) + NL)
    logfile.log("Via*-Index   : %s" % \
                 (frame_info['via_list_sender_index']) + NL)
    logfile.log("Sender       : %s-%i" % \
                 (frame_info['sender_id']['callsign'], \
                  frame_info['sender_id']['ssid']) + NL)
    logfile.log("Recipient    : %s-%i" % \
                 (frame_info['recipient_id']['callsign'], \
                 frame_info['recipient_id']['ssid']) + NL)

  # go to control byte, after the last callsign found by get_next_address()
  ptr = address_dict['ptr']
  # try to read the control byte, and go on to the next character
  # (the PID position for later usage with I and UI frames only)
  try:
    control_byte = packet[ptr]
    ptr = ptr + 1
  except:
    raise FrameDecodingException("could not read control byte")
  # convert control byte to integer
  frame_info['control_byte'] = ord(control_byte)
  if debugvalue >= 8:
    logfile.log("Control Byte : %02X" % (frame_info['control_byte']) + NL)

  # Detect frame-format (AX25 spec 2.2, paper page 16, PDF page 26)
  # Bits     87654321
  # I Frame: ???????0 -> Information Frame if last bit is 0
  if frame_info['control_byte'] & 0x01 == L2CI:
    frame_info['frame_format'] = 'I'
  # Bits     87654321
  # S Frame: ??????01 -> Supervisory Frame if last two bits are 01
  elif frame_info['control_byte'] & 0x03 == 0x01:
    frame_info['frame_format'] = 'S'
  # Bits     87654321
  # U Frame: ??????11 -> Unnumbered) if last two bits are 11
  elif frame_info['control_byte'] & 0x03 == 0x03:
    frame_info['frame_format'] = 'U' # Unnumbered Information
  # This should not happen
  else:
    raise FrameDecodingException("unknown frame format")
  if debugvalue >= 8:
    logfile.log("Frame Format : %s" % (frame_info['frame_format']) + NL)

  # Distinguish frame types

  # More information about Information Frame
  if frame_info['frame_format'] == "I":
    #
    # Information frames contain an information field
    #
    # sequence number for sending N(S)
    frame_info['send_seqnr'] = frame_info['control_byte']>>1 & 0x07
    if debugvalue >= 8:
      logfile.log("Send Sequence: %s" % (frame_info['send_seqnr']) + NL)
    # sequence number for next expected packet N(R)
    frame_info['recv_seqnr'] = frame_info['control_byte']>>5 & 0x07
    if debugvalue >= 8:
      logfile.log("Recv Sequence: %s" % (frame_info['recv_seqnr']) + NL)
    # Type of I Frames is always "I"
    frame_info['frame_type'] = "I"
    # Numbered Info-Frames contain a PID (and an information field)
    # Set protocol_id to None to _create_ key -> has_key('protocol_id')==True
    frame_info['protocol_id'] = None

  # More Information about Supervisory Frame
  elif frame_info['frame_format'] == 'S':
    # S-Frames do not have an information field
    # sequence number for next expected packet N(R)
    frame_info['recv_seqnr'] = frame_info['control_byte']>>5 & 0x07
    # determine exact S frame type (last two bits are always "01")
    s_frame_function = frame_info['control_byte'] & 0x0F
    # Type of S Frames depends on the two s_frame_mode bits (?): ****??01
    if   s_frame_function == L2CRR:   frame_info['frame_type'] = "RR"
    elif s_frame_function == L2CRNR:  frame_info['frame_type'] = "RNR"
    elif s_frame_function == L2CREJ:  frame_info['frame_type'] = "REJ"
    elif s_frame_function == L2CSREJ: frame_info['frame_type'] = "SREJ"
    else:
      # Should not happen
      raise FrameDecodingException("unknown function for S frame")

  # More Information about Unnumbered Frame
  elif frame_info['frame_format'] == 'U':
    # There are two types of U frames:
    # (1) NO pid + NO information field
    # (2)  a pid + information field
    #
    # U frame type can be determined with the following bitmask:: 11101111
    # where the last two bits are always "11" (but are included in the mask)
    u_frame_type = frame_info['control_byte'] & 0xEF
    if   u_frame_type == L2CSABME: frame_info['frame_type'] = "SABME"
    # information fields are not allowed in SABM frames -> no PID/no info
    elif u_frame_type == L2CSABM:  frame_info['frame_type'] = "SABM"
    elif u_frame_type == L2CDISC:  frame_info['frame_type'] = "DISC"
    elif u_frame_type == L2CDM:    frame_info['frame_type'] = "DM"
    elif u_frame_type == L2CUA:    frame_info['frame_type'] = "UA"
    elif u_frame_type == L2CFRMR:  frame_info['frame_type'] = "FRMR"
    elif u_frame_type == L2CUI:
      frame_info['frame_type'] = "UI"
      # Unnumbered Information Frames contain a PID (and an information field)
      # Set protocol_id to None to _create_ key -> has_key('protocol_id')==True
      frame_info['protocol_id'] = None
      
    elif u_frame_type == L2CXID:   frame_info['frame_type'] = "XID"
    elif u_frame_type == L2CTEST:  frame_info['frame_type'] = "TEST"
    else:                          frame_info['frame_type'] = "U"

  # More Information which can be found in every frame
  # poll flag: Poll = 1 / Final = 0
  frame_info['poll_flag']  = (frame_info['control_byte'] & L2CPF != 0)
  if debugvalue >= 8:
    logfile.log("Poll Flag    : %s" % (frame_info['poll_flag']) + NL)
    logfile.log("Frame Type   : %s" % (frame_info['frame_type']) + NL)

  # If we have a frame with a PID (I or UI information frame)
  if ('protocol_id' in frame_info) == True:
    # Try to read the protocol id (PID) byte only for frames which have a PID
    # and go to the next character (the information field which contains data)
    try:
      pid_byte = packet[ptr]
      ptr = ptr + 1
    except:
      raise FrameDecodingException("could not read byte with protocol id (PID)")

    # convert pid byte to integer
    frame_info['protocol_id'] = ord(pid_byte)

    # convert pid's to strings
    if frame_info['protocol_id'] & 0x30 in [0x10, 0x20]:
      frame_info['protocol'] = "Layer3 implemented"
    elif frame_info['protocol_id'] == 0x01:
      frame_info['protocol'] = 'ISO 8208/CCITT X.25 PLP'
    elif frame_info['protocol_id'] == 0x06:
      frame_info['protocol'] = 'Compressed TCP/IP'
    elif frame_info['protocol_id'] == 0x07:
      frame_info['protocol'] = 'Uncompressed TCP/IP'
    elif frame_info['protocol_id'] == 0x08:
      frame_info['protocol'] = 'Segmentation Fragment'
    elif frame_info['protocol_id'] == 0xC3:
      frame_info['protocol'] = 'TEXNET Datagram Protocol'
    elif frame_info['protocol_id'] == 0xC4:
      frame_info['protocol'] = 'Link Quality Protocol'
    elif frame_info['protocol_id'] == 0xCA:
      frame_info['protocol'] = 'Appletalk'
    elif frame_info['protocol_id'] == 0xCB:
      frame_info['protocol'] = 'Appletalk ARP'
    elif frame_info['protocol_id'] == 0xCC:
      frame_info['protocol'] = 'ARPA Internet Protocol'
    elif frame_info['protocol_id'] == 0xCD:
      frame_info['protocol'] = 'ARPA Address Resolution'
    elif frame_info['protocol_id'] == 0xCE:
      frame_info['protocol'] = 'Flexnet'
    elif frame_info['protocol_id'] == 0xCF:
      frame_info['protocol'] = 'NET/ROM'
    elif frame_info['protocol_id'] == 0xF0:
      frame_info['protocol'] = 'No Layer3'
    else:
      frame_info['protocol'] = "Unknown Protocol"
    
    # print PID
    if debugvalue >= 8:
      logfile.log("Protocol ID  : %02X" % (frame_info['protocol_id']))

  # print complete frame info dictionary in high debug mode
  if debugvalue >= 9:
    logfile.log("Frame Info   : %s" % (frame_info))

  # print end banner in lower debug mode
  if debugvalue >= 8:
    logfile.log("--- Packet information END ---" + NL + NL)

  # return dictionary with a lot of information about this packet
  return frame_info
