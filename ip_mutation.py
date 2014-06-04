#
# Copyright 2013 Liu Weiyu
#

"""
A switch which realizes ip mutation to protect the internal node

For each switch:
1) When get a DNS query for internal node from any external node, response with a random virtual ip address.
2) When get an arp request for internal node from any external node, change the destination ip to the real ip of internal node and forward the request to the internal node.
3) When get an arp reply from internal node, change the source real ip into the virtual ip and forward the reply to the related destination external node.
4) When get an icmp request from external node, install an entry into the switch to change the destination ip to real ip of the internal node, set the destination mac address and switch port related to the internal node.
5) When get an icmp reply from internal node, install an entry into the switch to change the srcip into virtual ip of the internal node, set the mac addr and switch port for the destinated external node.
"""

from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.dns import dns
from pox.lib.packet.udp import udp
from pox.lib.packet.icmp import icmp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpidToStr
from pox.lib.recoco import Timer
from pox.lib.revent import *

import pox.openflow.libopenflow_01 as of

import time
import copy

import random

# Timeout for flows
FLOW_IDLE_TIMEOUT = 10

# Timeout for ARP entries
ARP_TIMEOUT = 60 * 2

# Maximum number of packet to buffer on a switch for an unknown IP
MAX_BUFFERED_PER_IP = 5

# Maximum time to hang on to a buffer for an unknown IP in seconds
MAX_BUFFER_TIME = 5

# Real Ip of the internal host
REAL_IP_OF_INTERNAL_HOST = '10.0.0.3'
IP_OF_DNS_SERVER = '10.0.0.10'
MAC_OF_DNS_SERVER = '00:00:00:00:00:01'

class Entry (object):
  """
  We use the port to determine which port to forward traffic out of.
  We use the MAC to answer ARP replies.
  We use the timeout so that if an entry is older than ARP_TIMEOUT, we
   flood the ARP request rather than try to answer it ourselves.
  """
  def __init__ (self, port, mac):
    self.timeout = time.time() + ARP_TIMEOUT
    self.port = port
    self.mac = mac

  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)
	
  def isExpired (self):
    if self.port == of.OFPP_NONE: return False
    return time.time() > self.timeout


def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))


class l3_switch (EventMixin):
  def __init__ (self, fakeways = [], arp_for_unknowns = False):
    # These are "fake gateways" -- we'll answer ARPs for them with MAC
    # of the switch they're connected to.
    self.fakeways = set(fakeways)

    # If this is true and we see a packet for an unknown
    # host, we'll ARP for it.
    self.arp_for_unknowns = arp_for_unknowns

    # (IP,dpid) -> expire_time
    # We use this to keep from spamming ARPs
    self.outstanding_arps = {}

    # (IP,dpid) -> [(expire_time,buffer_id,in_port), ...]
    # These are buffers we've gotten at this datapath for this IP which
    # we can't deliver because we don't know where they go.
    self.lost_buffers = {}

    # For each switch, we map IP addresses to Entries
    self.arpTable = {}

    # This timer handles expiring stuff
    self._expire_timer = Timer(5, self._handle_expiration, recurring=True)

    self.listenTo(core)

    # initialize virtual ip pool
    self.vipList = []
    for i in range(128, 254):
       vip = "10.0.0.%s" % i
       self.vipList.append(vip)

    self.srcip_dstvip_map = {}

  def _handle_expiration (self):
    # Called by a timer so that we can remove old items.
    empty = []
    for k,v in self.lost_buffers.iteritems():
      ip,dpid = k
      expires_at,buffer_id,in_port = v

      for item in list(v):
        if expires_at < time.time():
          # This packet is old.  Tell this switch to drop it.
          v.remove(item)
          po = of.ofp_packet_out(buffer_id = buffer_id, in_port = in_port)
          core.openflow.sendToDPID(dpid, po)
      if len(v) == 0: empty.append(k)

    # Remove empty buffer bins
    for k in empty:
      del self.lost_buffers[k]

  def _send_lost_buffers (self, dpid, ipaddr, macaddr, port):
    """
    We may have "lost" buffers -- packets we got but didn't know
    where to send at the time.  We may know now.  Try and see.
    """
    if (dpid,ipaddr) in self.lost_buffers:
      # Yup!
      bucket = self.lost_buffers[(dpid,ipaddr)]
      del self.lost_buffers[(dpid,ipaddr)]
      log.debug("Sending %i buffered packets to %s from %s"
                % (len(bucket),ipaddr,dpidToStr(dpid)))
      for _,buffer_id,in_port in bucket:
        po = of.ofp_packet_out(buffer_id=buffer_id,in_port=in_port)
        po.actions.append(of.ofp_action_dl_addr.set_dst(macaddr))
        po.actions.append(of.ofp_action_output(port = port))
        core.openflow.sendToDPID(dpid, po)

  def _handle_GoingUpEvent (self, event):
    self.listenTo(core.openflow)
    log.debug("Up...")

  def _handle_PacketIn (self, event):
    dpid = event.connection.dpid

    inport = event.port
    packet = copy.deepcopy(event.parsed)
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    if dpid not in self.arpTable:
      # New switch -- create an empty table
      self.arpTable[dpid] = {}
      for fake in self.fakeways:
        self.arpTable[dpid][IPAddr(fake)] = Entry(of.OFPP_NONE,
         dpid_to_mac(dpid))

    # store the mac, ip info of the DNS SERVER into arpTable
    self.arpTable[dpid][IPAddr(IP_OF_DNS_SERVER)]=Entry(6633, EthAddr(MAC_OF_DNS_SERVER))

    if packet.type == ethernet.LLDP_TYPE:
      # Ignore LLDP packets
      return

    p = packet.find('dns')

    if p is not None and p.parsed:

      # Get dstName of the DNS Query
      dstname = '';
      for question in p.questions:
          dstname = question.name

      log.debug("DNS Query msg from %s: asking ip address for %s", packet.next.srcip, dstname)

      # Learn or update port/MAC info
      if packet.next.srcip in self.arpTable[dpid]:
        if self.arpTable[dpid][packet.next.srcip] != (inport, packet.src):
          log.info("%i %i RE-learned %s", dpid, inport, packet.next.srcip)
      else:
        log.debug("%i %i learned %s", dpid, inport, str(packet.next.srcip))
      self.arpTable[dpid][packet.next.srcip] = Entry(inport, packet.src)

      # generate random virtual ip for internal node
      n = random.randint(128, 254)
      vip = "10.0.0." + str(n)
      #add the srcip and virtual destination ip pair into srcip_dstip_map
      self.srcip_dstvip_map[str(packet.next.srcip)] = vip
      # forming answer
      answer = dns.rr(dstname, 1, 1, 5, len(vip), IPAddr(vip))
      # write dns reply msg
      d = dns()
      d.questions = p.questions
      d.answers.append(answer)
      d.authorities = []
      d.additional =[]

      d.id = p.id
      d.qr = True # dns reply
      d.opcode = 0 # standard
      d.aa = False
      d.tc = False
      d.rd = False
      d.ra = False
      d.z = False
      d.ad = False
      d.cd = False
      d.rcode = 0

      e = ethernet(type=ethernet.IP_TYPE, src=MAC_OF_DNS_SERVER, dst=str(packet.src))
      ip = ipv4(srcip = IPAddr(IP_OF_DNS_SERVER))
      ip.dstip = packet.next.srcip
      ip.protocol = ip.UDP_PROTOCOL
      u = udp()
      u.srcport = dns.SERVER_PORT
      # get srcport from the packet and set it to the udp's dstport
      m = packet.find("udp")
      m.parsed
      u.dstport = m.srcport
      u.payload = d
      ip.payload = u
      e.payload = ip

      msg = of.ofp_packet_out()
      msg.data = e.pack()
      msg.actions.append(of.ofp_action_nw_addr.set_dst(packet.next.srcip))
      msg.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
      msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
      msg.in_port = inport
      event.connection.send(msg)
      log.debug(" DNS reply msg has been sent to %s: %s's ip address is %s" % (str(packet.next.srcip), dstname, vip))

    elif isinstance(packet.next, ipv4):
      log.debug("IPv4 msg: %i %i IP %s => %s", dpid,inport,
                packet.next.srcip,packet.next.dstip)

      # Send any waiting packets...
      self._send_lost_buffers(dpid, packet.next.srcip, packet.src, inport)
      print "Have sent lost buffers"

      # Learn or update port/MAC info
      if packet.next.srcip in self.arpTable[dpid]:
        if self.arpTable[dpid][packet.next.srcip] != (inport, packet.src):
          log.info("%i %i RE-learned %s", dpid,inport,packet.next.srcip)
      else:
        log.debug("%i %i learned %s", dpid,inport,str(packet.next.srcip))
      self.arpTable[dpid][packet.next.srcip] = Entry(inport, packet.src)

      srcaddr = packet.next.srcip
      dstaddr = packet.next.dstip

      if(dstaddr in self.vipList):
         self.srcip_dstvip_map[srcaddr] = dstaddr
         dstaddr = IPAddr(REAL_IP_OF_INTERNAL_HOST)

      if dstaddr in self.arpTable[dpid]:
         # We have info about what port to send it out on...
         prt = self.arpTable[dpid][dstaddr].port
         mac = self.arpTable[dpid][dstaddr].mac

         # Try to forward
         icmpmsg = packet.find("icmp")
         icmpmsg.parsed

         # icmp echo reply from internal host
         if icmpmsg.type == 0 and srcaddr == IPAddr(REAL_IP_OF_INTERNAL_HOST):   
           log.info("ICMP echo reply msg from %s to %s", srcaddr, packet.next.dstip)

           if prt == inport:
               log.warning("%i %i not sending packet for %s back out of the " +
                         "input port" % (dpid, inport, str(dstaddr)))
           else:
               log.debug("%i %i installing flow for %s => %s out port %i"
                       % (dpid, inport, packet.next.srcip, dstaddr, prt))

           # add flow entry
           msg = of.ofp_flow_mod(command = of.OFPFC_ADD)
           msg.match.dl_type = 0x0800 #ipv4
           msg.match.nw_src = REAL_IP_OF_INTERNAL_HOST
           msg.match.nw_dst = dstaddr

           # change the srcip to virtual ip
           msg.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(self.srcip_dstvip_map[dstaddr])))
           msg.actions.append(of.ofp_action_dl_addr.set_dst(mac))
           msg.actions.append(of.ofp_action_output(port = prt))

           event.connection.send(msg)
           log.info("ICMP echo reply flow entry for internal node to %s has been installed", packet.next.dstip)

         # icmp echo reply for internal host
         elif icmpmsg.type == 8 and dstaddr == IPAddr(REAL_IP_OF_INTERNAL_HOST):
           log.info("ICMP echo request msg from %s to %s", packet.next.srcip, packet.next.dstip)

           if prt == inport:
              log.warning("%i %i not sending packet for %s back out of the " +
                         "input port" % (dpid, inport, str(dstaddr)))
           else:
              log.debug("%i %i installing flow for %s => %s out port %i"
                      % (dpid, inport, packet.next.srcip, dstaddr, prt))

           msg = of.ofp_flow_mod(command = of.OFPFC_ADD)
           msg.match.dl_type = 0x0800 #ipv4 msg
           msg.match.in_port = inport
           msg.match.nw_dst = "10.0.0.128/255.255.255.128"
           msg.actions.append(of.ofp_action_nw_addr.set_dst(dstaddr))
           msg.actions.append(of.ofp_action_output(port = prt))
           msg.actions.append(of.ofp_action_dl_addr.set_dst(mac))
           event.connection.send(msg)
           log.info("ICMP echo request flow entry for %s to internal host has been instaled", packet.next.srcip)

         else:
           log.warning("Uninvolved icmp msg type")
           return

      elif self.arp_for_unknowns:
        # We don't know this destination.
        # First, we track this buffer so that we can try to resend it later
        # if we learn the destination, second we ARP for the destination,
        # which should ultimately result in it responding and us learning
        # where it is

        # Add to tracked buffers
        if (dpid,dstaddr) not in self.lost_buffers:
          self.lost_buffers[(dpid,dstaddr)] = []
        bucket = self.lost_buffers[(dpid,dstaddr)]
        entry = (time.time() + MAX_BUFFER_TIME,event.ofp.buffer_id,inport)
        bucket.append(entry)
        while len(bucket) > MAX_BUFFERED_PER_IP: del bucket[0]

        # Expire things from our outstanding ARP list...
        self.outstanding_arps = {k:v for k,v in
          self.outstanding_arps.iteritems() if v > time.time()}

        # Check if we've already ARPed recently
        if (dpid,dstaddr) in self.outstanding_arps:
          # Oop, we've already done this one recently.
          return

        # And ARP...
        self.outstanding_arps[(dpid,dstaddr)] = time.time() + 4

        r = arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.hwlen = 6
        r.protolen = r.protolen
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST

        if dstaddr in self.vipList:
             r.protodst = IPAddr(REAL_IP_OF_INTERNAL_HOST)
        else:
             r.protodst = dstaddr

        r.hwsrc = packet.src
        r.protosrc = packet.next.srcip
        e = ethernet(type=ethernet.ARP_TYPE, src=packet.src,
                     dst=ETHER_BROADCAST)
        e.set_payload(r)
        log.debug("%i %i ARPing for %s on behalf of %s for Ipv4" % (dpid, inport, str(r.protodst), str(r.protosrc)))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.in_port = inport
        event.connection.send(msg)

    elif isinstance(packet.next, arp):

      a = packet.next

      if a.protosrc in self.arpTable[dpid]:
         if self.arpTable[dpid][a.protosrc] != (inport, packet.src):
                log.info("%i %i RE-learned %s", dpid,inport,str(a.protosrc))
      else:
         log.debug("%i %i learned %s", dpid,inport,str(a.protosrc))
         self.arpTable[dpid][a.protosrc] = Entry(inport, packet.src)

      if a.protodst in self.vipList:
         self.srcip_dstvip_map[a.protosrc] = str(a.protodst)
         a.protodst = REAL_IP_OF_INTERNAL_HOST

      log.info("%i %i ARP %s %s => %s", dpid, inport,
             {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
             'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))

      if a.prototype == arp.PROTO_TYPE_IP:

        if a.hwtype == arp.HW_TYPE_ETHERNET:

          if a.protosrc != 0:

            # Learn or update port/MAC info
            if a.protosrc in self.arpTable[dpid]:
              if self.arpTable[dpid][a.protosrc] != (inport, packet.src):
                log.info("%i %i RE-learned %s", dpid,inport,str(a.protosrc))
            else:
              log.debug("%i %i learned %s", dpid,inport,str(a.protosrc))
            self.arpTable[dpid][a.protosrc] = Entry(inport, packet.src)

            # Send any waiting packets...
            self._send_lost_buffers(dpid, a.protosrc, packet.src, inport)

            if a.opcode == arp.REPLY:
                  r = arp()
                  r.hwtype = a.hwtype
                  r.prototype = a.prototype
                  r.hwlen = a.hwlen
                  r.protolen = a.protolen
                  r.opcode = arp.REPLY
                  r.hwsrc = a.hwsrc
                  if a.protosrc == IPAddr(REAL_IP_OF_INTERNAL_HOST):
                     if a.protodst in self.srcip_dstvip_map:
                        r.protosrc = IPAddr(self.srcip_dstvip_map[a.protodst])
                  else:
                     r.protosrc = a.protosrc
                  r.protodst = a.protodst
                  r.hwdst = self.arpTable[dpid][a.protodst].mac
                  e = ethernet(type=packet.type, src=dpid_to_mac(dpid), dst=a.hwdst)
                  e.set_payload(r)
                  log.debug("%i %i answering ARP for %s to %s" % (dpid, inport,
                   str(r.protosrc), str(r.protodst)))
                  msg = of.ofp_packet_out()
                  msg.data = e.pack()
                  msg.actions.append(of.ofp_action_output(port = self.arpTable[dpid][a.protodst].port))
                  msg.in_port = inport
                  event.connection.send(msg)
                  return

            if a.opcode == arp.REQUEST:
              # Maybe we can answer

              if a.protodst in self.vipList:
                   self.srcip_dstvip_map[a.protosrc] = str(a.protodst)
                   a.protodst = IPAddr(REAL_IP_OF_INTERNAL_HOST)

              if a.protodst in self.arpTable[dpid]:
                # We have an answer...

                if not self.arpTable[dpid][a.protodst].isExpired():
                  # .. and it's relatively current, so we'll reply ourselves

                  r = arp()
                  r.hwtype = a.hwtype
                  r.prototype = a.prototype
                  r.hwlen = a.hwlen
                  r.protolen = a.protolen
                  r.opcode = arp.REPLY
                  r.hwdst = a.hwsrc
                  r.hwsrc = self.arpTable[dpid][a.protodst].mac
                  r.protodst = a.protosrc
                  if a.protodst == IPAddr(REAL_IP_OF_INTERNAL_HOST):
                     r.protosrc = IPAddr(self.srcip_dstvip_map[a.protosrc])
                  else:
                     r.protosrc = a.protodst

                  e = ethernet(type=packet.type, src=dpid_to_mac(dpid), dst=a.hwsrc)
                  e.set_payload(r)
                  log.debug("%i %i answering ARP for %s" % (dpid, inport,
                   str(r.protosrc)))
                  msg = of.ofp_packet_out()
                  msg.data = e.pack()
                  msg.actions.append(of.ofp_action_output(port =
                                                          of.OFPP_IN_PORT))
                  msg.in_port = inport
                  event.connection.send(msg)
                  return

      # Didn't know how to answer or otherwise handle this ARP, so just flood it
              log.debug("%i %i flooding ARP %s %s => %s" % (dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst)))
              r1 = arp()
              r1.hwtype = a.HW_TYPE_ETHERNET
              r1.prototype = a.PROTO_TYPE_IP
              r1.hwlen = 6
              r1.protolen = a.protolen
              r1.opcode = arp.REQUEST
              r1.hwdst = ETHER_BROADCAST
              r1.protodst = IPAddr(a.protodst)
              r1.hwsrc = a.hwsrc
              r1.protosrc = a.protosrc
              e1 = ethernet(type=ethernet.ARP_TYPE, src=a.hwsrc, dst=ETHER_BROADCAST)
              e1.set_payload(r1)
              log.debug("%i %i ARPing for %s on behalf of %s" % (dpid, inport, str(r1.protodst), str(r1.protosrc)))
              msg1 = of.ofp_packet_out()
              msg1.data = e1.pack()
              msg1.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
              msg1.in_port = inport
              event.connection.send(msg1)

def launch (fakeways="", arp_for_unknowns=None):
  fakeways = fakeways.replace(","," ").split()
  fakeways = [IPAddr(x) for x in fakeways]
  if arp_for_unknowns is None:
    arp_for_unknowns = len(fakeways) > 0
  else:
    arp_for_unknowns = str_to_bool(arp_for_unknowns)
  core.registerNew(l3_switch, fakeways, arp_for_unknowns)
