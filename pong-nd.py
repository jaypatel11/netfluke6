#!/usr/bin/env python

#
# Fake Neighbor Discovery and ICMPv6 Echo responses for any address.
#

from scapy.all import *

import os

# About-face for a packet: swap src and dst in specified layer
def swap_src_and_dst(pkt, layer):
  pkt[layer].dst, pkt[layer].src = pkt[layer].src, pkt[layer].dst


def configure_iface(ifname, ether, ip, netmask = '255.255.255.0', bcast = ''):
    # Bring it down first
    subprocess.check_call("ifconfig %s down" % ifname, shell=True)

    hw_cfg_cmd = "ifconfig %s hw ether %s " % (ifname, ether)
    # Something causes this to fail on MacOS:
    try:
      subprocess.check_call( hw_cfg_cmd, shell=True)
    except:
      print "%s seems unsuppoted on this platform, skipping\n" % hw_cfg_cmd
      pass

    if bcast != '':
      ip_cfg_cmd = "ifconfig %s %s netmask %s broadcast %s up" % (ifname, ip, netmask, bcast)
    else:
      # ...and hope ifconfig is smart and computes bcast address! YMMV.
      ip_cfg_cmd = "ifconfig %s %s netmask %s up" % (ifname, ip, netmask)

    subprocess.check_call( ip_cfg_cmd, shell=True)


#
# Configure interface
#
IFNAME = "en0"
print "Allocated interface %s. Configuring it." % IFNAME
configure_iface(IFNAME, 'f2:02:03:04:05:01', '10.5.0.1')


#
# Now process packets
#
while 1:
  packets = sniff(iface=IFNAME, filter="ip6", count=1) # get packet routed to our "network"
  packet = packets[0] # Scapy parses byte string into its packet object


  if packet.haslayer(ICMPv6ND_NS) and packet[ICMPv6ND_NS].type == 135 : # ICMP echo-request
    ns = packet[ICMPv6ND_NS]
    print packet.summary() + " for " + packet[ICMPv6ND_NS].tgt

    # make a new NA to answer this NS
    na = ICMPv6ND_NA()
    na.S = 1
    na.R = 0
    na.O = 1
    na.tgt = ns.tgt
    lla = ICMPv6NDOptDstLLAddr()
    lla.lladdr = "f2:01:02:03:04:05"

    i6 = IPv6()
    i6.hlim = 255 # must be that for NA to be valid
    i6.src = ns.tgt 
    i6.dst = packet[IPv6].src # well, this is expected to be a unicast address

    e = Ether()
    e.type = 0x86dd # IPv6
    e.src = lla.lladdr
    if ns.haslayer(ICMPv6NDOptSrcLLAddr):
      e.dst = ns[ICMPv6NDOptSrcLLAddr].lladdr # from the incoming NS option
    else:
      e.dst = packet[Ether].src 

    reply_na = e/i6/na/lla

    print "ND IN: " + packet.summary()
    print "ND OUT: " + reply_na.summary()
    sendp(reply_na, iface="en0")

  elif packet.haslayer(ICMPv6EchoRequest):  # send ICMPv6EchoReply

    e = Ether()
    e.type = 0x86dd
    e.src, e.dst = packet[Ether].dst, packet[Ether].src

    i = IPv6()
    i.src, i.dst = packet[IPv6].dst, packet[IPv6].src

    r = ICMPv6EchoReply()
    r.id = packet[ICMPv6EchoRequest].id
    r.seq = packet[ICMPv6EchoRequest].seq
    r.data = packet[ICMPv6EchoRequest].data

    reply_icmpv6 = e/i/r

    print "ECHO IN: " + packet.summary()
    print "ECHO OUT: " + reply_icmpv6.summary()
    sendp(reply_icmpv6, iface="en0")

  else: # just print the packet. Use "packet.summary()" for one-line summary
    print "Unknown packet: "
    print packet.summary()

