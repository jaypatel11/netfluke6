#!/usr/bin/env python

#
#  Fake ICMP and ARP responses from non-existings IPs via tap0.
#   Create fake MAC addresses on the fly.
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
#  Configure interface
#
ifname = "eth0"
print "Allocated interface %s. Configuring it." % ifname
configure_iface(ifname, 'f0:02:03:04:05:01', '10.5.0.1')


#
#  Now process packets
#
while 1:
  packets = sniff(iface=ifname, filter="arp or icmp", count=1)   # get packet routed to our "network"
  packet = packets[0]        # Scapy parses byte string into its packet object


  if packet.haslayer(ICMP) and packet[ICMP].type == 8 : # ICMP echo-request
    pong = packet.copy() 
    swap_src_and_dst(pong, Ether)
    swap_src_and_dst(pong, IP)
    pong[ICMP].type='echo-reply'
    pong[ICMP].chksum = None   # force recalculation
    pong[IP].chksum   = None
    sendp(pong, iface="eth0")

  elif packet.haslayer(ARP) and packet[ARP].op == 1 : # ARP who-has
    arp_req = packet;  # don't need to copy, we'll make reply from scratch

    # make up a new MAC for every IP address, using the address' last octet 
    s1, s2, s3, s4 = arp_req.pdst.split('.')
    fake_src_mac = "f0:02:03:04:05:" + ("%02x" % int(s4))  

    # craft an ARP response
    arp_rpl = Ether(dst=arp_req.hwsrc, src=fake_src_mac)/ARP(op="is-at", psrc=arp_req.pdst, pdst="10.5.0.1", hwsrc=fake_src_mac, hwdst=arp_req.hwsrc)
    sendp(arp_rpl, iface="eth0")

  else:      # just print the packet. Use "packet.summary()" for one-line summary
    print "Unknown packet: "
    print packet.summary()

