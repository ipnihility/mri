#!/usr/bin/env python
import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, UDP, Raw, Ether

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class SwitchTrace(Packet):
    fields_desc = [ BitField("swid", 0, 8),
                  BitField("in_port", 0, 8),
                  BitField("out_port", 0, 8),
                  ShortField("qdepth", 0),
                  BitField("in_time", 0, 48),
                  BitField("queue_time", 0, 32)]
    def extract_padding(self, p):
                return "", p

class MRI(Packet):
    fields_desc = [FieldLenField("length", None,
                                  length_of="swtraces",
                                  adjust=lambda pkt,l:l*15+4),
                  ShortField("count", 0),
                  PacketListField("swtraces",
                                  [],
                                  SwitchTrace,
                                  count_from=lambda pkt:(pkt.count*1))]

class SourceRoute(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]

bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)
bind_layers(IP, MRI, proto=250)
#bind_layers(SwitchTrace, UDP, bos=0)

def handle_pkt(pkt):
    print "got a packet"
    pkt.show2()
#    hexdump(pkt)
    sys.stdout.flush()


def main():
    iface = 'h4-eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="ip dst 10.0.4.4", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
