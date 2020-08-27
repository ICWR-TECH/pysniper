#!/usr/bin/env python3
# Coded By Afrizal F.A - ICWR-TECH

import os, datetime
from scapy.all import *
from scapy.error import Scapy_Exception
from argparse import ArgumentParser

class sniffer:

    def pktTCP(self, pkt):

        if pkt.haslayer(TCP) and pkt.getlayer(TCP).dport == 80 and pkt.haslayer(Raw):

            try:

                print("[+] [Recive Packet] [{}]\n".format(pkt.getlayer(IP).src))
                paket = pkt.getlayer(Raw).load
                print(paket.decode('utf-8') + "\n")
                f = open("result-sniffing/sniff-{}.txt".format(datetime.today().strftime('%Y-%m-%d')), "a")
                f.write(paket.decode('utf-8'))

            except:

                pass

    def __init__(self):

        if not os.path.isdir("result-sniffing"):

            os.mkdir("result-sniffing")

        parser = ArgumentParser()
        parser.add_argument("-i", "--interface", required=True)
        args = parser.parse_args()
        sniff(iface=args.interface, prn=self.pktTCP)

sniffer()
