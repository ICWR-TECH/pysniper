#!/usr/bin/env python
# Coded By Afrizal F.A - ICWR-TECH
import sys, datetime
from scapy.all import *
from scapy.error import Scapy_Exception
m_iface=sys.argv[1]
count=0
def pktTCP(pkt):
	global count
	if pkt.haslayer(TCP) and pkt.getlayer(TCP).dport == 80 and pkt.haslayer(Raw):
 		count=count+1
		try:
			print("[+] Recive Packet -> " + pkt.getlayer(IP).src + " [+]\n")
			paket = pkt.getlayer(Raw).load
			print(paket.decode('utf-8') + "\n")
			f = open("sniff-" + datetime.today().strftime('%Y-%m-%d') + ".txt", "a")
			f.write(paket.decode('utf-8'))
		except:
			pass
sniff(iface=m_iface,prn=pktTCP)
