import logging
from datetime import datetime
import subprocess
import sys

#to suppress initial scapy messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

#recommended way to import scapy

try:
    from scapy.all import *

except ImportError:
    print("Scapy package for python is not installed in your system")
    sys.exit()

print("\nrun this program as root\n")

net_iface= input("* Enter the interface the sniffer has to run on(Eg: 'enp0s8'): ")


#sitting interface to promiscuous mode - all the traffic recieved by interface is sent to CPU instead of only the frames
#promiscous mode is used generally for packet sniffing

try:
    subprocess.call(["ifconfig",net_iface,"promisc"],stdout=None,stderr=None,shell=False)

except:
    print("\nFailed to enter promiscuous mode\n")

else:
    print("\nInterface %s set to promiscuous mode\n" %net_iface)

#number of packets
pkt_to_sniff=input("\nEnter the number of packets to sniff (0 is infinity): ")

if int(pkt_to_sniff)!=0:
    print("\nprogram will capture %d packets\n"%int(pkt_to_sniff))
elif int(pkt_to_sniff)==0:
    print("\nprogram will capture packets until timeout.\n")

#time to sniff
time_to_sniff=input("\nEnter the time in seconds to sniff: ")

if int(time_to_sniff)!=0:
    print("\n The program will run for %d seconds\n"%int(time_to_sniff))

#protocols to be used
proto_sniff=input("\nEnter the protocol to be filtered (icmp | arp | bootp | 0 for all): ")

if (proto_sniff=="arp")or (proto_sniff=="bootp")or (proto_sniff=="icmp"):
    print("\nprogram will capture %s protocols only\n"%proto_sniff.upper())
elif proto_sniff=="0":
    print("\nprogram will capture all protocols.\n")

#creating a file to save sniff details
file_name=input("*Please enter a name for the log file: ")
sniffer_log=open(file_name,"a")

def packet_log(packet):
    now=datetime.now()
    if proto_sniff=="0":
        print("Time: "+str(now)+" Protocol: ALL "+" SMAC: "+packet[0].src+" DMAC: "+packet[0].dst, file = sniffer_log)
    elif (proto_sniff=="arp")or (proto_sniff=="bootp")or (proto_sniff=="icmp"):
        print("Time: "+str(now)+" Protocol: "+proto_sniff.upper()+" SMAC: "+packet[0].src+" DMAC: "+packet[0].dst,file=sniffer_log)

print("\nStarting the capture...")

#Running the sniffing process (with or without a filter)
if proto_sniff == "0":
    sniff(iface = net_iface, count = int(pkt_to_sniff), timeout = int(time_to_sniff), prn = packet_log)

elif (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
    sniff(iface = net_iface, filter = proto_sniff, count = int(pkt_to_sniff), timeout = int(time_to_sniff), prn = packet_log)

else:
    print("\nCould not identify the protocol.\n")
    sys.exit()

#Printing the closing message
print("\n* Please check the %s file to see the captured packets.\n" % file_name)

sniffer_log.close()
