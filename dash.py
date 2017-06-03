from scapy.all import *


# BUTTONS
sheeba = '44:65:0d:c5:96:f1'
dreamies = '50:f5:da:ba:07:3a'

def arp_detect(pkt):
  if pkt[ARP].op == 1:
      if pkt[ARP].hwsrc == sheeba:
        print("Sheeba Pressed") #Tutaj zamiast print twoja komenda albo funkcja
        
      if pkt[ARP].hwsrc == dreamies:
        print("Dreamies Pressed") #Tutaj zamiast print twoja komenda albo funkcja

sniff(prn=arp_detect, filter="arp", store=0, count=0)

