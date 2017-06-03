from scapy.all import *
import RPi.GPIO as GPIO
import time

# BUTTONS
sheeba = '44:65:0d:c5:96:f1'
dreamies = '50:f5:da:ba:07:3a'

def arp_detect(pkt):
  if pkt[ARP].op == 1:
      if pkt[ARP].hwsrc == sheeba:
        print("Sheeba Pressed") #Tutaj zamiast print twoja komenda albo funkcja
        GPIO.setmode(GPIO.BCM)
        GPIO.setwarnings(False)
        GPIO.setup(23, GPIO.OUT)
        GPIO.output(23, GPIO.LOW)
        time.sleep(0.05)
        GPIO.output(23, GPIO.HIGH)
      if pkt[ARP].hwsrc == dreamies:
        print("Dreamies Pressed") #Tutaj zamiast print twoja komenda albo funkcja

sniff(prn=arp_detect, filter="arp", store=0, count=0)

