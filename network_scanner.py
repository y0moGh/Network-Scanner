#!usr/bin/env python

import scapy.all as scapy
import argparse

def parsing():
    
    parser = argparse.ArgumentParser()

    parser.add_argument("-r", "--range", dest="ip", help="IP or IPs range you want to scan")

    values = parser.parse_args()

    if not values.ip:
        parser.error("[-] Please, specify an IP/IPs range")

    return values

def scan(ip):
    
    arp_request = scapy.ARP(pdst=ip)
    
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    final_packet = broadcast/arp_request
    
    answered_packets = scapy.srp(final_packet, timeout=1, verbose=False)[0]

    super_list = []

    for element in answered_packets:
        
        clients_dic = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        
        super_list.append(clients_dic)

    return super_list

def print_results(result_list):

    print ("-----------------------------------------")
    print ("IP\t\t\tMAC ADDRESS\n-----------------------------------------")  

    for client in result_list:
        print (client['ip'] + "\t\t" + client['mac']) 

# Calling functions

values = parsing()

scan_result = scan(values.ip)
print_results(scan_result)
