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

# En esta funcion usa el objeto scapy.ARP() y sus funciones para realizar el envio de los paquetes preguntando "Who has (ip)"
def scan(ip):
    # Creo el objeto scpy.ARP y le asigno el valor del campo donde van las ips (pdst) a la variable ip
    arp_request = scapy.ARP(pdst=ip)
    # Ethernet framework que envio para la broadcast MAC
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Literalmente combino el packet de la broadcast mac y la ip generando el packet final
    final_packet = broadcast/arp_request
    # Envio y respuesta del paquete. El [0] es para capturar solo el primer elemento de la lista, o sea, el answered_packets.
    # answered_packets tmb es una lista teniendo dos elementos: los paquetes enviados, y el otro las respuestas de esos paquetes
    answered_packets = scapy.srp(final_packet, timeout=1, verbose=False)[0]

    super_list = []

    for element in answered_packets:
        # Para cada elemento creo un diccionario que contenga la ip y la mac de ese cliente. Las Ips estan en psrc y las macs en hwsrc
        clients_dic = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        # Por cada diccionario que se va creando lo voy adding a la super_list con el .append
        super_list.append(clients_dic)

    return super_list

def print_results(result_list):

    print ("-----------------------------------------")
    print ("IP\t\t\tMAC ADDRESS\n-----------------------------------------")  # El \t imprime un tab y el \n baja un renglon

    for client in result_list:
        print (client['ip'] + "\t\t" + client['mac'])  # Printing only the ip and mac values from the dictionaries

# Calling functions

values = parsing()

scan_result = scan(values.ip)
print_results(scan_result)