#Program to build a mini firewall using python

import struct
import sys
import time
import socket
from socket import AF_INET, AF_INET6, inet_ntoa
import nfqueue
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.inet import IP,TCP
from scapy.all import *

#from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
from math import ceil
import re
import binascii

global action, inputprotocol, actiontype, inputportnum, inputipaddr

class Firewall:
    def __init__(self):
        self.protocolname = ''
        self.srcipaddress = ''
        self.srcportnum = 0

    #""" Checks the packet to make sure the IPv4 address is valid. Upon
        #verifying that the addresses in the IP packet are valid, method
        #returns True. Else, it returns False. """
    def valid_IP_address(self, ext_addr):
        try:
            #print("ext_addr: ", ext_addr)
           socket.inet_ntoa(ext_addr)
            #print("ext_addr then : ", socket.inet_ntoa(ext_addr))
           return True
        except socket.error:
            #print("ext_addr error : ")
           return False

    def obtain_fields(self, pckt):
        try:
            #print("protocol: ", pckt[9:10])
            protocol = struct.unpack('!B', pckt[9:10]) # (integer,)
            # print("protocol: ", protocol)
            #print("total_len: ", pckt[2:4])
            total_length = struct.unpack('!H', pckt[2:4])
            #print("total_len: ", total_length)
            return self.strip_format(protocol), self.strip_format(total_length)
        except struct.error as e:
            print (e)
            return None, None

    def valid_ip_header(self, pckt):
        try:

            #print("valid ip: ",pckt[0:1])
            ip_header = struct.unpack('!B', pckt[0:1])
            #print("ip_header: ",ip_header)
            #print("ip_header stripped: ",self.strip_format(ip_header))
            return self.strip_format(ip_header)
        except struct.error as e:
            print (e)
            print pckt[0:1]
            return None

    def get_udp_length(self, pckt, startIndex):
        try:
            #print("udplen: ", pckt[startIndex + 4 : startIndex + 6])
            length = struct.unpack('!H', pckt[startIndex + 4 : startIndex + 6])
            #print("UDP_LEN: ", length)
            return self.strip_format(length)
        except struct.error:
            return None

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pckt_dir, pckt):
        ip_header = self.valid_ip_header(pckt)
        if (ip_header == None):
            print (1)
            return
        ip_header = ip_header & 0x0f
        if (ip_header < 5):
            print (2)
            return

        protocol, total_length = self.obtain_fields(pckt)
        #print ("proto: ",protocol)
        # print ("total length: ",total_length)
        if (protocol == None and total_length == None):
            print (3)
            return

        if (total_length != len(pckt)):
            print (4)
            return

        if (self.protocol_selector(protocol) == None):
            #self.send_packet(pckt, pckt_dir)
            print (5)
            return
            #   print("src_addr: ", socket.inet_ntoa(pckt[12:16]))
            #print("dest_addr: ", socket.inet_ntoa(pckt[16:20]))
            #print("direct: ", pckt_dir)
        src_addr, dst_addr, pckt_dir = pckt[12:16], pckt[16:20], self.packet_direction(pckt_dir)
        if (pckt_dir == 'incoming'):
            external_addr = src_addr
            # print("extern_addr: ", external_addr)
        else:
            external_addr = dst_addr
            #print("else extern_addr: ", external_addr)
        if not (self.valid_IP_address(external_addr)): # check valid address.
            print (6)
            return

        if (protocol == 6):  # TCP

            if (pckt_dir == 'incoming'):

                 external_port = self.handle_external_port(pckt, (ip_header) * 4)
            else:

                 external_port = self.handle_external_port(pckt, ((ip_header) * 4) + 2)

        elif (protocol == 1): # ICMP
            type_field = self.handle_icmp_packet(pckt, (ip_header * 4))
            # print ("ICMP PORT NUMBER: ",self.handle_external_port(pckt, (ip_header) * 4))
            if (type_field == None):
                print (8)
                return

        elif (protocol == 17): # UDP
            #print("udp ip_header : ", (ip_header * 4))
            udp_length = self.get_udp_length(pckt, (ip_header * 4))
            if (udp_length == None or udp_length < 8):
                print (9)
                return
            if (pckt_dir == 'incoming'):
                external_port = self.handle_external_port(pckt, (ip_header) * 4)
                if (external_port == None):
                    print (10)
                    return
            else:
                external_port = self.handle_external_port(pckt, ((ip_header) * 4) + 2)
                #   print("port : ", external_port)
                if (external_port == None):
                    print (10)
                    return



        verdict = "pass"
        self.protocolname = self.protocol_selector(protocol)
        # print("protocolname : ", self.protocolname)
        self.srcipaddress = external_addr
        # print ("external_addr : ", external_addr)
        #print ("srcipaddress : ", self.srcipaddress)
        if (protocol != 1):
            self.srcportnum = external_port


    """ Protocol Selector."""
    def protocol_selector(self, protocol):
        if (protocol == 1):
            return "icmp"
        elif (protocol == 6):
            return 'tcp'
        elif (protocol == 17):
            return 'udp'
        return None


    """ Returns True if the protocol of the packet is either TCP, UDP, or ICMP.
        Else, the method returns False. """
    def check_protocol(self, protocol):
        return (protocol == 'tcp') or (protocol == 'udp') or (protocol == 'icmp')



    """ Returns True if the external IP address is within the range of the
        IP prefix."""
    def within_range(self, start_port, end_port, external_ip):
        return external_ip >= start_port and external_ip <= end_port

    """ Check if the data is an IP prefix."""
    def is_IP_Prefix(self, data):
        return data.find('/')


    """ Strips the parentheses and comma off the number and converts string to int."""
    def strip_format(self, format_str):
        new_str = str(format_str)
        return int(new_str[1: len(new_str) - 2])

    """ Returns the external port and checks to see if there is a socket error. If
        the port is valid, then it returns a number, else it returns 'None'. """
    def handle_external_port(self, pckt, startIndex):
        try:
            #   print("start index : ", startIndex)

            ext_port = pckt[startIndex : startIndex + 2]
            #print("ext_port : ", pckt[startIndex: startIndex + 2])
            ext_port = struct.unpack('!H', ext_port)
            return ext_port
        except struct.error:
            return None

    """ Returns the TYPE field for the IMCP packet."""
    def handle_icmp_packet(self, pckt, startIndex):
        try:
            #print("start index : ", startIndex)
            type_field = pckt[startIndex : startIndex + 1]

            type_field = struct.unpack('!B', type_field)
            #print("type_field : ", self.strip_format(type_field))
            return self.strip_format(type_field)
        except struct.error:
            return None

    """ Returns the direction of the packet in a string."""
    def packet_direction(self, direction):
        if (direction == 'outgoing'):
            return 'outgoing'
        else:
            return 'incoming'


def cb(i, payload):
    data = payload.get_data()
    pkt = IP(data)
    # print ("pkt: ",pkt)
    f = Firewall()

    #check whether the packet is incomming or outgoing
    if(socket.inet_ntoa(str(pkt)[12:16])==deviceipaddr):
        print ("outgoing")
        f.handle_packet("outgoing", str(pkt))
    else:
        print ("incomming")
        f.handle_packet("incoming", str(pkt))

   # f.handle_packet("incoming", str(pkt))
    print (f.protocolname)
    print (socket.inet_ntoa(f.srcipaddress))
    print (f.srcportnum)

    if action == "block":
        if actiontype == "protocol":
            #   print ("protocolname: ", f.protocolname)
            #print ("inputprotocol: ", inputprotocol)
            if inputprotocol == f.protocolname:  #TCP, UDP, ICMP
                payload.set_verdict(nfqueue.NF_DROP)
                print (f.protocolname + " Packet blocked")

        elif actiontype == "ipaddress":
            #print ("inputipaddr: ",inputipaddr)
            #print ("srcipaddress: ",socket.inet_ntoa(f.srcipaddress))
            if inputipaddr == socket.inet_ntoa(f.srcipaddress):  #IP address
                payload.set_verdict(nfqueue.NF_DROP)
                print (socket.inet_ntoa(f.srcipaddress) + " blocked")

        elif actiontype == "portnum":
            if int(inputportnum) in f.srcportnum:
                payload.set_verdict(nfqueue.NF_DROP)
                print (inputportnum + " blocked")

    elif action == "accept":
        if actiontype == "protocol":
            if inputprotocol == f.protocolname:  #TCP, UDP, ICMP
                payload.set_verdict(nfqueue.NF_ACCEPT)
                print (f.protocolname + " Packet accepted")
            else:
                payload.set_verdict(nfqueue.NF_DROP)
                print (f.protocolname + " Packet blocked")

        elif actiontype == "ipaddress":

            if inputipaddr == socket.inet_ntoa(f.srcipaddress):  #IP address
                payload.set_verdict(nfqueue.NF_ACCEPT)
                print (socket.inet_ntoa(f.srcipaddress) + " accepted")
            else:
                payload.set_verdict(nfqueue.NF_DROP)
                print (socket.inet_ntoa(f.srcipaddress) + " blocked")

        elif actiontype == "portnum":
            if int(inputportnum) in f.srcportnum:
                payload.set_verdict(nfqueue.NF_ACCEPT)
                print (inputportnum + " accepted")
            else:
                payload.set_verdict(nfqueue.NF_DROP)
                print (inputportnum + " blocked")


def main():
    global action, inputprotocol, actiontype, inputportnum, inputipaddr, deviceipaddr

    #actiontype = "portnum"
    #action = "block"
    #inputportnum = "80"
    #inputprotocol = "tcp"
    #inputipaddr="128.119.245.12"
    deviceipaddr = "10.0.0.210"

    while True:

        act = input("Enter action to be performed : \n1. accept\n2. block\n==> ")

        if int(act) < 1 or int(act) > 2:
            print('Invalid option...... Select again\n')
            continue
        else:
            break


    if int(act) == 1:
        action = 'accept'

    elif int(act) == 2:
        action = 'block'


    while True:

        act_type = input("Enter action type : \n1. Protocol \n2. Port number \n3. IP address\n==> ")

        if int(act_type) < 1 or int(act_type) > 3:
            print('Invalid option...... Select again\n')
            continue
        else:
            break

    if int(act_type) == 1:
        actiontype = 'protocol'

    elif int(act_type) == 2:
        actiontype = 'portnum'

    elif int(act_type) == 3:
        actiontype = 'ipaddress'



    if actiontype == 'protocol':

        while True:

            proto_type = input("Enter protocol : \n1. TCP \n2. UDP \n3. ICMP\n==> ")

            if int(proto_type) < 1 or int(proto_type) > 3:
                print('Invalid option...... Select again\n')
                continue
            else:
                break

        if int(proto_type) == 1:
            inputprotocol = 'tcp'

        elif int(proto_type) == 2:
            inputprotocol = 'udp'

        elif int(proto_type) == 3:
            inputprotocol = 'icmp'


    elif actiontype == 'portnum':
        inputportnum = raw_input("Enter port number: ")


    elif actiontype == 'ipaddress':
        inputipaddr = raw_input("Enter ip address: ")


    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(cb)
    q.create_queue(0)

    try:
        q.try_run()
    except KeyboardInterrupt, e:
        print ("Interrupted")

    print ("unbind")
    q.unbind(AF_INET)
    print ("close")
    q.close()

main()





