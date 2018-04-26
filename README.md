# Firewall-for-Linux-using-Python


INTRODUCTION

A firewall forms an important component in terms of defense mechanism when considered over a network connected to Internet. It is a system which pre-defines a certain set of rules to restrict and filter the incoming and outgoing traffic so as to assure the network security. The purpose of the firewall is to stop the unwanted and malicious network communication taking place and allow a legitimate traffic over the network. Thus, understanding a firewall is important if one is interested in the computer security. In this project we have implemented a firewall for LINUX using Python and NetFilter tools. 


MAJOR COMPONENTS

1. NFQUEUE
NFQUEUE is an iptables and ip6tables target which delegate the decision on packets to a userspace software. For example, the following rule will ask for a decision to a listening userpsace program for all packet going to the box:
Iptables -A INPUT -j NFQUEUE --queue-num 0
 
When a packet reach an NFQUEUE target it is enqueued to the queue corresponding to the number given by the --queue-num option. The packet queue is a implemented as a chained list with element being the packet and metadata (a Linux kernel skb):
 · It is a fixed length queue implemented as a linked-list of packets.
 · Storing packet which are indexed by an integer.
 · A packet is released when userspace issue a verdict to the corresponding index integer.
 · When queue is full, no packet can be enqueued to it.
 
This has some implication on userspace side:
 · Userspace can read multiple packets and wait for giving a verdict. If the queue is not full there is no impact of this behavior.
 · Packets can be verdict without order. Userspace can read packet 1,2,3,4 and verdict at 4,2,3,1 in that order.
 · Too slow verdict will result in a full queue. The kernel will then drop incoming packets instead of enqueuing them.
  
The protocol used between kernel and userspace is nfnetlink. This is a message based protocol which does not involve any shared memory. When a packet is enqueued, the kernel sends a nfnetlink formatted message containing packet data and related information to a socket and userspace reads this message. To issue a verdict, userspace format a nfnetlink message containing the index number of the packet and send it to the communication socket.
 
 
2. SCAPY
Scapy is a powerful interactive packet manipulation program. It is able to forge or decode packets of a wide number of protocols, send them on the wire, capture them, match requests and replies, and much more. It can easily handle most classical tasks like scanning, tracerouting, probing, unit tests, attacks or network discovery. It also performs very well at a lot of other specific tasks that most other tools can't handle, like sending invalid frames, injecting your own 802.11 frames, combining techniques (VLAN hopping+ARP cache poisoning, VOIP decoding on WEP encrypted channel).
 
Most other tools confuse users between decoding and interpreting. For eg.They might display ‘Port is open’ instead of ‘SYN-ACK is received’. Sometimes this can be wrong. Scapy tries to overcome those problems. It enables us to build exactly the packets you want. Scapy has a flexible model that tries to avoid such arbitrary limits. After a probe (scan, traceroute, etc.) Scapy always gives us the full decoded packets from the probe, before any interpretation. That means that we can probe once and interpret many times, ask for a traceroute and look at the padding for instance.

3. BSD SOCKETS
Socket programming is a way of connecting two nodes on a network to communicate with each other. One socket(node) listens on a particular port at an IP, while other socket reaches out to the other to form a connection. Server forms the listener socket while client reaches out to the server.
 Socket programming is started by importing the socket library and making a simple socket.
 
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 
Here we made a socket instance and passed it two parameters. The first parameter is AF_INETand the second one is SOCK_STREAM. AF_INET refers to the address family ipv4. The SOCK_STREAM means connection oriented TCP protocol.
 
Server Socket Methods:
    1. s.bind()
This method binds address (hostname, port number pair) to socket.
    2. s.listen()
This method sets up and start TCP listener.
    3. s.accept()
This passively accept TCP client connection, waiting until connection arrives (blocking).
 
Client Socket Methods:
    1.s.connect()
This method actively initiates TCP server connection.
 
General Socket Methods:
1. s.recv()
This method receives TCP message  
2. s.send()
This method transmits TCP message
3. s.recvfrom()
This method receives UDP message 
4. s.sendto()
This method transmits UDP message
5. s.close()
This method closes socket  	
6. socket.gethostname()
Returns the hostname.
 

IPTABLES:
iptables is a user-space utility program that allows a system administrator to configure the tables provided by the Linux kernel firewall (implemented as different Netfilter modules) and the chains and rules it stores. Different kernel modules and programs are currently used for different protocols; iptables applies to IPv4, ip6tables to IPv6, arptables to ARP, and ebtables to Ethernet frames.
iptables requires elevated privileges to operate and must be executed by user root, otherwise it fails to function. On most Linux systems, iptables is installed as /usr/sbin/iptables and documented in its man pages, which can be opened using man iptables when installed. It may also be found in /sbin/iptables, but since iptables is more like a service rather than an "essential binary", the preferred location remains /usr/sbin.
The term iptables is also commonly used to inclusively refer to the kernel-level components. x_tables is the name of the kernel module carrying the shared code portion used by all four modules that also provides the API used for extensions; subsequently, Xtables is more or less used to refer to the entire firewall (v4, v6, arp, and eb) architecture.



IMPLEMENTATION              

We integrated NFQUEUE with INPUT and OUTPUT iptables using below commands.

iptables -A INPUT -j NFQUEUE --queue-num 0
iptables -A OUTUT -j NFQUEUE --queue-num 0

After making these changes to iptable, firewall.py code can be run on host.

RESULTS
We have enabled user to select option for allowing or accepting the traffic. The user can filter out packets on the basis of Protocol, Port number and IP address. 
We are able to allow and block traffic of TCP, UDP and ICMP. 
