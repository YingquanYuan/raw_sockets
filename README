# README

This is the manual for Raw Sockets, a Python implementation of the TCP/IP
protocol stack.

This project is implemented using Python2.7. And the C-style structure used
to compose TCP stack packets are from Python struct module.

To run the program, run:
    ./rawhttpget URL

For basic TCP/IP feature, I implemented the protocols stack with TCP/IP
checksum, timeout/retransmission, congestion window and advertised window, etc.

===============================================================================

REALLY IMPORTANT

I utilized some feature of the network interface in Linux, and by default,
'eth0' will be used. Since the main network interfaces in different machines
could be varying, so that an optional argument of the main executable
'rawhttpget' has been made.

Please remember to change the correct network interface on your machine if
the currently working one is not 'eth0', such as:
    ./rawhttpget -i eth1 URL
The program will use 'eth0' by default.

===============================================================================

Data Link Layer features

The raw socket is in AF_PACKET family, which bypasses the operating systems
layer-2 stack as well at layers 3 and 4.

For Ethernet functionality, I have built my own Ethernet frames wrapping IP
datagram and ARP request. Before sending any high level message to remote
host, the raw socket in AF_PACKET family must query its gateway MAC address
for building the subsequent Ethernet frame, so the first Ethernet frame sent
is a broadcast, wrapping an ARP request for every host in the LAN to query the
gateway MAC address. Once the gateway sends back an ARP reply. I can extract
its MAC address from the ARP reply and embed this MAC address to our subsequent
Ethernet frames.

There are 2 challenges I faced when working on layer 2.

1. Before sending the broadcast ARP request for querying gateway MAC address,
how to get the gateway IP address? I finally hacked it that the gateway IP
address could be obtained from the file /proc/net/route, which is the static
routing table file in a Linux system, and the encoded gateway IP address of the
given network interface (e.g. eth0) is there.

2. I did not realize that in layer 2, the raw socket usually adds some padding
bytes at the end of an Ethernet frame, which yields a packet as below:
-------------------------------------------------------------------
|                 |           |            |           |          |
| Ethernet Header | IP Header | TCP Header | HTTP data | Paddings |
|                 |           |            |           |          |
-------------------------------------------------------------------
This cannot be a problem when working with SOCK_RAW/IPPROTO_TCP, because what
initially get from the raw socket is an IP datagram, and the Ethernet header
and trailing paddings have been removed by the raw socket. But when using
AF_PACKET, what get from the raw socket is an Ethernet frame, since the minimum
size of the user data in an Ethernet frame is 46 bytes, hence the raw socket
would add some trailer to some 'short' Ethernet frame. So that's why a lot of TCP
checksum failure gets generated because the Ethernet frame paddings have not been
removed.
To illustrate such situation, we can assume an Ethernet frame containing a TCP/IP
packet composed of a 20 byte IP header and 20 byte TCP header, so the raw socket
would pad the payload with 6 bytes. To calculate the actual length of the packet,
we need to use the total length and header length values in the IP header and
the offset value in the TCP header.

===============================================================================

Makefile

The project root directory is raw_sockets.

Run 'make' would create a symbolic link 'rawhttpget' under the root directory,
which is linking to the executable Python script 'rawhttpget.py' in the ./src
directory. Also the iptables would be modified during 'make' so that you can
use the raw socket without losing any packets, and this needs you have sudo
privilege.

Run 'sudo make clean' would purge all binary, executable links and transient
files inside the project directory.

Run 'sudo make test' would kick off an integration testing script 'test.sh'
in the ./test directory, which will run 'rawhttpget' several time to download
files with the given urls. Note that this might take minutes since there is a
url pointing to a 50MB file in the script.

===============================================================================

The Design

rawhttpget.py
Main entry of the raw socket program.

HttpClient.py, HttpParser.py
Python modules reused from project-2, mainly process all HTTP related issues.

rawurllib.py
Simple wrapper of the url based application layer module, works compactly with
the above 2 modules.

rawsocket.py
A socket module integrating the TCP/IP protocols stack, very similar to the
generic socket module of Python on functionality.

rawtcp.py
Simple Python model for easily packing and unpacking TCP segment.

rawip.py
Simple Python model for easily packing and unpacking IP datagram.

rawethernet.py
Simple Python model for easily packing and unpacking Ethernet frame.

rawarp.py
Simple Python model for easily packing and unpacking ARP packet.

utils.py
Contains useful util functions and classes, the checksum algorithm gets
implemented here for global usage through the TCP/IP stack.

logger.py
A simple logger that can log message in different severity level, could enter
silent mode.

===============================================================================

