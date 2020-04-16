# SIS 2 Project: Capturing network packets 
![Network](https://res-3.cloudinary.com/crunchbase-production/image/upload/c_lpad,h_256,w_256,f_auto,q_auto:eco/v1493701906/jwsxmtgk1rsjo9yp61ik.png)
## Team members:

Name | Github Link
--- | ---
Biryukova Alexandra | https://github.com/AlexandraBiryukova
Savoskin Roman |  https://github.com/savoskin0502
Amambayeva Meruert | https://github.com/hellomeruert
	
### Goal of the project: 
Create a simple sniffer that can help to analyze and control packets in the network

### Description: 
We want to create a module that will present all packets in the socket buffer structure form, that is using to store all information about packets, like header, ip, destination information etc. For all packets in the network we will fi lter them by protocol type and decide which ones we will accept and which ones to discard. At the same time, for all received packets we will determine for whom they were intended. Were they directed to us or for all machines in the network(broadcast), or may be some looped back packets.
In our work we will control at least two type of protocols(UDP, TCP) and six packet types. There are:
1. Packets that was directed to us
2. Broadcast packets - intended for reception by all network participants
3. Multicast packets - addressed to a group of destination computers simultaneously
4. Unicast packets for sending to a peer - host to host sending
5. Outgoing packets - originate at the machine
6. Any looped back broadcast or unicast packets

```diff
+ As a parameter to the module you can pass following protocol numbers
```
Protocol | Number | Title
--- | --- | ---
ICMP | 1 | Internet Control Message Protocol
IGMP | 2 | Internet Group Management Protocol
IPIP | 4 | IPIP tunnels (older KA9Q tunnels use 94)
TCP | 6 | Transmission Control Protocol
EGP | 8 | Exterior Gateway Protocol
PUP | 12 | PUP protocol
UDP | 17 | User Datagram Protocol
IDP | 22 | XNS IDP protocol
TP | 29 | SO Transport Protocol Class 4
DCCP | 33 | Datagram Congestion Control Protocol
IPV6 | 41 | IPv6 header
RSV | 46 | Reservation Protocol
GRE | 47 | General Routing Encapsulation
ESP | 50 | encapsulating security payload
AH | 51 | authentication header
MTP | 92 | Multicast Transport Protocol
BEETPH | 94 | IP option pseudo header for BEET
ENCAP | 98 | Encapsulation Header
PIM | 103 | Protocol Independent Multicast
COMP | 108 | Compression Header Protocol
SCTP | 132 | Stream Control Transmission Protocol
UDPLITE | 136 | UDP-Lite protocol
MPLS | 137 | MPLS in IP
RAW | 255 | Raw IP packets
