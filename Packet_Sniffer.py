#!/usr/bin/python

# Look at ethernet frame wikipedia page
# Can google different protocols RFC for documentation on them
# Should read the documentation on this
# Always use unsigned for header fields
# Can set urgent flag and send data to see how people's machines handle it

import socket
import os
import struct
import binascii  # Converts binary data to ascii and vice-versa


def analyze_udp_header(data):
    udp_hdr = struct.unpack("!4H", data[:8])
    src_port = udp_hdr[0]
    dst_port = udp_hdr[1]
    length = udp_hdr[2]
    chk_sum = udp_hdr[3]

    data = data[8:]
    return data


def analyze_tcp_header(data):
    tcp_hdr = struct.unpack("!2H2I4H", data[:20])  # Breaking apart the packet
    src_port = tcp_hdr[0]  # Source Port
    dst_port = tcp_hdr[1]  # Destination Port
    seq_num = tcp_hdr[2]  # Sequence Number | Used to determine the order of the packets and error checking
    ack_num = tcp_hdr[3]  # Acknowledgemnt Number
    reserved = (tcp_hdr[
                    4] >> 6) & 0x03ff  # Resevered (must be zero) | Note: can find the bits we need to shift and operate on from the protocol documentation
    flags = tcp_hdr[4] & 0x003f  # Control Bit
    urg = flags & 0x0020  # Urgent Flag
    ack = flags & 0x0010  # Acknowledgment bit | If set it means that we have recieved data and will send back packet to confirm data was recieved
    psh = flags & 0x0008  # Push bit | Means I have data for you
    rst = flags & 0x0004  # Reset bit | Means an error occured and need to resend/restart the connection
    syn = flags & 0x0002  # Syncronize bit | Part of the 3-way handshake
    fin = flags & 0x0001  # End bit | Connection will be ended
    window = tcp_hdr[5]  # Size of data that can be sent through the connection
    checksum = tcp_hdr[6]  # Used to make sure data was sent properly
    urg_ptr = tcp_hdr[7]  # Urge Pointer | Can be monitored to see if someone is doing something malicious

    data = data[20:]
    return data


def analyze_ip_header(data):
    ip_hdr = struct.unpack("!6H4s4s", data[:20])
    ver = ip_hdr[0] >> 12  # Version | Version
    # Shifting the header over right 12 bits to get rid of unnecessary fields, leaving us with only what we care about
    # Using & operator to specify which bits we want, specified by the 1
    ihl = (ip_hdr[0] >> 8) & 0x0f  # 00001111 | IHL
    tos = ip_hdr[0] & 0x00ff  # 0000000011111111 | Type of Service
    tot_len = ip_hdr[1]  # Total Length
    ip_id = ip_hdr[2]  # Identification
    flags = ip_hdr[3] >> 13  # Only the first 3 bits | Flags
    frag_offset = ip_hdr[3] & 0x1fff  # 0111... | Fragment Offset | Only sees 13 bits cause of &
    ip_ttl = ip_hdr[4] >> 8  # Time to Live
    ip_proto = ip_hdr[4] & 0x00ff  # Protocol
    chk_sum = ip_hdr[5]  # Header Checksum
    src_addr = socket.inet_ntoa(ip_header[6])  # Source Address
    dst_addr = socket.inet_ntoa(ip_header[7])  # Destination Address

    # Checking next protocol
    if ip_proto == 6:  # TCP number | Can look at assigned internet protocol numbers for this
        next_proto = "TCP"
    if ip_proto == 17:
        next_proto = "UDP"

    data = data[20:]
    return data, next_proto


def analyze_ether_header(data):
    ip_bool = False

    eth_hdr = struct.unpack("!6s6sH", data[:14])  # Need to slice data field, as it is giving us all the data
    # Ethernet frame starts at MAC destination
    # ! parameter is used because we don't know if our pc is little or big edian
    # First parameter is taking the packet apart, ie. specifying first 6 octets/bytes is the mac address
    # Notice from python struct documentation that string (s) has unspecified size, so we use it to get first 6 octetes/bytes for MAC address
    # Breaking up the tuple to get required info
    dest_mac = binascii.hexlify(eth_hdr[0])  # Destination Address
    src_mac = binascii.hexlify(eth_hdr[1])  # Source Address
    proto = eth_hdr[2]  # Next protocol (the protocol we need to be prepared to handle next)

    print
    "|====================ETH Header====================|"
    print
    "Destination MAC: %s:%s:%s:%s:%s%s" % (
    dest_mac[0:2], dest_mac[2:4], dest_mac[4:6], dest_mac[6:8], dest_mac[8:10], dest_mac[10:12])
    print
    "Source MAC: %s:%s:%s:%s:%s%s" % (
    src_mac[0:2], src_mac[2:4], src_mac[4:6], src_mac[6, 8], src_mac[8:10], src_mac[10:12])
    print
    "Next Protocol: " + hex(proto) + "\n"

    if hex(proto) == 0x0800:  # If the next protocol is IPv4
        ip_bool = True

    data = data[14:]
    return data, ip_bool  # Returning the data and boolean for if next protocol is IPv4


def main():
    sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    # socket.PF_PACKET gives us the whole packet
    # socket.htons(0x0003) get anything on internet that is an IP packet
    # sniffer_socket.bind() <=== Don't do this
    # If we bind it to a specific port it will only sniff on that port, if not then it will sniff all traffic
    recv_data = sniffer_socket.recv(2048)  # Recieving data we are sniffing

    data, ip_bool = analyze_ether_header(recv_data)

    if ip_bool:
        data, next_proto = analyze_ip_header(data)

    if next_proto == "TCP":
        data = analyze_tcp_header(data)
    elif next_proto == "UDP":
        data = analyze_udp_header(data)
    else:
        return


while True:
    main()
