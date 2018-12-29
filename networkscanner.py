import scapy.all as scapy  # Requires pip to install


def scan(ip):
    # Var holding an instance of an arp packet object
    arp_request = scapy.ARP(pdst=ip)  #Setting the destination ip variable, pdst
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Creates an Ethernet frame object
    arp_request_broadcast = broadcast/arp_request  # Combining the ARP packet and Ethernet frame packet objects
    # Sends the specified packet, waits till it recieves a response and returns answered and unanswered packets
    # The timeout var is set to x seconds to wait for a response before considering it unanswered
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
    for x in answered_list:
        client_dict = {"ip": x[1].psrc, "mac": x[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


def print_result(results_list):
    print("+- IP\t\t\tMAC Address\n-----------------------------------------------+")
    for x in results_list:
        print(x["ip"] + "\t\t" + x["mac"])


# scan_result = scan("192.168.0.1/24")
# print_result(scan_result)
