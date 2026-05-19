#!/usr/bin/env python3
import argparse
import ipaddress
import random
import sys
from scapy.all import *

'''
Simple dhcp server.
'''
dhcp_config = {}
transaction_id = None

def handle_dhcp_packet(packet):
    """
    Handles incoming DHCP packets (Discover and Request).
    """
    if not DHCP in packet or not packet[BOOTP].chaddr:
        return

    # Client's MAC address
    client_mac = packet[BOOTP].chaddr

    # Handle DHCP Discover
    if packet[DHCP].options[0][1] == 1:
        print(f"--- DHCP Discover from {pretty_mac(client_mac)} ---")
        transaction_id = packet[BOOTP].xid
        # Convert the transaction ID to a more readable hexadecimal format if needed
        hex_id = hex(transaction_id)
        print('transaction id %s' % hex_id)

        # Craft DHCP Offer
        dhcp_offer = (
            #Ether(src=get_if_hwaddr(conf.iface), dst="ff:ff:ff:ff:ff:ff") /
            Ether(src=get_if_hwaddr(conf.iface), dst=pretty_mac(client_mac)) /
            IP(src=dhcp_config["server_ip"], dst=dhcp_config["offer_ip"]) /
            UDP(sport=67, dport=68) /
            BOOTP(
                op=2, # BOOTREPLY
                yiaddr=dhcp_config["offer_ip"],
                siaddr=dhcp_config["server_ip"],
                chaddr=client_mac,
                sname = "dhcp_service_node.sn",
                xid=transaction_id
            ) /
            DHCP(options=[
                ("message-type", "offer"),
                ("lease_time", 172800), # 2 days
                (54, b"10.10.0.1"), 
                ("router", dhcp_config["server_ip"]),
                ("subnet_mask", dhcp_config["subnet_mask"]),
                (15, b"network.sim"), 
                ("name_server", "10.10.0.1"),
                ("sname", "dhcp_driver.sn"),
                ("hostname", "dhcp0"), 
                "end"
            ])
        )

        print(f"--- Sending DHCP Offer of {dhcp_config['offer_ip']} ---")
        sendp(dhcp_offer, iface=conf.iface, verbose=0)

    # Handle DHCP Request
    elif packet[DHCP].options[0][1] == 3:
        print(f"--- DHCP Request from {pretty_mac(client_mac)} ---")
        transaction_id = packet[BOOTP].xid

        # Craft DHCP ACK
        dhcp_ack = (
            #Ether(src=get_if_hwaddr(conf.iface), dst="ff:ff:ff:ff:ff:ff") /
            Ether(src=get_if_hwaddr(conf.iface), dst=pretty_mac(client_mac)) /
            IP(src=dhcp_config["server_ip"], dst=dhcp_config["offer_ip"]) /
            UDP(sport=67, dport=68) /
            BOOTP(
                op=2, # BOOTREPLY
                yiaddr=dhcp_config["offer_ip"],
                siaddr=dhcp_config["server_ip"],
                chaddr=client_mac,
                xid=transaction_id
            ) /
            DHCP(options=[
                ("message-type", "ack"),
                ("subnet_mask", dhcp_config["subnet_mask"]),
                ("router", dhcp_config["server_ip"]),
                ("name_server", dhcp_config["dns"]),
                ("lease_time", 172800), # 2 days
                "end"
            ])
        )

        print(f"--- Sending DHCP ACK for {dhcp_config['offer_ip']} ---")
        sys.stdout.flush() 
        sendp(dhcp_ack, iface=conf.iface, verbose=0)

def pretty_mac(mac_bytes):
    """Converts a byte-string MAC to a human-readable string."""
    return ":".join(f"{b:02x}" for b in mac_bytes)[:17]

def dhcp_server():
    """
    Starts the DHCP server and begins sniffing for packets.
    """
    print("Starting DHCP server...")
    print(f"Server IP: {dhcp_config['server_ip']}")
    print(f"Offering IP: {dhcp_config['offer_ip']}")
    print(f"Subnet Mask: {dhcp_config['subnet_mask']}")
    print(f"Broadcast IP: {dhcp_config['broadcast_ip']}")
    sys.stdout.flush() 
    
    sniff(filter="udp and (port 67 or port 68)", prn=handle_dhcp_packet, store=0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Python DHCP Server")
    parser.add_argument("--subnet", required=True, type=str, help="The subnet to operate on, e.g., '192.168.1.0/24'")
    parser.add_argument("--dns", required=True, type=str, help="The dns address to return to the client.")
    args = parser.parse_args()

    try:
        # Use the ipaddress module to configure the network
        network = ipaddress.ip_network(args.subnet, strict=False)
        all_hosts = list(network.hosts())

        if len(all_hosts) < 101:
            raise ValueError("Subnet is too small. It must contain at least 101 usable addresses.")
            
        dhcp_config["server_ip"] = str(all_hosts[0])
        dhcp_config["offer_ip"] = str(all_hosts[99]) # Offer the 100th usable address
        dhcp_config["subnet_mask"] = str(network.netmask)
        dhcp_config["broadcast_ip"] = str(network.broadcast_address)
        dhcp_config["dns"] = args.dns
        print('Calling dhcp_server')
        transaction_id = None
        dhcp_server()

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


