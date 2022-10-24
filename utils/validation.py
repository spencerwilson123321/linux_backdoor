"""
    This module contains functions for validating command line arguments.
"""
from ipaddress import ip_address, IPv6Address
from psutil import net_if_addrs

def validate_ipv4_address(address: str) -> bool:
    """
        Returns True if the given address is a valid IPv4 address.
        Else False.
    """
    try:
        ip = ip_address(address)
        if isinstance(ip, IPv6Address):
            return False
        return True
    except:
        return False

def validate_nic_interface(interface: str) -> bool:
    """
        Returns True if the given address is a valid network interface.
        Else False.
    """
    addresses = net_if_addrs()
    if interface in addresses.keys():
        return True
    return False
