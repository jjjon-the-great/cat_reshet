from scapy.all import *
import mac_vendor_lookup

class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to pcap file
        """
        self.pcap_path = pcap_path
        self.packets = rdpcap(pcap_path)
        
    def get_ips(self):
        """
        Returns a list of all ip addresses(strings) that appear in the pcap
        """
        raise NotImplementedError
    def get_macs(self):
        """
        Returns a list of all MAC addresses(strings) that appear in the pcap
        """
        
        raise NotImplementedError
    def get_info_by_mac(self, mac):
        """
        returns a dict with all information about the device with the given mac address
        """
        raise NotImplementedError
    def get_info_by_ip(self, ip):
        """
        returns a dict with all information about the device with the given ip address
        """
        raise NotImplementedError
    def get_info(self):
        """
        returns a list of dicts with all information about every device.
        If a device has multiple IPs, multiple dicts will be present in the list.
        """
        devices_array = []
        for packet in self.packets:
            if Ether in packet:
                device_info = {}
                device_info["mac"] = packet[Ether].src
                device_info["vendor"] = mac_vendor_lookup.MacLookup().lookup(packet[Ether].src)
                if IP in packet:
                    device_info["ip"] = packet[IP].src
                elif ARP in packet:
                    device_info["ip"] = packet[ARP].psrc
                else:
                    device_info["ip"] = "Unknown"
                if device_info not in devices_array:
                    devices_array.append(device_info)
        return devices_array
        
    def __repr__(self):
        raise NotImplementedError
    def __str__(self):
        raise NotImplementedError
    
    
if __name__ == "__main__":
    analyzer = AnalyzeNetwork("pcaps/pcap-00.pcapng")
    print(analyzer.get_info())