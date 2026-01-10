from scapy.all import *
import mac_vendor_lookup

class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to pcap file
        """
        self.pcap_path = pcap_path
        self.packets = rdpcap(pcap_path)
        self.info = self.get_info()
    def get_ips(self):
        """
        Returns a list of all ip addresses(strings) that appear in the pcap
        """
        ips = []
        for device in self.info:
            if device["ip"] != "Unknown" and device["ip"] not in ips:
                ips.append(device["ip"])
        return ips
    def get_macs(self):
        """
        Returns a list of all MAC addresses(strings) that appear in the pcap
        """
        macs = []
        for device in self.info:
            if device["mac"] != "Unknown" and device["mac"] not in macs:
                macs.append(device["mac"])
        return macs
    def get_info_by_mac(self, mac):
        """
        returns a dict with all information about the device with the given mac address
        """
        # there might be multiple devices with the same mac. return a list of dicts
        devices = []
        for device in self.info:    
            if device["mac"] == mac:
                devices.append(device)
        return devices
    def get_info_by_ip(self, ip):
        """
        returns a dict with all information about the device with the given ip address
        """
        # there might be multiple devices with the same ip. return a list of dicts
        devices = []
        for device in self.info:    
            if device["ip"] == ip:
                devices.append(device)
        return devices
    def get_info(self):
        """
        returns a list of dicts with all information about every device.
        If a device has multiple IPs, multiple dicts will be present in the list.
        """
        devices_array = []
        for packet in self.packets:
            if Ether in packet:
                #sender info
                device_info = {}
                device_info["mac"] = packet[Ether].src
                device_info["vendor"] = mac_vendor_lookup.MacLookup().lookup(packet[Ether].src)
                if IP in packet:
                    device_info["ip"] = packet[IP].src
                elif ARP in packet:
                    device_info["ip"] = packet[ARP].psrc
                else:
                    device_info["ip"] = "Unknown"
                device_info["os_from_ttl"] = self.guess_os_from_ttl(device_info)
                device_info["os_from_ping_payload"] = self.guess_os_from_content(device_info)
                if device_info not in devices_array:
                    devices_array.append(device_info)
                #receiver info
                
                device_info = {}
                if packet[Ether].dst == "ff:ff:ff:ff:ff:ff":
                    continue
                device_info["mac"] = packet[Ether].dst
                device_info["vendor"] = mac_vendor_lookup.MacLookup().lookup(packet[Ether].dst)
                if IP in packet:
                    device_info["ip"] = packet[IP].dst
                elif ARP in packet:
                    device_info["ip"] = packet[ARP].pdst
                else:
                    device_info["ip"] = "Unknown"
                device_info["os_from_ttl"] = self.guess_os_from_ttl(device_info)
                device_info["os_from_ping_payload"] = self.guess_os_from_content(device_info)
                if device_info not in devices_array:
                    devices_array.append(device_info)
        return devices_array
    def guess_os_from_ttl(self, device_info):
        """
        Given a device info dict, tries to guess the OS of the device.
        Works with ttl - if ttl>64 its windows, else probably linux.
        """
        for packet in self.packets:
            if Ether in packet:
                if packet[Ether].src == device_info["mac"]:
                    if IP in packet:
                        ttl = packet[IP].ttl
                        if ttl > 64:
                            return "Windows"
                        else:
                            return "Linux/Windows"
        return "Unknown"
    def guess_os_from_content(self, device_info):
        """
        Given a device info dict, tries to guess the OS of the device.
        Works with packet content - checks for common patterns in icmp packets.
        """
        for packet in self.packets:
            if Ether in packet:
                if packet[Ether].src == device_info["mac"] and ICMP in packet:
                    raw_data = bytes(packet)
                    if b"\x61\x62\x63\x64\x65\x66\x67\x68\x69" in raw_data:
                        return "Windows"
                    elif b"\x10\x11\x12\x13\x14\x15\x16\x17\x18" in raw_data:
                        return "Linux"
        return "Unknown"
    def __repr__(self):
        raise NotImplementedError
    def __str__(self):
        raise NotImplementedError
    
    
if __name__ == "__main__":
    analyzer = AnalyzeNetwork("pcaps/pcap-02.pcapng")
    print(analyzer.get_info())
    #print(analyzer.get_ips())
    #print(analyzer.get_macs())
    for i in analyzer.get_macs():
        print(i)
        print(analyzer.get_info_by_mac(i))
        print(f"from ttl: {analyzer.guess_os_from_ttl(analyzer.get_info_by_mac(i)[0])}")
        print(f"from content: {analyzer.guess_os_from_content(analyzer.get_info_by_mac(i)[0])}")
    
    