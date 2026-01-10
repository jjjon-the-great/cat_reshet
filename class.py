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
        for packet in self.packets:
            if IP in packet:
                if packet[IP].src not in ips:
                    ips.append(packet[IP].src)
                if packet[IP].dst != "255.255.255.255" and packet[IP].dst not in ips:
                    ips.append(packet[IP].dst)
        return ips
    def get_macs(self):
        """
        Returns a list of all MAC addresses(strings) that appear in the pcap
        """
        macs = []
        for packet in self.packets:
            if Ether in packet:
                if packet[Ether].src not in macs:
                    macs.append(packet[Ether].src)
                if packet[Ether].dst != "ff:ff:ff:ff:ff:ff" and packet[Ether].dst not in macs:
                    macs.append(packet[Ether].dst)
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
            if ip in device["ip"]:
                devices.append(device)
        return devices
    
    def establish_device(self, mac):
        """
        establishes all information about the device with the given mac address
        returns a dict with the information about it.
        """
        device_info = {}
        device_info["mac"] = mac
        device_info["vendor"] = mac_vendor_lookup.MacLookup().lookup(mac)
        device_info["ip"] = []
        device_info["os"] = {"from_ttl": "Unknown", "from_ping_payload": "Unknown"}
        
        packets_from_device, packets_to_device = self.find_all_packets_of_device(mac)
        for packet in packets_from_device:
            if IP in packet:
                if packet[IP].src not in device_info["ip"]:
                    device_info["ip"].append(packet[IP].src)
            self.guess_os_from_packet(device_info, packet)
        for packet in packets_to_device:
            if IP in packet:
                if packet[IP].dst not in device_info["ip"]:
                    device_info["ip"].append(packet[IP].dst)
        return device_info
    
    def guess_os_from_packet(self, device_info, packet):
        """
        tries to guess the OS of the device from the given packet.
        updates the device_info dict in place.
        """
        if IP in packet:
            ttl = packet[IP].ttl
            if packet[IP].ttl > 64:
                os_from_ttl = "Windows"
            else:
                os_from_ttl = "Linux"
            self.update_device_os_field(device_info, "from_ttl", os_from_ttl)
                
        if ICMP in packet:
            raw_data = bytes(packet)
            if b"\x61\x62\x63\x64\x65\x66\x67\x68\x69" in raw_data:
                os_from_content = "Windows"
            elif b"\x10\x11\x12\x13\x14\x15\x16\x17\x18" in raw_data:
                os_from_content = "Linux"
            else:
                os_from_content = "Unknown"
            self.update_device_os_field(device_info, "from_ping_payload", os_from_content)
    
    def update_device_os_field(self, device_info, field, new_value):
        """
        updates the os field of a device_info dict.
        if the field is "Unknown", sets it to new_value. If conflict found, sets it to Conflict
        """
        if device_info["os"][field] == "Unknown":
            device_info["os"][field] = new_value
        elif device_info["os"][field] != new_value:
            device_info["os"][field] = "Conflict"
    
    def find_all_packets_of_device(self, mac):
        """"
        finds all packets coming from or to the device with the given mac address
        returns a tuple of two lists: (packets_from_device, packets_to_device)
        """
        packets_from_device = []
        packets_to_device = []
        for packet in self.packets:
            if Ether in packet:
                if packet[Ether].src == mac:
                    packets_from_device.append(packet)
                elif packet[Ether].dst == mac:
                    packets_to_device.append(packet)
        return (packets_from_device, packets_to_device)
    
    def get_info(self):
        """
        returns a list of dicts with all information about every device.
        """
        devices_array = []
        for mac in self.get_macs():
            device_info = self.establish_device(mac)
            devices_array.append(device_info)
        return devices_array
    
    
    def __repr__(self):
        raise NotImplementedError
    def __str__(self):
        raise NotImplementedError
    
    
if __name__ == "__main__":
    analyzer = AnalyzeNetwork("pcaps/pcap-03.pcapng")
    print(analyzer.get_info())
    #print(analyzer.get_ips())
    #print(analyzer.get_macs())
    
    