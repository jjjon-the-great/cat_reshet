class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to pcap file
        """
        self.pcap_path = pcap_path
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
        returns a list of dicts with all information about every device 
        """
        raise NotImplementedError
    def __repr__(self):
        raise NotImplementedError
    def __str__(self):
        raise NotImplementedError