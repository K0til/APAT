from scapy.all import *

class Mitm:

    def __init__(self, p_iface, p_ipsrc, p_time):
        self.time = p_time
        self.iface = p_iface
        self.ipsrc = p_ipsrc

    def capture(self):
        pl = PacketList()
        pkts = sniff(iface=self.iface, timeout=self.time)
        for p in pkts:
            pl.append(p)
        return pl

    def get_dns(self, pl):
        pkts = pl
        domaine_list = []
        for p in pkts:
            if p.haslayer("IP"):
                if p.haslayer("UDP"):
                    if p.haslayer("DNS"):
                        if p["IP"].src == self.ipsrc:
                            domaine = p["DNS"].qd['DNS Question Record'].qname.decode("utf-8")
                            domaine_list.append(domaine[:-1])
        return domaine_list
