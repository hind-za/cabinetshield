# Génère un pcap synthétique (laboratoire, adresses fictives)
from scapy.all import Ether, IP, ICMP, TCP, wrpcap

pkts = []
# 1. Événement informatif : un ping vers le serveur du cabinet
pkts.append(Ether()/IP(src="192.168.1.20", dst="192.168.1.10")/ICMP())
# 2. Tentatives de connexion SSH répétées depuis un même poste
for i in range(10):
    pkts.append(Ether()/IP(src="192.168.1.45", dst="192.168.1.10")/TCP(sport=40000+i, dport=22, flags="S"))
# 3. Connexion sortante suspecte (port 4444, adresse de documentation)
pkts.append(Ether()/IP(src="192.168.1.30", dst="203.0.113.50")/TCP(sport=50000, dport=4444, flags="S"))

wrpcap("tests/data/demo.pcap", pkts)
print(len(pkts), "paquets écrits")
